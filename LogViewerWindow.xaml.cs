using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FirewallManager
{
    public partial class LogViewerWindow : Window
    {
        private static readonly string LogFile =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                @"System32\LogFiles\Firewall\pfirewall.log");

        public class LogEntry
        {
            public string Time      { get; set; } = "";
            public string Action    { get; set; } = "";
            public string Protocol  { get; set; } = "";
            public string SrcIP     { get; set; } = "";
            public string DstIP     { get; set; } = "";
            public string SrcPort   { get; set; } = "";
            public string DstPort   { get; set; } = "";
            public string Direction { get; set; } = "";
            public string Resolved  { get; set; } = "";   // name/org for DstIP (from local DNS cache)
            public DateTime Ts      { get; set; }          // parsed timestamp, for the freshness gate

            // DNS tripwire: empty for normal traffic. For DNS to an UNCONFIGURED
            // resolver it carries the warning, which displays instead of Resolved.
            public string DnsWarn   { get; set; } = "";
            public string RuleName  { get; set; } = "";   // inferred rule (ALLOW: active; DROP: would-allow)
            public bool   IsWouldAllow { get; set; }       // true = DROP matched a DISABLED rule
            public Brush  RuleBrush => IsWouldAllow
                ? new SolidColorBrush(Color.FromRgb(0xfb,0xbf,0x24))   // amber: would allow if enabled
                : new SolidColorBrush(Color.FromRgb(0x7d,0xd3,0xfc));  // blue: active rule that allowed it
            public bool   IsDnsAnomaly => !string.IsNullOrEmpty(DnsWarn);
            public string ResolvedDisplay => IsDnsAnomaly ? DnsWarn : Resolved;
            public Brush  ResolvedBrush => DnsWarn.StartsWith("🚨")
                ? new SolidColorBrush(Color.FromRgb(0xf8,0x71,0x71))   // allowed unexpected = red
                : IsDnsAnomaly
                    ? new SolidColorBrush(Color.FromRgb(0xfb,0xbf,0x24)) // dropped unexpected = amber
                    : new SolidColorBrush(Color.FromRgb(0xfb,0xbf,0x24)); // normal resolved = amber (as before)
            public Brush  RowTint => DnsWarn.StartsWith("🚨")
                ? new SolidColorBrush(Color.FromArgb(0x33,0xf8,0x71,0x71))  // subtle red wash
                : IsDnsAnomaly
                    ? new SolidColorBrush(Color.FromArgb(0x22,0xfb,0xbf,0x24)) // subtle amber wash
                    : System.Windows.Media.Brushes.Transparent;
        }

        private DateTime? _since          = null;
        private Button    _activeScopeBtn;
        private bool      _dropsOnly      = false;
        private bool      _allowsOnly     = false;

        // ── Noise categories (true = suppress) ────────────────────────────────
        // Default: all suppressed → clean log on open (traffic light green).
        private readonly Dictionary<string, bool> _noise = new()
        {
            ["Multicast"]   = true,   // 224.x / 239.x
            ["Broadcast"]   = true,   // x.x.x.255 / 255.255.255.255
            ["Link-local"]  = true,   // 169.254.x
            ["NetBIOS"]     = true,   // ports 137/138/139
            ["mDNS"]        = true,   // port 5353
            ["SSDP/WSD"]    = true,   // ports 1900/3702/5357
            ["LLMNR"]       = true,   // port 5355
            ["Loopback"]    = true,   // 127.x — local IPC, never egress
            ["DNS (configured)"] = true, // DNS to your configured resolver(s) — expected chatter
        };

        // Configured resolver IPs (from active CUSTOM_DNS rules). DNS to anything
        // NOT in this set is an anomaly on a deny-by-default box → flagged, never hidden.
        private HashSet<string> _configuredDns = new();

        private void LoadConfiguredDns()
        {
            var set = new HashSet<string>();
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules");
                if (k != null)
                    foreach (var name in k.GetValueNames())
                    {
                        if (name.IndexOf("DNS", StringComparison.OrdinalIgnoreCase) < 0) continue;
                        var val = k.GetValue(name)?.ToString() ?? "";
                        foreach (var part in val.Split('|'))
                            if (part.StartsWith("RA4=", StringComparison.OrdinalIgnoreCase))
                            {
                                var ip = part.Substring(4);
                                var slash = ip.IndexOf('/');
                                if (slash > 0) ip = ip.Substring(0, slash);
                                if (!string.IsNullOrWhiteSpace(ip)) set.Add(ip.Trim());
                            }
                    }
            }
            catch { }
            _configuredDns = set;
        }

        // ── Rule inference ────────────────────────────────────────────────────
        // pfirewall.log records the packet, NOT which rule matched it. So for ALLOW
        // entries we re-derive the likely rule by matching (dst IP, port, proto, dir)
        // against the live CUSTOM_* allow rules. Exact single match → show its name;
        // no match or ambiguous (multiple) → blank, so we hint rather than lie.
        private sealed class LogRule
        {
            public string Name = "";
            public bool   DirOut;                       // true = Out, false = In
            public string Proto = "Any";                // TCP / UDP / Any
            public HashSet<int>? Ports;                 // null = any
            public List<(uint net, uint mask)>? Cidrs;  // null = any
            public int Spec;                            // specificity (higher = narrower)
            public bool Enabled;                        // active rule vs disabled (would-allow)
        }
        private List<LogRule> _allowRules = new();

        private void LoadAllowRules()
        {
            var list = new List<LogRule>();
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules");
                if (k != null)
                    foreach (var name in k.GetValueNames())
                    {
                        if (!name.StartsWith("CUSTOM_", StringComparison.Ordinal)) continue;
                        var raw = k.GetValue(name)?.ToString() ?? "";
                        var r = ParseLogRule(name, raw);
                        if (r != null) list.Add(r);
                    }
            }
            catch { }
            _allowRules = list;
        }

        private static LogRule? ParseLogRule(string regKey, string raw)
        {
            string action = "", dir = "", proto = "Any", display = regKey, active = "TRUE";
            var ports = new HashSet<int>();
            var cidrs = new List<(uint, uint)>();
            bool anyPort = true, anyIp = true;

            foreach (var part in raw.Split('|'))
            {
                var i = part.IndexOf('=');
                if (i < 0) continue;
                var key = part[..i].Trim().ToUpperInvariant();
                var v   = part[(i + 1)..].Trim();
                switch (key)
                {
                    case "NAME":     display = v; break;
                    case "ACTION":   action = v; break;
                    case "ACTIVE":   active = v; break;
                    case "DIR":      dir = v; break;
                    case "PROTOCOL": proto = v switch { "6"=>"TCP","17"=>"UDP","0"=>"Any",_=>v }; break;
                    case "RPORT":
                        if (int.TryParse(v, out var pnum)) { ports.Add(pnum); anyPort = false; }
                        break;
                    case "RA4":
                        var c = ParseCidr(v);
                        if (c.HasValue) { cidrs.Add(c.Value); anyIp = false; }
                        break;
                }
            }

            if (!action.Equals("Allow", StringComparison.OrdinalIgnoreCase)) return null;
            bool enabled = !active.Equals("FALSE", StringComparison.OrdinalIgnoreCase);

            // Specificity: an IP-scoped rule beats any-IP; a narrower CIDR beats a
            // wider one; a port-scoped rule beats any-port. Used to pick the most
            // meaningful rule when several would match a packet.
            int spec = 0;
            if (!anyIp)   spec += 1000 + cidrs.Max(c => System.Numerics.BitOperations.PopCount(c.Item2));
            if (!anyPort) spec += 100;

            return new LogRule
            {
                Name   = display.StartsWith("CUSTOM_", StringComparison.Ordinal)
                            ? display["CUSTOM_".Length..].Replace('_', ' ') : display,
                DirOut = !dir.Equals("In", StringComparison.OrdinalIgnoreCase),
                Proto  = proto,
                Ports  = anyPort ? null : ports,
                Cidrs  = anyIp   ? null : cidrs,
                Spec   = spec,
                Enabled = enabled
            };
        }

        // "140.82.112.0/20" or a bare "160.79.104.10" → (network, mask). Null on parse fail.
        private static (uint net, uint mask)? ParseCidr(string s)
        {
            int bits = 32; var ipPart = s;
            var slash = s.IndexOf('/');
            if (slash > 0) { ipPart = s[..slash]; int.TryParse(s[(slash+1)..], out bits); }
            if (!TryIpv4(ipPart, out var ip)) return null;
            uint mask = bits >= 32 ? 0xFFFFFFFF : bits <= 0 ? 0u : 0xFFFFFFFF << (32 - bits);
            return (ip & mask, mask);
        }

        private static bool TryIpv4(string s, out uint val)
        {
            val = 0;
            var o = s.Split('.');
            if (o.Length != 4) return false;
            uint acc = 0;
            foreach (var part in o)
            {
                if (!byte.TryParse(part, out var b)) return false;
                acc = (acc << 8) | b;
            }
            val = acc;
            return true;
        }

        // Returns (name, isWouldAllow). ALLOW entries match ENABLED rules (what let
        // them through). DROP entries match DISABLED allow rules (what WOULD let them
        // through if turned on) — turning the drop log into a preview/test surface.
        private (string name, bool wouldAllow) MatchRule(LogEntry e)
        {
            bool isAllow = e.Action.Equals("ALLOW", StringComparison.OrdinalIgnoreCase);
            bool isDrop  = e.Action.Equals("DROP",  StringComparison.OrdinalIgnoreCase);
            if (!isAllow && !isDrop) return ("", false);
            if (!TryIpv4(e.DstIP, out var dstIp)) return ("", false);
            bool sendDir = !e.Direction.Equals("RECEIVE", StringComparison.OrdinalIgnoreCase);
            int.TryParse(e.DstPort, out var dstPort);

            // ALLOW → enabled rules; DROP → disabled rules.
            bool wantEnabled = isAllow;

            var matches = new List<LogRule>();
            foreach (var r in _allowRules)
            {
                if (r.Enabled != wantEnabled) continue;
                if (r.DirOut != sendDir) continue;
                if (r.Proto != "Any" && !r.Proto.Equals(e.Protocol, StringComparison.OrdinalIgnoreCase)) continue;
                if (r.Ports != null && !r.Ports.Contains(dstPort)) continue;
                if (r.Cidrs != null && !r.Cidrs.Any(c => (dstIp & c.mask) == c.net)) continue;
                matches.Add(r);
            }
            if (matches.Count == 0) return ("", false);

            int top = matches.Max(m => m.Spec);
            var best = matches.Where(m => m.Spec == top).ToList();
            if (best.Count != 1) return ("", false);   // ambiguous → blank

            // DROP→disabled rule reads "⊘ Name" (amber); ALLOW→active rule reads plain.
            var display = best[0].Name.StartsWith("CUSTOM ") ? best[0].Name["CUSTOM ".Length..] : best[0].Name;
            return isDrop ? ("⊘ " + display, true) : (display, false);
        }

        // Predicate definitions (prefixes/suffixes/ports/etc.) from the effective
        // config. The _noise dict above holds the on/off toggles by category name.
        private readonly List<AppConfig.NoiseCategory> _noiseDefs =
            ConfigService.Effective().Noise;

        // Local DNS-cache map (DstIP → resolved name), rebuilt each load. No egress.
        private Dictionary<string, string> _dnsMap = new();

        // Guards against CheckBox Checked events firing LoadLog during InitializeComponent
        private bool _ready = false;

        // Keep full loaded list for export
        private List<LogEntry> _currentEntries = new();

        public LogViewerWindow()
        {
            InitializeComponent();
            _ready          = true;          // elements now realized; handlers may run LoadLog
            _activeScopeBtn = BtnAll;
            LogPath.Text    = $"Log: {LogFile}";
            SyncNoiseMenuChecks();
            RefreshNoiseLight();
            RefreshLoggingButtons();
            LoadLog();
        }

        // ── WF Logging toggles (moved here from the main window — they govern what
        //    Windows Firewall writes to the very log this window displays) ──────────

        private void BtnLogDrops_Click(object s, RoutedEventArgs e) => ToggleWFLogging("droppedconnections");
        private void BtnLogAllow_Click(object s, RoutedEventArgs e) => ToggleWFLogging("allowedconnections");

        private void ToggleWFLogging(string setting)
        {
            var on = GetWFLoggingState(setting);
            Process.Start(new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"advfirewall set allprofiles logging {setting} {(on ? "disable" : "enable")}",
                CreateNoWindow = true, UseShellExecute = false
            })?.WaitForExit();

            if (!on)   // turning on — make sure the log path is set
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = @"advfirewall set allprofiles logging filename ""%systemroot%\system32\LogFiles\Firewall\pfirewall.log""",
                    CreateNoWindow = true, UseShellExecute = false
                })?.WaitForExit();
            }

            RefreshLoggingButtons();
            LoadLog();   // logging change affects what's captured — refresh the view
        }

        private bool GetWFLoggingState(string setting)
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "advfirewall show currentprofile logging",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                });
                var output = p?.StandardOutput.ReadToEnd() ?? "";
                p?.WaitForExit();
                var key = setting == "droppedconnections" ? "LogDroppedConnections" : "LogAllowedConnections";
                return output.Split('\n').Any(l => l.Contains(key) && l.Contains("Enable"));
            }
            catch { return false; }
        }

        private void RefreshLoggingButtons()
        {
            var dropsOn = GetWFLoggingState("droppedconnections");
            var allowOn = GetWFLoggingState("allowedconnections");
            BtnLogDrops.Content = dropsOn ? "📥 Drops ✓" : "📥 Drops ✗";
            BtnLogAllow.Content = allowOn ? "📤 Allow ✓" : "📤 Allow ✗";
            BtnLogDrops.Style = (Style)FindResource(dropsOn ? "FilterBtnGood" : "FilterBtn");
            BtnLogAllow.Style = (Style)FindResource(allowOn ? "FilterBtnGood" : "FilterBtn");
        }

        // ── Scope (mutually exclusive) ────────────────────────────────────────

        private void BtnAll_Click(object s, RoutedEventArgs e)    { _since = null;                          SetScope(BtnAll);    LoadLog(); }
        private void BtnLast5_Click(object s, RoutedEventArgs e)  { _since = DateTime.Now.AddMinutes(-5);   SetScope(BtnLast5);  LoadLog(); }
        private void BtnLast30_Click(object s, RoutedEventArgs e) { _since = DateTime.Now.AddMinutes(-30);  SetScope(BtnLast30); LoadLog(); }

        private void SetScope(Button btn)
        {
            foreach (var b in new[] { BtnAll, BtnLast5, BtnLast30 })
                b.Style = (Style)Resources["FilterBtn"];
            btn.Style       = (Style)Resources["FilterBtnActive"];
            _activeScopeBtn = btn;
        }

        // ── Content filters (independent toggles) ────────────────────────────

        private void BtnDropsOnly_Click(object s, RoutedEventArgs e)
        {
            _dropsOnly = !_dropsOnly;
            if (_dropsOnly) _allowsOnly = false;   // mutually exclusive
            RefreshActionFilterStyles();
            LoadLog();
        }

        private void BtnAllowsOnly_Click(object s, RoutedEventArgs e)
        {
            _allowsOnly = !_allowsOnly;
            if (_allowsOnly) _dropsOnly = false;    // mutually exclusive
            RefreshActionFilterStyles();
            LoadLog();
        }

        private void RefreshActionFilterStyles()
        {
            BtnDropsOnly.Style  = _dropsOnly  ? (Style)Resources["FilterBtnWarn"] : (Style)Resources["FilterBtn"];
            BtnAllowsOnly.Style = _allowsOnly ? (Style)Resources["FilterBtnGood"] : (Style)Resources["FilterBtn"];
        }

        // ── Noise filter: traffic-light master + per-category surgical menu ────
        // Green = suppress all (clean) · Yellow = suppress some · Red = suppress none (raw)

        private void BtnNoiseMaster_Click(object s, RoutedEventArgs e)
        {
            // Toggle all: if anything is currently let through (not all suppressed), suppress all;
            // otherwise (all suppressed) release all.
            var allSuppressed = _noise.Values.All(v => v);
            foreach (var key in _noise.Keys.ToList()) _noise[key] = !allSuppressed;
            SyncNoiseMenuChecks();
            RefreshNoiseLight();
            LoadLog();
        }

        private void NoiseCategory_Toggled(object sender, RoutedEventArgs e)
        {
            if (!_ready) return;   // ignore Checked events fired during InitializeComponent
            if (sender is CheckBox cb && cb.Tag is string cat && _noise.ContainsKey(cat))
            {
                _noise[cat] = cb.IsChecked == true;   // checked = suppress
                RefreshNoiseLight();
                LoadLog();
            }
        }

        // Keep the popup checkboxes in sync with the _noise dictionary (after master toggle)
        private void SyncNoiseMenuChecks()
        {
            foreach (var child in NoiseMenuPanel.Children)
                if (child is CheckBox cb && cb.Tag is string cat && _noise.ContainsKey(cat))
                    cb.IsChecked = _noise[cat];
        }

        private void RefreshNoiseLight()
        {
            var on  = _noise.Values.Count(v => v);
            var tot = _noise.Count;
            // 🟢 all suppressed · 🟡 some · 🔴 none
            var (glyph, color) = on == tot ? ("🟢", "#34d399")
                               : on == 0   ? ("🔴", "#f87171")
                                           : ("🟡", "#fbbf24");
            NoiseLight.Text       = glyph;
            NoiseLabel.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(color));
        }

        private void BtnNoiseArrow_Click(object s, RoutedEventArgs e)
        {
            NoisePopup.IsOpen = !NoisePopup.IsOpen;
        }

        private void BtnRefreshLog_Click(object s, RoutedEventArgs e)
        {
            // Re-anchor time scope on refresh
            if (_activeScopeBtn == BtnLast5)  _since = DateTime.Now.AddMinutes(-5);
            if (_activeScopeBtn == BtnLast30) _since = DateTime.Now.AddMinutes(-30);
            LoadLog();
        }

        // ── Export ────────────────────────────────────────────────────────────

        private void BtnExport_Click(object s, RoutedEventArgs e)
        {
            if (_currentEntries.Count == 0)
            {
                LogCount.Text = "Nothing to export.";
                return;
            }

            var dlg = new SaveFileDialog
            {
                Title      = "Export Log",
                Filter     = "Text file (*.txt)|*.txt|CSV (*.csv)|*.csv",
                FileName   = $"firewall-log-{DateTime.Now:yyyyMMdd-HHmm}.txt",
                DefaultExt = ".txt"
            };

            if (dlg.ShowDialog() != true) return;

            try
            {
                var sb  = new StringBuilder();
                var csv = dlg.FileName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase);
                var sep = csv ? "," : "\t";

                sb.AppendLine($"Firewall Drop Log Export — {DateTime.Now:yyyy-MM-dd HH:mm}");
                var releasedCats = _noise.Where(kv => !kv.Value).Select(kv => kv.Key);
                var noiseDesc    = _noise.Values.All(v => v) ? "all suppressed"
                                 : _noise.Values.All(v => !v) ? "none suppressed"
                                 : $"released: {string.Join("+", releasedCats)}";
                sb.AppendLine($"Filters: scope={(_since.HasValue ? $"from {_since:HH:mm}" : "All")}  drops={_dropsOnly}  allows={_allowsOnly}  noise=[{noiseDesc}]");
                sb.AppendLine();
                sb.AppendLine(string.Join(sep, "Time", "Action", "Proto", "Src IP", "Dst IP", "Resolved", "Src Port", "Dst Port", "Direction"));

                foreach (var e2 in _currentEntries)
                    sb.AppendLine(string.Join(sep, e2.Time, e2.Action, e2.Protocol,
                        e2.SrcIP, e2.DstIP, e2.Resolved, e2.SrcPort, e2.DstPort, e2.Direction));

                File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
                LogCount.Text = $"Exported {_currentEntries.Count} entries → {Path.GetFileName(dlg.FileName)}";
            }
            catch (Exception ex)
            {
                LogCount.Text = $"Export error: {ex.Message}";
            }
        }

        // ── Log loading ───────────────────────────────────────────────────────

        private void LoadLog()
        {
            if (LogGrid == null) return;   // not yet realized (early event during init)

            if (!File.Exists(LogFile))
            {
                LogCount.Text       = "Log file not found — enable logging first.";
                LogGrid.ItemsSource = new ObservableCollection<LogEntry>();
                return;
            }

            try
            {
                _dnsMap = BuildDnsCacheMap();   // local cache snapshot, no egress
                LoadConfiguredDns();            // resolver IPs from active DNS rules
                LoadAllowRules();               // CUSTOM_* allow rules for rule-name inference

                using var fs     = new FileStream(LogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(fs);

                _currentEntries = reader.ReadToEnd()
                    .Split('\n')
                    .Where(l => !l.StartsWith("#") && !string.IsNullOrWhiteSpace(l))
                    .TakeLast(2000)
                    .Select(line =>
                    {
                        var p = line.Trim().Split(' ');
                        if (p.Length < 9) return null;
                        DateTime.TryParse($"{p[0]} {p[1]}", out var ts);
                        var dst = p[5];
                        var entry = new LogEntry
                        {
                            Time      = $"{p[0]} {p[1]}",
                            Action    = p[2],
                            Protocol  = p[3],
                            SrcIP     = p[4],
                            DstIP     = dst,
                            SrcPort   = p[6] == "-" ? "" : p[6],
                            DstPort   = p[7] == "-" ? "" : p[7],
                            Direction = p.Length > 16 ? p[16] : "",
                            Resolved  = ResolveDst(dst),
                            Ts        = ts
                        };
                        // DNS tripwire: DNS (port 53/853) to a resolver NOT in the
                        // configured set is an anomaly that should never happen here.
                        if ((entry.DstPort == "53" || entry.DstPort == "853")
                            && _configuredDns.Count > 0 && !_configuredDns.Contains(entry.DstIP))
                        {
                            entry.DnsWarn = entry.Action.Equals("ALLOW", StringComparison.OrdinalIgnoreCase)
                                ? "🚨 ALLOWED unexpected DNS"
                                : "⚠ unexpected DNS";
                        }
                        var (rn, wa) = MatchRule(entry);
                        entry.RuleName = rn;
                        entry.IsWouldAllow = wa;
                        return new { Entry = entry, Ts = ts };
                    })
                    .Where(x => x != null)
                    .Where(x => !_since.HasValue || x!.Ts >= _since.Value)
                    .Where(x => !_dropsOnly      || x!.Entry.Action == "DROP")
                    .Where(x => !_allowsOnly     || x!.Entry.Action == "ALLOW")
                    .Where(x => !IsSuppressedNoise(x!.Entry))
                    .Select(x => x!.Entry)
                    .OrderByDescending(e => e.Time)
                    .ToList();

                LogGrid.ItemsSource = new ObservableCollection<LogEntry>(_currentEntries);

                var filters = new List<string>();
                if (_since.HasValue)    filters.Add($"from {_since.Value:HH:mm}");
                if (_dropsOnly)         filters.Add("DROPs only");
                if (_allowsOnly)        filters.Add("ALLOWs only");
                var released = _noise.Where(kv => !kv.Value).Select(kv => kv.Key).ToList();
                if (released.Count > 0) filters.Add($"noise: {string.Join("+", released)}");
                var label = filters.Count > 0 ? $" — {string.Join(", ", filters)}" : "";

                var drops  = _currentEntries.Count(e => e.Action == "DROP");
                var allows = _currentEntries.Count(e => e.Action == "ALLOW");
                var enabledRules  = _allowRules.Count(r => r.Enabled);
                var disabledRules = _allowRules.Count(r => !r.Enabled);
                var allowMatched  = _currentEntries.Count(e => !string.IsNullOrEmpty(e.RuleName) && !e.IsWouldAllow);
                var wouldMatched  = _currentEntries.Count(e => e.IsWouldAllow);
                LogCount.Text = $"{drops} DROPs / {allows} ALLOWs / {_currentEntries.Count} entries{label}"
                              + $"  ·  rules: {enabledRules} on / {disabledRules} off"
                              + $"  ·  matched: {allowMatched} allow / {wouldMatched} would-allow";
            }
            catch (Exception ex)
            {
                LogCount.Text = $"Error: {ex.Message}";
            }
        }

        // ── Noise classification (per category; suppress if its category is enabled) ──
        // Predicates come from the effective config (ConfigService); the popup
        // toggles (_noise) decide which categories are active. A config category
        // with no popup toggle falls back to its own Suppress default.

        private bool IsSuppressedNoise(LogEntry e)
        {
            // Unexpected DNS is an alarm, not noise — it always shows, no matter
            // what's toggled.
            if (e.IsDnsAnomaly) return false;

            // DNS to a configured resolver is expected chatter — suppress if its
            // toggle is on.
            if (_noise.TryGetValue("DNS (configured)", out var dnsOn) && dnsOn
                && (e.DstPort == "53" || e.DstPort == "853")
                && _configuredDns.Contains(e.DstIP))
                return true;

            var ip   = e.DstIP;
            var port = e.DstPort;

            foreach (var c in _noiseDefs)
            {
                bool enabled = _noise.TryGetValue(c.Name, out var on) ? on : c.Suppress;
                if (!enabled) continue;

                foreach (var p in c.IpPrefixes) if (!string.IsNullOrEmpty(p) && ip.StartsWith(p)) return true;
                foreach (var sfx in c.IpSuffixes) if (!string.IsNullOrEmpty(sfx) && ip.EndsWith(sfx)) return true;
                foreach (var ex in c.IpExact)    if (ip == ex) return true;
                foreach (var pt in c.Ports)      if (port == pt) return true;
                if (c.MatchSource)
                    foreach (var p in c.IpPrefixes) if (!string.IsNullOrEmpty(p) && e.SrcIP.StartsWith(p)) return true;
            }
            return false;
        }

        // ── Local DNS cache resolution (ipconfig /displaydns) — no network egress ──

        private static Dictionary<string, string> BuildDnsCacheMap()
        {
            var map = new Dictionary<string, string>();
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ipconfig", Arguments = "/displaydns",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                };
                var proc = System.Diagnostics.Process.Start(psi);
                var outp = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(4000);

                string currentName = "";
                foreach (var raw in outp.Split('\n'))
                {
                    var line = raw.Trim();
                    var colon = line.IndexOf(':');
                    if (colon < 0) continue;
                    var key = line[..colon];
                    var val = line[(colon + 1)..].Trim();

                    if (key.StartsWith("Record Name"))                         currentName = val;
                    else if (key.StartsWith("A (Host) Record") ||
                             key.StartsWith("AAAA Record"))
                    {
                        if (!string.IsNullOrEmpty(val) && !string.IsNullOrEmpty(currentName)
                            && !map.ContainsKey(val))
                            map[val] = currentName;
                    }
                }
            }
            catch { /* cache unavailable (e.g. Dnscache disabled) → empty map, fall back */ }
            return map;
        }

        // Cache hit → hostname; else coarse org tag by known range; else blank.
        private string ResolveDst(string ip)
        {
            if (_dnsMap.TryGetValue(ip, out var name)) return name;
            return OrgTag(ip);
        }

        // Conservative static range tags. Coarse hits get a trailing '?' to signal imprecision.
        // ── "Who owns this connection?" — live process attribution via Get-NetTCPConnection ──
        // No age gate: pfirewall.log flushes on an uncontrollable delay, so the row timestamp is
        // not a reliable proxy for whether the connection is still live. The TCP table itself is
        // the arbiter — the query returns the owner if a connection exists, or "nothing live".

        private void LogContextMenu_Opened(object sender, RoutedEventArgs e)
        {
            var entry = LogGrid.CurrentItem as LogEntry;
            if (entry == null)
            {
                MnuWhoOwns.IsEnabled = false;
                MnuWhoOwns.Header    = "Who owns this connection?";
                return;
            }

            if (!string.Equals(entry.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
            {
                MnuWhoOwns.IsEnabled = false;
                MnuWhoOwns.Header    = "Who owns this? (UDP — no per-flow attribution)";
            }
            else
            {
                MnuWhoOwns.IsEnabled = true;
                MnuWhoOwns.Header    = $"Who owns {entry.DstIP}?";
            }
        }

        private void MnuWhoOwns_Click(object sender, RoutedEventArgs e)
        {
            if (LogGrid.CurrentItem is not LogEntry entry) return;
            var ip = entry.DstIP;

            // Only pass through plausible IP characters — never interpolate raw log text into a shell
            if (string.IsNullOrEmpty(ip) || !ip.All(c => char.IsDigit(c) || c == '.' || c == ':' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            {
                MessageBox.Show("Unrecognised address.", "Connection owner", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                var cmd =
                    $"Get-NetTCPConnection -RemoteAddress {ip} -ErrorAction SilentlyContinue | " +
                    "Select-Object RemoteAddress,RemotePort,State,OwningProcess," +
                    "@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}," +
                    "@{N='Path';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} | Format-List";

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-NoProfile -NonInteractive -Command \"{cmd}\"",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                };
                var proc = System.Diagnostics.Process.Start(psi);
                var outp = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(6000);

                var body = string.IsNullOrWhiteSpace(outp)
                    ? $"No live TCP connection to {ip} right now.\n\n" +
                      "It may have already closed, or (if this was a DROP) was blocked before it connected."
                    : outp;

                MessageBox.Show(body, $"Connection owner — {ip}",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lookup failed: {ex.Message}", "Connection owner",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private static string OrgTag(string ip)
        {
            foreach (var t in ConfigService.Effective().OrgTags)
                foreach (var p in t.Prefixes)
                    if (!string.IsNullOrEmpty(p) && ip.StartsWith(p))
                        return t.Tag;
            return "";
        }
    }
}
