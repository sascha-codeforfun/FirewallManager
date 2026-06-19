using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Controls;
using System.Windows.Media;

namespace FirewallManager
{
    public partial class SetupWindow : Window
    {
        private const string RegFWRules    = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";
        private const string RegFWProfiles = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";
        private const string EdgeExe       = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        private const string ChromeExe     = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        private const string FirefoxExe    = @"C:\Program Files\Mozilla Firefox\firefox.exe";

        private bool _hasExistingRules = false;

        public SetupWindow()
        {
            InitializeComponent();
            Loaded += SetupWindow_Loaded;
            PrePopulate();
        }

        private void SetupWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Surface any config.json ⇄ baseline disagreements now (Setup = intent).
            // Hash-gated: an unchanged config never re-prompts.
            ConfigService.ReconcileOnSetup(this);

            // If the config couldn't be parsed, say so once (we fell back to baseline).
            if (ConfigService.Status == AppConfig.LoadStatus.UsedBaselineParseError)
                SetStatus($"config.json couldn't be parsed — using built-in defaults. ({ConfigService.LoadError})", error: true);

            BuildDnsPresets();
            RefreshEmptyTags();

            // TEMP diagnostic — shows exactly what the reconcile saw.
            ConfigService.Reload();
            SetStatus($"config: {AppConfig.ConfigPath}  ·  exists={System.IO.File.Exists(AppConfig.ConfigPath)}  ·  " +
                      $"status={ConfigService.Status}  ·  usable={ConfigService.FileUsable}  ·  " +
                      $"diffs={(ConfigService.FileUsable ? ConfigService.DifferingSections().Count : -1)}  ·  " +
                      $"fileHash={ConfigService.FileHashShort}  storedHash={ConfigService.StoredHashShort}");
        }

        // Rebuild the DNS preset dropdowns from the effective config (keeps the
        // placeholder first; each item's Tag is the IP, or "gateway" sentinel).
        private void BuildDnsPresets()
        {
            foreach (var (cbo, _) in new[] { (CboDNS1Preset, 1), (CboDNS2Preset, 2) })
            {
                cbo.Items.Clear();
                cbo.Items.Add(new ComboBoxItem { Content = "— pick preset —", IsSelected = true });
                foreach (var p in ConfigService.Effective().DnsPresets)
                    cbo.Items.Add(new ComboBoxItem { Content = p.Label, Tag = p.Ip });
            }
        }

        // ── Pre-populate ─────────────────────────────────────────────────────

        private void PrePopulate()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(RegFWRules, writable: false);
                _hasExistingRules = key != null && key.GetValueNames().Any(n => n.StartsWith("CUSTOM_"));

                if (_hasExistingRules)
                {
                    // Load from existing CUSTOM_ rules — takes full priority
                    SetupMode.Text = "  — loaded from existing rules";
                    SetupMode.Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0xd3, 0x99));
                    LoadFromExistingRules(key!);
                }
                else
                {
                    // First run — auto-detect from network
                    SetupMode.Text = "  — first run, defaults detected";
                    SetupMode.Foreground = new SolidColorBrush(Color.FromRgb(0xfb, 0xbf, 0x24));
                    LoadFromNetwork();
                }
            }
            catch { LoadFromNetwork(); }
        }

        private void LoadFromExistingRules(RegistryKey key)
        {
            _populating = true;   // values from rules are neither "detected" nor "user input" — leave untagged

            // IPs from existing rules
            var rdpRaw  = key.GetValue("CUSTOM_RDP_In")?.ToString() ?? "";
            var dnsRaw  = key.GetValue("CUSTOM_DNS_UDP_Out")?.ToString() ?? "";
            var ntpRaw  = key.GetValue("CUSTOM_NTP_Out")?.ToString() ?? "";

            var rdpIP = ExtractField(rdpRaw, "RA4");
            var dnsIP = ExtractField(dnsRaw, "RA4");
            var gwIP  = ExtractField(ntpRaw, "RA4"); // NTP goes to gateway

            if (!string.IsNullOrEmpty(rdpIP)) TxtRDPSource.Text = rdpIP;

            // DNS may have multiple IPs
            if (!string.IsNullOrEmpty(dnsIP))
            {
                var dnsParts = dnsIP.Split(',');
                TxtDNS1.Text = dnsParts.Length > 0 ? dnsParts[0] : "";
                TxtDNS2.Text = dnsParts.Length > 1 ? dnsParts[1] : "";
            }

            if (!string.IsNullOrEmpty(gwIP))
            {
                TxtGateway.Text = gwIP;
            }

            // Own IP from network (not stored in rules)
            LoadOwnIPFromNetwork();

            // Toggle states from Active= field
            var names = key.GetValueNames();
            TogHTTP.IsChecked        = IsRuleActive(key, "CUSTOM_HTTP_Out");
            TogHTTPS.IsChecked       = IsRuleActive(key, "CUSTOM_HTTPS_Out");
            TogNTP.IsChecked         = IsRuleActive(key, "CUSTOM_NTP_Out");
            TogGitHub.IsChecked      = IsRuleActive(key, "CUSTOM_GitHub_Out");
            TogGitHubDNS.IsChecked   = names.Contains("CUSTOM_GitHub_DNS_Out");
            TogNuGet.IsChecked       = IsRuleActive(key, "CUSTOM_NuGet_Out");
            TogNuGetDNS.IsChecked    = names.Contains("CUSTOM_NuGet_DNS_Out");
            TogClaude.IsChecked      = IsRuleActive(key, "CUSTOM_Claude_Out");
            TogClaudeDNS.IsChecked   = names.Contains("CUSTOM_Claude_DNS_Out");
            TogEdge.IsChecked        = IsRuleActive(key, "CUSTOM_Edge_Out");
            TogEdgeDNS.IsChecked     = names.Contains("CUSTOM_Edge_DNS_Out");
            TogChrome.IsChecked      = IsRuleActive(key, "CUSTOM_Chrome_Out");
            TogChromeDNS.IsChecked   = names.Contains("CUSTOM_Chrome_DNS_Out");
            TogFirefox.IsChecked     = IsRuleActive(key, "CUSTOM_Firefox_Out");
            TogFirefoxDNS.IsChecked  = names.Contains("CUSTOM_Firefox_DNS_Out");
            TogWinUpdate.IsChecked   = IsRuleActive(key, "CUSTOM_WinUpdate_Out");
            TogVSUpdate.IsChecked    = IsRuleActive(key, "CUSTOM_VSUpdate_Out");
            TogOfficeUpdate.IsChecked= IsRuleActive(key, "CUSTOM_OfficeUpd_Out");
        }

        private void LoadFromNetwork()
        {
            LoadOwnIPFromNetwork();
            // Toggles stay at XAML defaults (core ON, browsers/updates OFF)
        }

        private bool _populating;   // true while we fill fields programmatically (suppresses the user-input flip)
        private bool _cleanSlate;   // true once the user forced a clean re-detect (replace on apply)

        private void LoadOwnIPFromNetwork()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    var props = ni.GetIPProperties();
                    var ipv4  = props.UnicastAddresses
                        .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                    var gw    = props.GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);

                    _populating = true;

                    if (ipv4 != null && string.IsNullOrEmpty(TxtOwnIP.Text))
                    {
                        TxtOwnIP.Text = ipv4.Address.ToString();
                        MarkDetected(TagOwnIP);
                    }

                    if (gw != null && string.IsNullOrEmpty(TxtGateway.Text))
                    {
                        TxtGateway.Text = gw.Address.ToString();
                        MarkDetected(TagGateway);
                    }

                    var dnsServers = props.DnsAddresses
                        .Where(d => d.AddressFamily == AddressFamily.InterNetwork)
                        .Select(d => d.ToString()).Distinct().ToList();

                    if (string.IsNullOrEmpty(TxtDNS1.Text) && dnsServers.Count > 0)
                    {
                        TxtDNS1.Text = dnsServers[0];
                        MarkDetected(TagDNS);
                    }
                    if (string.IsNullOrEmpty(TxtDNS2.Text) && dnsServers.Count > 1)
                        TxtDNS2.Text = dnsServers[1];

                    if (string.IsNullOrEmpty(TxtDNS1.Text) && !string.IsNullOrEmpty(TxtGateway.Text))
                    {
                        TxtDNS1.Text = TxtGateway.Text;     // fallback: gateway as DNS
                        MarkDetected(TagDNS);
                    }

                    // RDP source: detect the LIVE RDP client address (where you are connected FROM).
                    // No own-IP fallback — if undetected, leave empty for the user to fill.
                    if (string.IsNullOrEmpty(TxtRDPSource.Text))
                    {
                        var rdpClient = DetectRdpClientIp();
                        if (!string.IsNullOrEmpty(rdpClient))
                        {
                            TxtRDPSource.Text = rdpClient;
                            MarkDetected(TagRDP);
                        }
                    }

                    _populating = false;

                    if (!string.IsNullOrEmpty(TxtOwnIP.Text)) break;
                }
            }
            catch { _populating = false; }
        }

        // ── Provenance tags: amber "detected" ⇄ cyan "user input" ⇄ dim "not configured" ──
        private static readonly SolidColorBrush AmberDetected  = new(Color.FromRgb(0xfb, 0xbf, 0x24));
        private static readonly SolidColorBrush CyanUserInput  = new(Color.FromRgb(0x22, 0xd3, 0xee));
        private static readonly SolidColorBrush DimNotConfig   = new(Color.FromRgb(0x6b, 0x72, 0x80));

        private static void SetTag(System.Windows.Controls.TextBlock tag, string text, SolidColorBrush brush)
        {
            tag.Text = text;
            tag.Foreground = brush;
        }

        private void MarkDetected(System.Windows.Controls.TextBlock tag) => SetTag(tag, "detected", AmberDetected);

        private System.Windows.Controls.TextBlock? TagFor(string? key) => key switch
        {
            "own"  => TagOwnIP,
            "gw"   => TagGateway,
            "dns"  => TagDNS,
            "dns2" => TagDNS2,
            "rdp"  => TagRDP,
            _      => null
        };

        private void NetField_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (sender is not System.Windows.Controls.TextBox tb) return;
            var tag = TagFor(tb.Tag as string);
            if (tag == null) return;

            // Empty always reads "not configured" (even mid-populate / on clear).
            if (string.IsNullOrWhiteSpace(tb.Text)) { SetTag(tag, "not configured", DimNotConfig); return; }

            // Non-empty programmatic fill: leave the tag to the caller (detection sets "detected").
            if (_populating) return;

            // Non-empty user edit → user input.
            SetTag(tag, "user input", CyanUserInput);
        }

        // After load/populate, make any still-empty tagged field read "not configured".
        private void RefreshEmptyTags()
        {
            foreach (var (tb, tag) in new (System.Windows.Controls.TextBox, System.Windows.Controls.TextBlock)[]
                     { (TxtOwnIP, TagOwnIP), (TxtGateway, TagGateway), (TxtDNS1, TagDNS), (TxtDNS2, TagDNS2), (TxtRDPSource, TagRDP) })
            {
                if (string.IsNullOrWhiteSpace(tb.Text) && string.IsNullOrEmpty(tag.Text))
                    SetTag(tag, "not configured", DimNotConfig);
            }
        }

        // ── Live RDP client detection (WTS — no dependency) ────────────────────
        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public int SessionID;
            [MarshalAs(UnmanagedType.LPStr)] public string pWinStationName;
            public int State;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version,
            ref IntPtr ppSessionInfo, ref int pCount);
        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);
        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId,
            int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);

        private const int WTSActive = 0;
        private const int WTSClientAddress = 14;
        private const int AF_INET = 2;

        /// <summary>First active RDP session's client IPv4, or "" if none / not RDP / NAT-obscured.</summary>
        private static string DetectRdpClientIp()
        {
            IntPtr ppSessionInfo = IntPtr.Zero;
            int count = 0;
            try
            {
                if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref ppSessionInfo, ref count) == 0)
                    return "";
                int size = Marshal.SizeOf<WTS_SESSION_INFO>();
                IntPtr cur = ppSessionInfo;
                for (int i = 0; i < count; i++)
                {
                    var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(cur);
                    cur += size;
                    if (si.State != WTSActive) continue;

                    if (WTSQuerySessionInformation(IntPtr.Zero, si.SessionID, WTSClientAddress,
                                                   out IntPtr addr, out _))
                    {
                        try
                        {
                            int family = Marshal.ReadInt32(addr);       // WTS_CLIENT_ADDRESS.AddressFamily
                            if (family == AF_INET)
                            {
                                // Address[] starts at offset 4; IPv4 octets at Address[2..5]
                                byte a = Marshal.ReadByte(addr, 6);
                                byte b = Marshal.ReadByte(addr, 7);
                                byte c = Marshal.ReadByte(addr, 8);
                                byte d = Marshal.ReadByte(addr, 9);
                                var ip = $"{a}.{b}.{c}.{d}";
                                if (ip != "0.0.0.0") return ip;
                            }
                        }
                        finally { WTSFreeMemory(addr); }
                    }
                }
            }
            catch { /* not RDP, no permission, etc. → empty */ }
            finally { if (ppSessionInfo != IntPtr.Zero) WTSFreeMemory(ppSessionInfo); }
            return "";
        }

        // ── Clean slate: ignore existing rules, re-detect from the live machine ──
        private void BtnCleanSlate_Click(object sender, RoutedEventArgs e)
        {
            _populating = true;
            TxtOwnIP.Clear(); TxtGateway.Clear(); TxtDNS1.Clear(); TxtDNS2.Clear(); TxtRDPSource.Clear();
            TagOwnIP.Text = ""; TagGateway.Text = ""; TagDNS.Text = ""; TagRDP.Text = "";
            _populating = false;

            LoadOwnIPFromNetwork();          // detection only — no existing-rule values
            _cleanSlate = true;              // apply will replace, not merge

            SetupMode.Text = "  — clean slate (detected)";
            SetupMode.Foreground = AmberDetected;
        }

        private static bool IsRuleActive(RegistryKey key, string name)
            => (key.GetValue(name)?.ToString() ?? "").Contains("Active=TRUE");

        private static string ExtractField(string raw, string field)
        {
            var prefix = $"{field}=";
            var part   = raw.Split('|').FirstOrDefault(p =>
                p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
            return part?[prefix.Length..] ?? "";
        }

        // ── Apply ────────────────────────────────────────────────────────────

        // Service CIDRs from the effective config (comma-joined; WriteRule expands
        // each into a separate |RA4= field — never a comma-joined RA4, which WFP
        // silently rejects). Falls back to baseline if the named service is absent
        // or empty in the config, so a malformed edit can't blank a rule's scope.
        private static string SvcCidrs(string name)
        {
            var svc = ConfigService.Effective().Services
                        .FirstOrDefault(s => string.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase));
            var cidrs = svc?.Cidrs;
            if (cidrs == null || cidrs.Count == 0)
                cidrs = AppConfig.Baseline().Services
                          .FirstOrDefault(s => string.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase))?.Cidrs;
            return string.Join(",", cidrs ?? new System.Collections.Generic.List<string>());
        }

        private async void BtnApply_Click(object sender, RoutedEventArgs e)
        {
            // Hard gate at the write path: impossible values (bad octets/prefixes)
            // must never reach a rule. Re-read config and refuse if incoherent —
            // independent of whether reconcile-on-open ran. Summon the bouncer.
            ConfigService.Reload();
            var impossible = ConfigService.ImpossibleValues();
            if (impossible.Count > 0)
            {
                new ConsentWindow(impossible) { Owner = this }.ShowDialog();
                SetStatus("Apply aborted — config.json has impossible values (see the screen). Fix them first.", error: true);
                return;
            }

            // Core infrastructure is required. RDP source is NOT — empty means "no RDP rule"
            // (an empty source is never written as allow-from-anywhere).
            if (string.IsNullOrWhiteSpace(TxtGateway.Text) ||
                string.IsNullOrWhiteSpace(TxtDNS1.Text))
            {
                SetStatus("Gateway IP and DNS are required.", error: true);
                return;
            }

            var rdpSrc = TxtRDPSource.Text.Trim();
            if (string.IsNullOrWhiteSpace(rdpSrc))
            {
                var r = MessageBox.Show(
                    "RDP Source IP is empty.\n\n" +
                    "No inbound RDP rule will be created — inbound RDP stays blocked by default-deny. " +
                    "An empty source is never written as allow-from-anywhere.\n\n" +
                    "If RDP is how you reach this machine, fill in the source first.\n\n" +
                    "Continue without an RDP rule?",
                    "No RDP rule", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (r != MessageBoxResult.Yes) return;
                rdpSrc = "";   // explicit: ApplyRules will skip the RDP rule entirely
            }

            bool overwrite;
            if (_cleanSlate)
            {
                overwrite = true;   // clean slate = replace, no merge prompt
            }
            else if (_hasExistingRules)
            {
                var result = MessageBox.Show(
                    "Existing CUSTOM_ rules found.\n\nOverwrite all?\n\nYes = overwrite all\nNo = only add missing rules",
                    "Rules Exist", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
                if (result == MessageBoxResult.Cancel) return;
                overwrite = result == MessageBoxResult.Yes;
            }
            else overwrite = false;

            // Lock UI and show working state
            BtnApply.IsEnabled = false;
            BtnClose.IsEnabled = false;
            BtnClose.Content   = "⏳ Working…";
            SetStatus("Applying rules — please wait…", error: false);

            // Run on background thread so UI stays responsive
            var gw      = TxtGateway.Text.Trim();
            var dns     = BuildDNSList();
            var toggles = SnapshotToggles();

            string? error = null;
            await Task.Run(() =>
            {
                try
                {
                    if (overwrite) WipeCustomRules();
                    ApplyRules(gw, rdpSrc, dns, toggles);
                }
                catch (Exception ex) { error = ex.Message; }
            });

            // Back on UI thread
            BtnApply.IsEnabled = true;
            BtnClose.IsEnabled = true;

            if (error != null)
            {
                BtnClose.Content = "Close";
                SetStatus($"Error: {error}", error: true);
            }
            else
            {
                BtnClose.Content   = "✔ Done — Close";
                BtnClose.Background = new SolidColorBrush(Color.FromRgb(0x15, 0x80, 0x3d));
                SetStatus("Rules applied. GPO refreshed.", error: false);
                _hasExistingRules = true;
                SetupMode.Text = "  — loaded from existing rules";
            }
        }

        // Snapshot toggle values before going async
        private (bool http, bool https, bool ntp, bool github, bool githubDNS,
                 bool nuget, bool nugetDNS, bool claude, bool claudeDNS,
                 bool edge, bool edgeDNS, bool chrome, bool chromeDNS,
                 bool firefox, bool firefoxDNS,
                 bool winupd, bool vsupd, bool officeupd)
            SnapshotToggles() => (
            TogHTTP.IsChecked         == true,
            TogHTTPS.IsChecked        == true,
            TogNTP.IsChecked          == true,
            TogGitHub.IsChecked       == true,
            TogGitHubDNS.IsChecked    == true,
            TogNuGet.IsChecked        == true,
            TogNuGetDNS.IsChecked     == true,
            TogClaude.IsChecked       == true,
            TogClaudeDNS.IsChecked    == true,
            TogEdge.IsChecked         == true,
            TogEdgeDNS.IsChecked      == true,
            TogChrome.IsChecked       == true,
            TogChromeDNS.IsChecked    == true,
            TogFirefox.IsChecked      == true,
            TogFirefoxDNS.IsChecked   == true,
            TogWinUpdate.IsChecked    == true,
            TogVSUpdate.IsChecked     == true,
            TogOfficeUpdate.IsChecked == true);

        private void WipeCustomRules()
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegFWRules, writable: true);
            if (key == null) return;
            foreach (var n in key.GetValueNames().Where(n => n.StartsWith("CUSTOM_")).ToList())
                key.DeleteValue(n, false);
        }

        private void ApplyRules(string gw, string rdpSrc, string dns,
            (bool http, bool https, bool ntp, bool github, bool githubDNS,
             bool nuget, bool nugetDNS, bool claude, bool claudeDNS,
             bool edge, bool edgeDNS, bool chrome, bool chromeDNS,
             bool firefox, bool firefoxDNS,
             bool winupd, bool vsupd, bool officeupd) t)
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegFWRules, writable: true)
                ?? throw new Exception("Cannot open registry — run as Administrator.");

            ApplyProfileSettings();

            // RDP: only write the inbound rule when a source is set. Empty source = NO rule
            // (must never become RA4=Any, which would be allow-RDP-from-anywhere).
            if (!string.IsNullOrWhiteSpace(rdpSrc))
                WriteRule(key, "CUSTOM_RDP_In",  $"Action=Allow|Dir=In|Protocol=6|LPort=3389|RA4={rdpSrc}", true);
            WriteRule(key, "CUSTOM_DNS_UDP_Out",  $"Action=Allow|Dir=Out|Protocol=17|RPort=53|RA4={dns}",   true);
            WriteRule(key, "CUSTOM_DNS_TCP_Out",  $"Action=Allow|Dir=Out|Protocol=6|RPort=53|RA4={dns}",    true);
            WriteRule(key, "CUSTOM_NTP_Out",      $"Action=Allow|Dir=Out|Protocol=17|RPort=123|RA4={gw}",   t.ntp);
            WriteRule(key, "CUSTOM_HTTP_Out",      "Action=Allow|Dir=Out|Protocol=6|RPort=80|RA4=Any",      t.http);
            WriteRule(key, "CUSTOM_HTTPS_Out",     "Action=Allow|Dir=Out|Protocol=6|RPort=443|RA4=Any",     t.https);
            WriteRule(key, "CUSTOM_GitHub_Out",
                $"Action=Allow|Dir=Out|Protocol=6|RPort=443|RA4={SvcCidrs("GitHub")}",
                t.github);
            if (t.githubDNS)
                WriteRule(key, "CUSTOM_GitHub_DNS_Out", $"Action=Allow|Dir=Out|Protocol=17|RPort=53|RA4=Any", t.github);

            var nugetIPs  = ResolveIPs("api.nuget.org");
            var claudeIPs = ResolveIPs("claude.ai", "api.anthropic.com");
            WriteRule(key, "CUSTOM_NuGet_Out",   $"Action=Allow|Dir=Out|Protocol=6|RPort=443|RA4={nugetIPs}",  t.nuget);
            if (t.nugetDNS)
                WriteRule(key, "CUSTOM_NuGet_DNS_Out", $"Action=Allow|Dir=Out|Protocol=17|RPort=53|RA4=Any", t.nuget);

            WriteRule(key, "CUSTOM_Claude_Out",  $"Action=Allow|Dir=Out|Protocol=6|RPort=443|RA4={claudeIPs}", t.claude);
            if (t.claudeDNS)
                WriteRule(key, "CUSTOM_Claude_DNS_Out", $"Action=Allow|Dir=Out|Protocol=17|RPort=53|RA4=Any", t.claude);

            WriteRule(key, "CUSTOM_Edge_Out",    $"Action=Allow|Dir=Out|Protocol=6|RPort=80,443|App={EdgeExe}",    t.edge);
            if (t.edgeDNS)
                WriteRule(key, "CUSTOM_Edge_DNS_Out", $"Action=Allow|Dir=Out|Protocol=17|RPort=53|RA4=Any|App={EdgeExe}", t.edge);

            WriteRule(key, "CUSTOM_Chrome_Out",  $"Action=Allow|Dir=Out|Protocol=6|RPort=80,443|App={ChromeExe}",  t.chrome);
            if (t.chromeDNS)
                WriteRule(key, "CUSTOM_Chrome_DNS_Out", $"Action=Allow|Dir=Out|Protocol=17|RPort=53|RA4=Any|App={ChromeExe}", t.chrome);

            WriteRule(key, "CUSTOM_Firefox_Out", $"Action=Allow|Dir=Out|Protocol=6|RPort=80,443|App={FirefoxExe}", t.firefox);
            if (t.firefoxDNS)
                WriteRule(key, "CUSTOM_Firefox_DNS_Out", $"Action=Allow|Dir=Out|Protocol=17|RPort=53|RA4=Any|App={FirefoxExe}", t.firefox);

            WriteRule(key, "CUSTOM_WinUpdate_Out",
                $"Action=Allow|Dir=Out|Protocol=6|RPort=80,443|RA4={SvcCidrs("WinUpdate")}",
                t.winupd);
            WriteRule(key, "CUSTOM_VSUpdate_Out",
                $"Action=Allow|Dir=Out|Protocol=6|RPort=443|RA4={SvcCidrs("VSUpdate")}",
                t.vsupd);
            WriteRule(key, "CUSTOM_OfficeUpd_Out",
                $"Action=Allow|Dir=Out|Protocol=6|RPort=443|RA4={SvcCidrs("OfficeUpdate")}",
                t.officeupd);

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "gpupdate", Arguments = "/force",
                CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
            })?.WaitForExit(10000);
        }

        private void ApplyProfileSettings()
        {
            foreach (var profile in new[] { "DomainProfile", "StandardProfile" })
            {
                using var k = Registry.LocalMachine.CreateSubKey($@"{RegFWProfiles}\{profile}");
                if (k == null) continue;
                k.SetValue("EnableFirewall",             1, RegistryValueKind.DWord);
                k.SetValue("DefaultInboundAction",       1, RegistryValueKind.DWord);
                k.SetValue("DefaultOutboundAction",      1, RegistryValueKind.DWord);
                k.SetValue("AllowLocalPolicyMerge",      0, RegistryValueKind.DWord);
                k.SetValue("AllowLocalIPsecPolicyMerge", 0, RegistryValueKind.DWord);
                k.SetValue("DisableNotifications",       1, RegistryValueKind.DWord);
            }
        }

        private static void WriteRule(RegistryKey key, string name, string fields, bool active)
        {
            var displayName = name.Replace("CUSTOM_", "").Replace("_", " ");
            var state = active ? "Active=TRUE" : "Active=FALSE";

            var parts = fields.Split('|').Where(f => !string.IsNullOrEmpty(f)).ToList();

            // Remove RA4=Any — omitting is equivalent
            parts = parts.Where(p => p != "RA4=Any").ToList();

            // Convert App= path to %SystemDrive% format
            if (parts.Any(p => p.StartsWith("App=")))
                parts = parts.Select(p => p.StartsWith("App=") ? ConvertToEnvPath(p) : p).ToList();

            // WFP needs ONE field per value for repeated keys. Expand comma lists in both
            // RPort= (e.g. RPort=80,443 → RPort=80|RPort=443) AND RA4= (multi-CIDR). Leaving
            // RA4 comma-joined makes WFP silently reject the whole rule — it looks correct in
            // the registry but never enters the active filter set (observed: GitHub Out, four
            // CIDRs comma-joined, Active=TRUE, yet github traffic dropped).
            var expanded = new List<string>();
            foreach (var part in parts)
            {
                if (part.StartsWith("RPort=") && part.Contains(","))
                {
                    foreach (var port in part["RPort=".Length..].Split(','))
                        expanded.Add($"RPort={port.Trim()}");
                }
                else if (part.StartsWith("RA4=") && part.Contains(","))
                {
                    foreach (var ra in part["RA4=".Length..].Split(','))
                        expanded.Add($"RA4={ra.Trim()}");
                }
                else if (part.StartsWith("RA6=") && part.Contains(","))
                {
                    foreach (var ra in part["RA6=".Length..].Split(','))
                        expanded.Add($"RA6={ra.Trim()}");
                }
                else expanded.Add(part);
            }

            var val = $"v2.33|{string.Join("|", expanded)}|{state}|Name=CUSTOM {displayName}|";
            key.SetValue(name, val, RegistryValueKind.String);
        }

        private static string ConvertToEnvPath(string appField)
        {
            var path = appField["App=".Length..];
            // Use %SystemDrive%\Program Files format (matches gpedit.msc output)
            path = path.Replace(@"C:\Program Files (x86)\", @"%SystemDrive%\Program Files (x86)\");
            path = path.Replace(@"C:\Program Files\",       @"%SystemDrive%\Program Files\");
            path = path.Replace(@"C:\Windows\",             @"%SystemRoot%\");
            path = path.Replace(@"C:\Users\",               @"%USERPROFILE%\");
            // Handle already-converted %ProgramFiles% paths
            path = path.Replace(@"%ProgramFiles(x86)%\",   @"%SystemDrive%\Program Files (x86)\");
            path = path.Replace(@"%ProgramFiles%\",         @"%SystemDrive%\Program Files\");
            return $"App={path}";
        }

        private string BuildDNSList()
        {
            var list = new List<string>();
            if (!string.IsNullOrWhiteSpace(TxtDNS1.Text)) list.Add(TxtDNS1.Text.Trim());
            if (!string.IsNullOrWhiteSpace(TxtDNS2.Text)) list.Add(TxtDNS2.Text.Trim());
            return list.Count > 0 ? string.Join(",", list) : TxtGateway.Text.Trim();
        }

        private static string ResolveIPs(params string[] hostnames)
        {
            var ips = new List<string>();
            foreach (var host in hostnames)
            {
                try
                {
                    ips.AddRange(System.Net.Dns.GetHostAddresses(host)
                        .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                        .Select(a => a.ToString()));
                }
                catch { }
            }
            return ips.Count > 0 ? string.Join(",", ips.Distinct()) : "Any";
        }

        private void SetStatus(string msg, bool error = false)
        {
            SetupStatus.Text       = msg;
            SetupStatus.Foreground = error
                ? new SolidColorBrush(Color.FromRgb(0xf8, 0x71, 0x71))
                : new SolidColorBrush(Color.FromRgb(0x34, 0xd3, 0x99));
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();

        private void CboDNSPreset_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (sender is not ComboBox cbo) return;
            if (cbo.SelectedItem is not ComboBoxItem item) return;
            var tag = item.Tag?.ToString() ?? "";
            if (string.IsNullOrEmpty(tag)) return;   // placeholder

            var ip = tag == "gateway" ? TxtGateway.Text.Trim() : tag;
            if (string.IsNullOrEmpty(ip)) return;

            // Fill the field AND force "user input" — picking a preset is an explicit
            // choice, so the marker cycles even when the value is identical to before.
            if (cbo.Name == "CboDNS1Preset") { TxtDNS1.Text = ip; SetTag(TagDNS,  "user input", CyanUserInput); }
            else                             { TxtDNS2.Text = ip; SetTag(TagDNS2, "user input", CyanUserInput); }

            // Stay on the selected entry (do NOT reset to the placeholder).
        }

        // Stage 1: write the app's knowledge to an editable config.json template
        // (UTF-8, no BOM, LF — the clean style; see AppConfig.Write).
        private void BtnExportJson_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Title      = "Export config.json template",
                Filter     = "JSON config (*.json)|*.json",
                FileName   = "config.json",
                DefaultExt = ".json"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                AppConfig.Write(AppConfig.Baseline(), dlg.FileName);
                var hash = AppConfig.CanonicalHash(AppConfig.Baseline());
                SetStatus($"config.json written → {System.IO.Path.GetFileName(dlg.FileName)}  (hash {hash[..8]}…)");
            }
            catch (Exception ex)
            {
                SetStatus($"config.json export error: {ex.Message}", error: true);
            }
        }

        private void BtnExportConfig_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Title      = "Export Firewall Config",
                Filter     = "Text file (*.txt)|*.txt",
                FileName   = $"firewall-config-{DateTime.Now:yyyyMMdd-HHmm}.txt",
                DefaultExt = ".txt"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("=== Firewall Rule Manager — Config Export ===");
                sb.AppendLine($"Exported : {DateTime.Now:yyyy-MM-dd HH:mm}");
                sb.AppendLine($"Source   : {(SetupMode.Text.Contains("existing") ? "Loaded from existing CUSTOM_ rules" : "First-run defaults")}");
                sb.AppendLine();
                sb.AppendLine("--- Network ---");
                sb.AppendLine($"Own IP       : {TxtOwnIP.Text}");
                sb.AppendLine($"Gateway IP   : {TxtGateway.Text}");
                sb.AppendLine($"DNS Primary  : {TxtDNS1.Text}");
                sb.AppendLine($"DNS Secondary: {TxtDNS2.Text}");
                sb.AppendLine($"RDP Source IP: {TxtRDPSource.Text}");
                sb.AppendLine();
                sb.AppendLine("--- Toggle State ---");
                sb.AppendLine($"HTTP  (80)   : {Tog(TogHTTP)}");
                sb.AppendLine($"HTTPS (443)  : {Tog(TogHTTPS)}");
                sb.AppendLine($"NTP          : {Tog(TogNTP)}");
                sb.AppendLine($"GitHub       : {Tog(TogGitHub)}");
                sb.AppendLine($"NuGet        : {Tog(TogNuGet)}");
                sb.AppendLine($"Claude       : {Tog(TogClaude)}");
                sb.AppendLine($"Edge         : {Tog(TogEdge)}");
                sb.AppendLine($"Chrome       : {Tog(TogChrome)}");
                sb.AppendLine($"Firefox      : {Tog(TogFirefox)}");
                sb.AppendLine($"Win Update   : {Tog(TogWinUpdate)}");
                sb.AppendLine($"VS Update    : {Tog(TogVSUpdate)}");
                sb.AppendLine($"Office Update: {Tog(TogOfficeUpdate)}");
                sb.AppendLine();
                sb.AppendLine("--- Raw Registry Rules (CUSTOM_*) ---");

                using var key = Registry.LocalMachine.OpenSubKey(RegFWRules, writable: false);
                if (key != null)
                {
                    foreach (var name in key.GetValueNames().Where(n => n.StartsWith("CUSTOM_")).OrderBy(n => n))
                    {
                        var val = key.GetValue(name)?.ToString() ?? "";
                        sb.AppendLine($"{name}");
                        sb.AppendLine($"  {val}");
                    }
                }
                else
                {
                    sb.AppendLine("(no CUSTOM_ rules found in registry)");
                }

                File.WriteAllText(dlg.FileName, sb.ToString(), System.Text.Encoding.UTF8);
                SetStatus($"Config exported → {System.IO.Path.GetFileName(dlg.FileName)}");
            }
            catch (Exception ex)
            {
                SetStatus($"Export error: {ex.Message}", error: true);
            }
        }

        private static string Tog(System.Windows.Controls.Primitives.ToggleButton tb)
            => tb.IsChecked == true ? "ON" : "OFF";
    }
}
