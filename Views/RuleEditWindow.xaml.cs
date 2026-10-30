using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;

using HueThemeKit;

namespace FirewallManager
{
    public partial class RuleEditWindow : Window
    {
        private const string RegGPO = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";

        private MainWindow.FirewallRule? _rule;
        private bool _isReadOnly  = false;
        private bool _isNew       = false;
        private List<string> _ips = new();
        private InputHygiene? _nameHygiene;
        private bool _closed;
        // Why the form opened as it did (Allow…): context for the whole edit, so an error shows
        // beside it rather than in its place.
        private string? _openingNote;

        // ── Entry points ─────────────────────────────────────────────────────

        public static void OpenEdit(MainWindow.FirewallRule rule, Window owner)
        {
            var w = new RuleEditWindow { Owner = owner };
            w._rule = rule;
            w.PopulateFromRule(rule);
            w.ShowDialog();
        }

        // ── From observed traffic (the log's Talkers tab, "Allow…") ─────────────

        /// <summary>
        /// What was seen for one talker, as the starting point of a rule. Remote: the addresses
        /// seen (comma-separated IPv4 addresses or ranges), "" for none.
        /// </summary>
        public sealed record Observed(string Name, string Direction, string Protocol, string Ports,
                                      string Program, string Service, string Title, string Detail,
                                      string Remote = "");

        /// <summary>
        /// A new rule filled in from what was observed. True if it was saved. The note, if any,
        /// shows in the status line: why a new rule was started rather than an existing one extended.
        /// </summary>
        public static bool OpenFromObserved(Observed o, Window owner, string? note = null)
        {
            var w = new RuleEditWindow { Owner = owner };
            w._isNew           = true;
            w.TitleText.Text   = "New Rule";
            w.SourceLabel.Text = "GPO-Script";
            w.ShowSource("GPO-Script");
            w.CboAction.SelectedIndex = 0;                 // Allow
            SelectCombo(w.CboDirection, o.Direction);
            SelectCombo(w.CboProtocol,  o.Protocol);
            w.TxtPorts.Text   = o.Ports;
            // With addresses, the rule is limited to them; without, trust is declared on the
            // program (or service).
            var remote = !string.IsNullOrWhiteSpace(o.Remote);
            w.TogLimit.IsChecked = remote;
            if (remote)
            {
                w.TxtNewIP.Text = o.Remote;
                w.AddRemote();
            }
            w.TxtProgram.Text = TrueCase(o.Program);       // shows the Service row for svchost.exe
            w.CboService.Text = o.Service;
            w.TxtName.Text    = o.Name;
            w.TogActive.IsChecked = true;
            w.ShowPrefillNote(o.Title, o.Detail);
            if (!string.IsNullOrEmpty(note)) w.EditStatus.Text = w._openingNote = note;
            return w.ShowDialog() == true;
        }

        /// <summary>
        /// An existing rule for the same program, opened with the observed ports added, so one
        /// program keeps one rule. True if it was saved.
        /// </summary>
        public static bool OpenExtending(MainWindow.FirewallRule rule, Observed o, Window owner)
        {
            var w = new RuleEditWindow { Owner = owner };
            w._rule = rule;
            w.PopulateFromRule(rule);
            // A rule the editor can't save is shown as it is: adding ports there would show
            // ports the rule doesn't have.
            if (w._isReadOnly)
            {
                w.ShowPrefillNote($"Existing rule for this program: {Shown(rule)}",
                    $"It can't be changed here, so the observed ports weren't added. {o.Detail}");
                return w.ShowDialog() == true;
            }

            var have  = w.TxtPorts.Text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            var added = o.Ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                               .Where(p => !have.Contains(p)).ToList();
            // A rule with no ports already allows every port: nothing to add.
            if (have.Count > 0 && added.Count > 0) w.TxtPorts.Text = string.Join(",", have.Concat(added));

            var what = (rule.Protocol is "ICMP" or "ICMPv6") ? $"It already allows every {rule.Protocol} message type."
                     : have.Count == 0 ? "It already allows every port."
                     : added.Count == 0 ? "It already has these ports."
                     : $"Added port {string.Join(", ", added)}.";
            var off = RuleText.IsOn(rule.RawValue) ? "" : " It is switched off: switch Active on if this program should get through.";
            w.ShowPrefillNote($"Existing rule for this program: {Shown(rule)}", $"{what}{off} {o.Detail}");
            return w.ShowDialog() == true;
        }

        /// <summary>
        /// The Security log hands paths over in lower case. Windows doesn't mind, but people
        /// read them: ask the file system for each name as it is written. Anything it can't
        /// see (no access, gone, %Variable% paths) is left as it came.
        /// </summary>
        private static string TrueCase(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !File.Exists(path))
                    return path;
                var root   = Path.GetPathRoot(path)!;
                var result = root.ToUpperInvariant();
                foreach (var part in path[root.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
                {
                    var match = new DirectoryInfo(result).EnumerateFileSystemInfos(part).FirstOrDefault();
                    if (match == null) return path;
                    result = Path.Combine(result, match.Name);
                }
                return result;
            }
            catch { return path; }
        }

        private void ShowPrefillNote(string title, string detail)
        {
            PrefillTitle.Text  = title;
            PrefillDetail.Text = detail;
            PrefillNote.Visibility = Visibility.Visible;
        }

        public static void OpenNew(Window owner)
        {
            var w = new RuleEditWindow { Owner = owner };
            w._isNew             = true;
            w.TitleText.Text     = "New Rule";
            w.SourceLabel.Text   = "GPO-Script";
            w.ShowSource("GPO-Script");
            // Direction, action and protocol start unset: they are chosen (or filled by a preset).
            w.TogActive.IsChecked        = true;
            w.ShowDialog();
        }

        // ── Is this rule the editor's own? ───────────────────────────────────
        // The editor writes Action, Dir, Protocol (6, 17, 1 or 58; none for Any), the port on the
        // side the direction uses (TCP and UDP only), RA4, LA4, App, Svc (svchost.exe only), Active
        // and Name. Anything else would be lost on save, so a rule carrying more is shown, not
        // edited or copied. ICMP: no ICMP4/ICMP6 field means every message type. The policy
        // format has no "all types" value for these fields (a type is a number; only the code
        // can be "*"), so any ICMP4/ICMP6 field limits the types and keeps the rule read-only.

        private static readonly HashSet<string> OwnFields = new(StringComparer.OrdinalIgnoreCase)
        {
            "Action", "Dir", "Protocol", "LPort", "RPort", "RA4", "LA4", "App", "Svc", "Active", "Name",
        };

        // Fields the editor reads one value of: a second one would be lost.
        private static readonly HashSet<string> SingleFields = new(StringComparer.OrdinalIgnoreCase)
        {
            "Action", "Dir", "Protocol", "App", "Svc", "Active", "Name",
        };

        private static readonly Dictionary<string, string> FieldWords = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Profile"]   = "a profile limit",
            ["RA6"]       = "IPv6 remote addresses",
            ["LA6"]       = "IPv6 local addresses",
            ["ICMP4"]     = "ICMP types",
            ["ICMP6"]     = "ICMPv6 types",
            ["IF"]        = "a network interface limit",
            ["IFType"]    = "an interface type limit",
            ["Edge"]      = "edge traversal",
            ["Defer"]     = "deferred edge traversal",
            ["LUAuth"]    = "authorized local users",
            ["LUOwn"]     = "a local user owner",
            ["RUAuth"]    = "authorized remote users",
            ["RMAuth"]    = "authorized remote computers",
            ["Security"]  = "an IPsec requirement",
            ["Security2"] = "an IPsec requirement",
            ["AppPkgId"]  = "an app package",
            ["Platform"]  = "a Windows version limit",
            ["Platform2"] = "a Windows version limit",
            ["LPort2_10"] = "a local port keyword",
            ["LPort2_20"] = "a local port keyword",
            ["RPort2_10"] = "a remote port keyword",
            ["Desc"]      = "a description",
            ["EmbedCtxt"] = "a group",
        };

        // Free text, named rather than quoted.
        private static readonly HashSet<string> NameOnlyFields = new(StringComparer.OrdinalIgnoreCase) { "Desc", "EmbedCtxt" };

        /// <summary>
        /// True when the editor shows the rule without letting it be changed: managed elsewhere
        /// (GPO-Manual), one of Windows' local rules (they don't count with merge off), or carrying
        /// settings the editor doesn't write, which a save would lose.
        /// </summary>
        internal static bool OpensReadOnly(MainWindow.FirewallRule rule) =>
            rule.Source is "GPO-Manual" or "Local" || ForeignParts(rule.RawValue).Count > 0;

        /// <summary>
        /// Everything in the rule beyond what the editor writes, in readable words with the raw
        /// field in brackets. Empty when the editor can save the rule without losing anything.
        /// </summary>
        /// <param name="forCopy">A copy is a new rule, so a description and a group, which don't change
        /// what a rule allows, may stay behind; an edit would drop them from the original.</param>
        internal static List<string> ForeignParts(string raw, bool forCopy = false)
        {
            const StringComparison ic = StringComparison.OrdinalIgnoreCase;
            var fields = raw.Split('|').Where(p => p.Contains('='))
                            .Select(p => (Key: p[..p.IndexOf('=')].Trim(), Value: p[(p.IndexOf('=') + 1)..].Trim()))
                            .ToList();
            string First(string key) => fields.FirstOrDefault(f => f.Key.Equals(key, ic)).Value ?? "";
            static string Raw(IEnumerable<(string Key, string Value)> fs) => string.Join(", ", fs.Select(f => $"{f.Key}={f.Value}"));
            var parts = new List<string>();

            var protocol = First("Protocol");
            if (protocol is not ("" or "6" or "17" or "1" or "58"))
                parts.Add(Protocols.Names.TryGetValue(protocol, out var pn) ? $"protocol {protocol} ({pn})" : $"protocol {protocol}");

            var action = First("Action");
            if (action.Length > 0 && !action.Equals("Allow", ic) && !action.Equals("Block", ic))
                parts.Add($"action {action} (Action={action})");

            var dir = First("Dir");
            if (dir.Length > 0 && !dir.Equals("In", ic) && !dir.Equals("Out", ic))
                parts.Add($"direction {dir} (Dir={dir})");

            // The port field the direction doesn't use, and port values the editor doesn't write (keywords such as RPC).
            var wrongSide = dir.Equals("In", ic) ? "RPort" : dir.Equals("Out", ic) ? "LPort" : null;
            var portFields = fields.Where(f => f.Key.Equals("LPort", ic) || f.Key.Equals("RPort", ic)).ToList();
            // The editor writes no ports for ICMP, so any port there is named once, as that.
            if (protocol is ("1" or "58") && portFields.Count > 0)
                parts.Add($"ports on an {Protocols.Name(protocol)} rule ({Raw(portFields)})");
            else
            {
                var otherSide = portFields.Where(f => wrongSide != null && f.Key.Equals(wrongSide, ic)).ToList();
                if (otherSide.Count > 0)
                {
                    var words = wrongSide == "LPort" ? "local port{0} on an outbound rule" : "remote port{0} on an inbound rule";
                    parts.Add((otherSide.Count == 1 ? "a " + string.Format(words, "") : string.Format(words, "s")) + $" ({Raw(otherSide)})");
                }
                var oddPorts = portFields.Except(otherSide).Where(f => Ipv4Scope.BadPorts(f.Value) != null).ToList();
                if (oddPorts.Count > 0) parts.Add($"ports the editor doesn't write ({Raw(oddPorts)})");
            }

            var svc = fields.Where(f => f.Key.Equals("Svc", ic)).ToList();
            if (svc.Count > 0)
            {
                var app = First("App");
                if (app.Length == 0)
                    parts.Add($"a service without a program ({Raw(svc)})");
                else if (!Path.GetFileName(app).Equals("svchost.exe", ic))
                    parts.Add($"a service on a program other than svchost ({Raw(svc)})");
            }

            // Addresses: each entry one the editor accepts. Comma-joined values are split on
            // save, so they count as the editor's own.
            foreach (var (key, words) in new[] { ("RA4", "remote addresses"), ("LA4", "local addresses") })
            {
                var odd = fields.Where(f => f.Key.Equals(key, ic) &&
                                            f.Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                                   .Any(a => !(key == "RA4" && a.Equals("Any", ic)) && Ipv4Scope.Parse(a, out _) == null))
                                .ToList();
                if (odd.Count > 0) parts.Add($"{words} the editor doesn't write ({Raw(odd)})");
            }

            // Fields the editor doesn't write at all; a repeated one (Profile=Domain|Profile=Private) reads once.
            foreach (var g in fields.Where(f => !OwnFields.Contains(f.Key) &&
                                                !(forCopy && (f.Key.Equals("Desc", ic) || f.Key.Equals("EmbedCtxt", ic))))
                                    .GroupBy(f => f.Key, StringComparer.OrdinalIgnoreCase))
            {
                var words = FieldWords.TryGetValue(g.Key, out var w) ? w : "a setting the editor doesn't write";
                parts.Add(NameOnlyFields.Contains(g.Key) ? $"{words} ({g.Key})" : $"{words} ({Raw(g)})");
            }

            foreach (var g in fields.Where(f => SingleFields.Contains(f.Key)).GroupBy(f => f.Key, StringComparer.OrdinalIgnoreCase)
                                    .Where(g => g.Count() > 1))
                parts.Add($"{g.Key} given more than once ({Raw(g)})");

            return parts;
        }

        // "a, b and c"
        private static string JoinWords(IReadOnlyList<string> parts) =>
            parts.Count <= 1 ? string.Join("", parts) : $"{string.Join(", ", parts.Take(parts.Count - 1))} and {parts[^1]}";

        public static void OpenCopy(MainWindow.FirewallRule rule, Window owner)
        {
            if (ForeignParts(rule.RawValue, forCopy: true) is { Count: > 0 } foreign)
            {
                ThemedDialog.Info(owner, "This rule can't be copied",
                    $"It also contains {JoinWords(foreign)}, which the editor doesn't write. A copy would leave " +
                    "them out and allow something different from the original, so no copy is made.");
                return;
            }

            var w = new RuleEditWindow { Owner = owner };
            w._isNew = true;
            // The copy is a new rule of this app's own, editable even when the original is
            // managed elsewhere (GPO-Manual) or is one of Windows' local rules.
            w.PopulateFromRule(rule, asCopy: true);
            w.TitleText.Text = "Copy Rule";
            w.SourceLabel.Text = "GPO-Script";
            w.ShowSource("GPO-Script");
            // Windows' own rules carry their names as resource references ("@FirewallAPI.dll,-28502");
            // with text added the reference breaks, so such a copy starts unnamed.
            w.TxtName.Text = rule.Name.StartsWith("@") ? "" : RuleWriter.Plain(rule.Name) + " copy";
            w._nameHygiene?.NoteExisting();
            w._rule = null;
            w.ShowDialog();
        }

        public RuleEditWindow()
        {
            InitializeComponent();
            HueTitleBar.Attach(this);
            TogLimit.IsChecked = true;
            // Grows with its content (the prefill note, the service row), but never past the
            // screen it opens on: only then does the form scroll.
            ScreenFit.Cap(this);
            TogActive.Checked   += (s, e) => ActiveLabel.Text = "Enabled";
            TogActive.Unchecked += (s, e) => ActiveLabel.Text = "Disabled";
            TxtProgram.TextChanged += TxtProgram_TextChanged;
            // A path is told apart by its exe name, so when one is filled in programmatically,
            // scroll to its end. While someone is typing, the caret stays where they put it.
            TxtProgram.TextChanged += (_, _) =>
            {
                if (TxtProgram.IsKeyboardFocusWithin) return;
                Dispatcher.InvokeAsync(() =>
                {
                    TxtProgram.CaretIndex = TxtProgram.Text.Length;
                    TxtProgram.ScrollToHorizontalOffset(double.PositiveInfinity);
                }, System.Windows.Threading.DispatcherPriority.Loaded);
            };
            BuildPresetChips();

            // Names, addresses and ports take plain characters; the program path stays as the file
            // system has it.
            TxtName.ToolTip = TextHygiene.NameRule;
            _nameHygiene = InputHygiene.ForName(TxtName, NameNote);
            InputHygiene.ForPlain(TxtPorts, PortsNote);
            _portsTip = TxtPorts.ToolTip;
            CboProtocol.SelectionChanged += (_, _) => ShowPortsForProtocol();
            InputHygiene.ForPlain(TxtLocalAddress, LocalNote);
            InputHygiene.ForPlain(TxtNewIP, RemoteNote);

            // The Local address tooltip adds the exact span of each range or subnet typed.
            var localTip = TxtLocalAddress.ToolTip as string ?? "";
            TxtLocalAddress.TextChanged += (_, _) =>
            {
                var spans = Ipv4Scope.Describe(TxtLocalAddress.Text);
                TxtLocalAddress.ToolTip = spans.Length == 0 ? localTip : $"{localTip}\n\n{spans}";
            };

            // The Any-destination note follows action, direction, destination and program.
            TogLimit.Checked             += (_, _) => UpdateOpenNote();
            CboDirection.SelectionChanged+= (_, _) => ShowLimit();
            TogLimit.Unchecked           += (_, _) => UpdateOpenNote();
            CboAction.SelectionChanged   += (_, _) => UpdateOpenNote();
            CboDirection.SelectionChanged+= (_, _) => UpdateOpenNote();
            TxtProgram.TextChanged       += (_, _) => UpdateOpenNote();
            CboProtocol.SelectionChanged += (_, _) => UpdateOpenNote();
            TxtProgram.TextChanged       += (_, _) => UpdateServiceRow();
            // Follow the ComboBox's Text property, not its inner text box: that only exists after
            // layout, and a service filled in before then must already hide the "any program" note.
            var serviceText = System.ComponentModel.DependencyPropertyDescriptor
                                  .FromProperty(ComboBox.TextProperty, typeof(ComboBox));
            EventHandler onService = (_, _) => { UpdateOpenNote(); SyncPresetChips(); };
            serviceText.AddValueChanged(CboService, onService);
            Closed += (_, _) => serviceText.RemoveValueChanged(CboService, onService);
            Closed += (_, _) => _closed = true;
            // Closed halfway, the guard's question would lose its window.
            Closing += (_, e) => { if (_guarding) e.Cancel = true; };
        }

        // ── Service presets ───────────────────────────────────────────────────
        // Each chip toggles its port in Port(s) and switches Protocol to TCP when
        // adding. Chips also light up when a matching port is typed by hand, so a
        // typo (389 instead of 3389) shows as an unlit chip. A preset has a direction
        // too: matched in the other one, the chip lights amber, the colour of "In" in
        // the rule list, and its line says so, since 443 out (a browser) and 443 in
        // (a web server) are different rules.
        // To add a preset, add a line here.

        // Icon = an Icon.* geometry key (Theme/AppIcons.xaml), shown at 24 epx. Service names
        // the rule (both browser ports make one "Browser" rule); Title tells the chips apart.
        private sealed record ServicePreset(string Service, string Title, string Port, string Hint, string Icon, string Direction);

        private static readonly ServicePreset[] Presets =
        {
            new("SMB",     "SMB",           "445",  "File sharing (SMB)", "Icon.Smb",   "Out"),
            new("RDP",     "RDP",           "3389", "Remote Desktop",     "Icon.Rdp",   "Out"),
            new("Browser", "Browser HTTP",  "80",   "Web, HTTP",          "Icon.Http",  "Out"),
            new("Browser", "Browser HTTPS", "443",  "Web, HTTPS",         "Icon.Https", "Out"),
        };

        private readonly List<ToggleButton> _presetChips = new();
        private readonly Dictionary<ToggleButton, TextBlock> _chipLine = new();
        private string _autoName = "";   // last name a preset filled in

        private void BuildPresetChips()
        {
            var style = (Style)FindResource("PresetChip");
            foreach (var p in Presets)
            {
                var chip = new ToggleButton
                {
                    Content = BuildChipContent(p.Title, $"TCP {p.Port}", p.Icon, out var line),
                    ToolTip = $"{p.Hint}: TCP {p.Port}, {(p.Direction == "Out" ? "outbound" : "inbound")}",
                    Style   = style,
                    Tag     = p
                };
                _chipLine[chip] = line;
                chip.Click += PresetChip_Click;
                _presetChips.Add(chip);
                PresetPanel.Children.Add(chip);
            }
            BuildDnsChip(style);
            BuildNtpChip(style);
            BuildIisChip(style);
            TxtPorts.TextChanged         += (_, _) => SyncPresetChips();
            CboProtocol.SelectionChanged += (_, _) => SyncPresetChips();
            TxtProgram.TextChanged       += (_, _) => SyncPresetChips();
            CboDirection.SelectionChanged += (_, _) => SyncPresetChips();
            SyncPresetChips();
        }

        // Text inherits the chip's Foreground, so it turns white when the chip is on.
        private static UIElement BuildChipContent(string title, string detail, string iconKey) =>
            BuildChipContent(title, detail, iconKey, out _);

        private static UIElement BuildChipContent(string title, string detail, string iconKey, out TextBlock line)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            row.Children.Add(ChipIcon(iconKey));

            var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            text.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, FontSize = 13 });
            line = new TextBlock { Text = detail, FontSize = 11 }.Ref(TextBlock.ForegroundProperty, "Brush.TextDim");
            text.Children.Add(line);
            row.Children.Add(text);
            return row;
        }

        // The one place a preset's icon is made. Its stroke follows the chip's Foreground too.
        private static UIElement ChipIcon(string key)
        {
            var icon = IconText.Glyph(key, 24);
            icon.Margin = new Thickness(0, 0, 10, 0);
            return icon;
        }

        private bool ProtocolIsTcp =>
            (CboProtocol.SelectedItem as ComboBoxItem)?.Content?.ToString() == "TCP";

        // ── ICMP: no ports ────────────────────────────────────────────────────
        // ICMP and ICMPv6 have no ports, so the box is greyed and holds nothing: what it shows
        // is what Save writes. Ports typed before are put aside and come back with TCP, UDP or Any.

        private bool IsIcmp => Chosen(CboProtocol) is "ICMP" or "ICMPv6";

        private object? _portsTip;
        private string _portsAside = "";

        private void ShowPortsForProtocol()
        {
            var icmp = IsIcmp;
            if (icmp && TxtPorts.Text.Length > 0)
            {
                _portsAside   = TxtPorts.Text;
                TxtPorts.Text = "";
            }
            else if (!icmp && _portsAside.Length > 0)
            {
                if (TxtPorts.Text.Length == 0) TxtPorts.Text = _portsAside;
                _portsAside = "";
            }
            TxtPorts.IsEnabled = !icmp;
            TxtPorts.ToolTip   = icmp ? "ICMP and ICMPv6 have no ports." : _portsTip;
        }

        private static List<string> SplitPorts(string text) =>
            text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        // Chip state always follows the fields, never the other way round.
        private void SyncPresetChips()
        {
            var ports = ProtocolIsTcp ? SplitPorts(TxtPorts.Text) : new List<string>();
            var direction = (CboDirection.SelectedItem as ComboBoxItem)?.Content?.ToString();
            var iis = IsIisForm;
            var own   = (Style)FindResource("PresetChip");
            var other = (Style)FindResource("PresetChipOtherWay");
            foreach (var chip in _presetChips)
            {
                if (chip.Tag is not ServicePreset p) continue;
                // IIS is Browser 443's inbound counterpart: when it matches, it alone lights.
                var match = ports.Contains(p.Port) && !(iis && p.Port == "443");
                var otherWay = match && direction != null && direction != p.Direction;
                chip.IsChecked = match;
                chip.Style = otherWay ? other : own;
                if (_chipLine.TryGetValue(chip, out var line))
                    line.Text = otherWay ? $"{(direction == "In" ? "inbound" : "outbound")} · TCP {p.Port}" : $"TCP {p.Port}";
            }

            if (_iisChip != null) _iisChip.IsChecked = iis;
            if (_ntpChip != null) _ntpChip.IsChecked = IsNtpForm && direction != "In";
            ClearNtpNoteUnlessNtp();
            if (_dnsChip == null) return;
            var dns = IsDnsForm && direction != "In";
            _dnsChip.IsChecked = dns;
            DnsResolverRow.Visibility = dns ? Visibility.Visible : Visibility.Collapsed;
            if (dns && CboResolver.ItemsSource == null) FillResolvers(pickDefault: false);
            else if (dns) ShowCurrentResolver();
        }

        private void PresetChip_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleButton { Tag: ServicePreset p }) return;

            // The quick path for a new rule: a chip fills a direction and action not yet chosen
            // (outbound Allow); one already chosen stays.
            if (CboDirection.SelectedItem == null) SelectCombo(CboDirection, "Out");
            if (CboAction.SelectedItem == null)    SelectCombo(CboAction,    "Allow");

            List<string> ports;
            if (!ProtocolIsTcp)
            {
                // Ports already there belong to UDP/Any, so they don't carry over to TCP.
                ports = new List<string> { p.Port };
                SelectCombo(CboProtocol, "TCP");
            }
            else
            {
                ports = SplitPorts(TxtPorts.Text);
                if (ports.Contains(p.Port)) ports.RemoveAll(x => x == p.Port);
                else                        ports.Add(p.Port);
            }

            TxtPorts.Text = string.Join(",", ports);

            // Inbound RDP is served by one service: scope the rule to it (svchost.exe + TermService),
            // the same way Windows' own Remote Desktop rule is scoped. Only fills an empty Program.
            var inbound = (CboDirection.SelectedItem as ComboBoxItem)?.Content?.ToString() == "In";
            if (p.Service == "RDP" && inbound && ports.Contains(p.Port) && string.IsNullOrWhiteSpace(TxtProgram.Text))
            {
                TxtProgram.Text = @"%SystemRoot%\system32\svchost.exe";
                CboService.Text = "TermService";
            }
            UpdateAutoName();
            SyncPresetChips();   // TextChanged may not fire if the text didn't change
        }

        // ── DNS preset ───────────────────────────────────────────────────────
        // One rule: UDP 53 to one resolver, for the DNS Client service only (see DnsRule). One
        // resolver, so every answer in the log has one known source. No TCP rule: answers too
        // big for UDP retry over TCP 53, and the log shows that as a blocked connection when
        // it happens; the rule for it is made then, if wanted.

        private ToggleButton? _dnsChip;
        private const string DefaultResolver = "208.67.222.222";   // OpenDNS

        private void BuildDnsChip(Style style)
        {
            _dnsChip = new ToggleButton
            {
                Content = BuildChipContent("DNS", "DNS Client · UDP 53", "Icon.Dns"),
                ToolTip = "DNS for the DNS Client service only (svchost.exe, Dnscache), UDP 53, to one resolver you pick below.",
                Style   = style,
            };
            _dnsChip.Click += DnsChip_Click;
            PresetPanel.Children.Add(_dnsChip);
        }

        // The chip shows whether the form is the DNS preset, whoever filled it in.
        private bool IsDnsForm =>
            (CboProtocol.SelectedItem as ComboBoxItem)?.Content?.ToString() == "UDP" &&
            SplitPorts(TxtPorts.Text) is [ "53" ] &&
            IsDnsScoped;

        // The form's program and service are the DNS Client's: its one address is a resolver.
        private bool IsDnsScoped =>
            string.Equals(Environment.ExpandEnvironmentVariables(TxtProgram.Text.Trim()),
                          Environment.ExpandEnvironmentVariables(DnsRule.Program), StringComparison.OrdinalIgnoreCase) &&
            CboService.Text.Trim().Equals(DnsRule.Service, StringComparison.OrdinalIgnoreCase);

        private void DnsChip_Click(object sender, RoutedEventArgs e)
        {
            // One address stays when it already was the resolver (a DNS rule being edited, a
            // resolver not in the list) or is a listed one; anything else, such as an IIS client
            // host, belonged to another preset.
            var keep = _ips.Count == 1 &&
                       (IsDnsScoped || CurrentResolver(ConfigService.Effective().DnsPresets) != null);
            SelectCombo(CboDirection, "Out");
            SelectCombo(CboAction,    "Allow");
            SelectCombo(CboProtocol,  "UDP");
            TxtPorts.Text   = "53";
            TxtProgram.Text = DnsRule.Program;
            UpdateServiceRow();
            CboService.Text = DnsRule.Service;
            TogLimit.IsChecked = true;
            // The DNS Client asks from any of this machine's addresses, and its one destination is
            // the resolver: another preset's local address and client prefill go.
            TxtLocalAddress.Text = "";
            _ipPrefill    = "";
            TxtNewIP.Text = "";
            FillResolvers(pickDefault: !keep);
            SyncPresetChips();
        }

        // The resolvers come from the configuration (dnsPresets). An address already in the
        // rule that is one of them is shown as selected. Only the chip picks a default
        // (OpenDNS, or the first entry): a rule opened for editing keeps its address.
        private bool _fillingResolvers;

        private void FillResolvers(bool pickDefault)
        {
            var presets = ConfigService.Effective().DnsPresets;
            var current = CurrentResolver(presets);
            _fillingResolvers = true;
            try
            {
                CboResolver.ItemsSource = presets;
                CboResolver.SelectedItem = current
                    ?? (pickDefault ? presets.FirstOrDefault(p => p.Ip == DefaultResolver) ?? presets.FirstOrDefault() : null);
            }
            finally { _fillingResolvers = false; }
            if (pickDefault) ApplyResolver();
        }

        // The list entry for the rule's one address; the gateway entry matches the gateway's address.
        private AppConfig.DnsPreset? CurrentResolver(IEnumerable<AppConfig.DnsPreset> presets)
        {
            if (_ips.Count != 1) return null;
            var gateway = LocalNet.Primary()?.Gateway ?? "";
            return presets.FirstOrDefault(p => p.Ip == _ips[0]) ??
                   (_ips[0] == gateway ? presets.FirstOrDefault(p => p.Ip.Equals("gateway", StringComparison.OrdinalIgnoreCase)) : null);
        }

        // Shows the rule's address in the list once the list exists (it can be filled before the
        // address is: a rule opened for editing sets its service first).
        private void ShowCurrentResolver()
        {
            if (CboResolver.ItemsSource is not IEnumerable<AppConfig.DnsPreset> presets) return;
            _fillingResolvers = true;
            try { CboResolver.SelectedItem = CurrentResolver(presets); }
            finally { _fillingResolvers = false; }
        }

        private void CboResolver_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_fillingResolvers) ApplyResolver();
        }

        // Exactly one address: the chosen resolver replaces whatever the list held.
        private void ApplyResolver()
        {
            if (CboResolver.SelectedItem is not AppConfig.DnsPreset p) return;
            var gateway = p.Ip.Equals("gateway", StringComparison.OrdinalIgnoreCase);
            var ip = gateway ? LocalNet.Primary()?.Gateway ?? "" : p.Ip;
            if (ip.Length == 0) { ShowError("This machine has no gateway to use as the resolver."); return; }
            _ips = new List<string> { ip };
            TogLimit.IsChecked = true;           // a chosen resolver is the destination, not "any"
            RefreshIPTags();

            var current = TxtName.Text.Trim();
            if (current.Length > 0 && current != _autoName) return;
            _autoName = gateway ? $"DNS gateway {ip}" : $"DNS {p.Label}";
            TxtName.Text = _autoName;
        }

        // ── Time preset ──────────────────────────────────────────────────────
        // UDP 123 out to one time server, for the Windows Time service only (see NtpRule), as
        // Setup's Time sync tile writes it. The server prefilled is the gateway, as on the tile;
        // a rule already holding its server keeps it. Where W32Time can't be tied to (no service
        // identity, or not installed), the rule is for any program, and the form says why.

        private ToggleButton? _ntpChip;
        // Read once per window: the chip state is checked on every keystroke.
        private readonly bool _ntpCanBind = NtpRule.CanBind;
        private bool _ntpNoteShown;

        private void BuildNtpChip(Style style)
        {
            _ntpChip = new ToggleButton
            {
                Content = BuildChipContent("Time", "W32Time · UDP 123", "Icon.Clock"),
                ToolTip = "Time sync for the Windows Time service only (svchost.exe, W32Time), UDP 123, to one time server: " +
                          "your gateway, or another you type.",
                Style   = style,
            };
            _ntpChip.Click += NtpChip_Click;
            PresetPanel.Children.Add(_ntpChip);
        }

        // The chip shows whether the form is the Time preset, whoever filled it in.
        private bool IsNtpForm =>
            (CboProtocol.SelectedItem as ComboBoxItem)?.Content?.ToString() == "UDP" &&
            SplitPorts(TxtPorts.Text) is [ NtpRule.Port ] &&
            (IsNtpScoped || (!_ntpCanBind && TxtProgram.Text.Trim().Length == 0));

        private bool IsNtpScoped =>
            string.Equals(Environment.ExpandEnvironmentVariables(TxtProgram.Text.Trim()),
                          Environment.ExpandEnvironmentVariables(NtpRule.Program), StringComparison.OrdinalIgnoreCase) &&
            CboService.Text.Trim().Equals(NtpRule.Service, StringComparison.OrdinalIgnoreCase);

        private void NtpChip_Click(object sender, RoutedEventArgs e)
        {
            // One address stays when the form already was a time rule, UDP 123, bound or not (a
            // rule being edited, its server: an old unbound one keeps it when it gets bound here);
            // anything else, such as a resolver or IIS client hosts, belonged to another preset.
            var keep = _ips.Count == 1 &&
                       (CboProtocol.SelectedItem as ComboBoxItem)?.Content?.ToString() == "UDP" &&
                       SplitPorts(TxtPorts.Text) is [ NtpRule.Port ];
            SelectCombo(CboDirection, "Out");
            SelectCombo(CboAction,    "Allow");
            SelectCombo(CboProtocol,  "UDP");
            TxtPorts.Text = NtpRule.Port;
            if (_ntpCanBind)
            {
                TxtProgram.Text = NtpRule.Program;
                UpdateServiceRow();
                CboService.Text = NtpRule.Service;
            }
            else
            {
                TxtProgram.Text = "";
                CboService.Text = "";
                UpdateServiceRow();
            }
            TogLimit.IsChecked = true;
            // W32Time asks from any of this machine's addresses; its one destination is the server.
            TxtLocalAddress.Text = "";
            _ipPrefill    = "";
            TxtNewIP.Text = "";
            var gateway = LocalNet.Primary()?.Gateway ?? "";
            if (!keep)
            {
                _ips = gateway.Length > 0 ? new List<string> { gateway } : new List<string>();
                RefreshIPTags();
            }

            var current = TxtName.Text.Trim();
            if (current.Length == 0 || current == _autoName)
            {
                _autoName = _ips.Count == 1 ? $"NTP-{LocalNet.LastOctet(_ips[0])}" : "NTP";
                TxtName.Text = _autoName;
            }
            SyncPresetChips();
            if (_ips.Count == 0) ShowError("This machine has no gateway to use as the time server: type the server's address.");
            // After ShowError, which clears the status line.
            if (!_ntpCanBind)
            {
                EditStatus.Text = NtpRule.UnboundNote;
                EditStatus.Ref(TextBlock.ForegroundProperty, "Brush.TextMuted");
                _ntpNoteShown = true;
            }
        }

        // The note about an unbound Time rule goes with the Time form.
        private void ClearNtpNoteUnlessNtp()
        {
            if (!_ntpNoteShown || IsNtpForm) return;
            if (EditStatus.Text == NtpRule.UnboundNote) EditStatus.Text = "";
            _ntpNoteShown = false;
        }

        /// <summary>A rule's name as the app shows it: the app's own without CUSTOM, any other as stored.</summary>
        private static string Shown(MainWindow.FirewallRule rule) =>
            rule.Source == "GPO-Script" ? RuleWriter.Plain(rule.Name) : rule.Name;

        // ── IIS preset ───────────────────────────────────────────────────────
        // Inbound HTTPS to this server from named hosts only. IIS doesn't own its sockets: the
        // kernel's HTTP listener (HTTP.sys) accepts the connection as System and only then hands
        // the request to an IIS worker, so System is the only program the rule can name. The
        // prefill is strict (443, this machine's address, no client yet); anything wider is
        // the user's own edit.

        private ToggleButton? _iisChip;

        private void BuildIisChip(Style style)
        {
            _iisChip = new ToggleButton
            {
                Content = BuildChipContent("IIS", "HTTPS in · TCP 443", "Icon.Iis"),
                ToolTip = "Inbound HTTPS to this server's address, from the hosts you name. The rule names System: IIS " +
                          "is reached through HTTP.sys, so anything else HTTP.sys serves on the same port passes too " +
                          "(netsh http show servicestate lists who is registered).",
                Style   = style,
            };
            _iisChip.Click += IisChip_Click;
            PresetPanel.Children.Add(_iisChip);
        }

        private bool IsIisForm =>
            (CboDirection.SelectedItem as ComboBoxItem)?.Content?.ToString() == "In" &&
            ProtocolIsTcp &&
            SplitPorts(TxtPorts.Text).Contains("443") &&
            TxtProgram.Text.Trim().Equals("System", StringComparison.OrdinalIgnoreCase);

        private void IisChip_Click(object sender, RoutedEventArgs e)
        {
            var net = LocalNet.Primary();
            // Already the IIS form with hosts entered (a rule being edited): nothing to fill, and
            // the hosts and local address stay.
            if (IsIisForm && _ips.Count > 0) { _ipPrefill = net?.Prefix ?? ""; SyncPresetChips(); return; }
            SelectCombo(CboDirection, "In");
            SelectCombo(CboAction,    "Allow");
            SelectCombo(CboProtocol,  "TCP");
            TxtPorts.Text    = "443";
            TxtProgram.Text  = "System";
            CboService.Text  = "";
            UpdateServiceRow();
            TogLimit.IsChecked = true;
            _ips = new List<string>();
            RefreshIPTags();
            TxtLocalAddress.Text = net?.Address ?? "";
            _ipPrefill   = net?.Prefix ?? "";
            TxtNewIP.Text = _ipPrefill;

            var current = TxtName.Text.Trim();
            if ((current.Length == 0 || current == _autoName) && net != null)
            {
                _autoName = $"IIS-{LocalNet.LastOctet(net.Address)}-IN";
                TxtName.Text = _autoName;
            }
            SyncPresetChips();
            if (net == null) ShowError("This machine's address couldn't be read: enter the local address and the client hosts in full.");
            TxtNewIP.Focus();
            TxtNewIP.CaretIndex = TxtNewIP.Text.Length;
        }

        // Name follows the selected presets only while it is empty or still holds the last
        // auto-filled name, so a typed name is never overwritten.
        private void UpdateAutoName()
        {
            var current = TxtName.Text.Trim();
            if (current.Length > 0 && current != _autoName) return;
            // A port added to the IIS form (80 next to 443) keeps the preset's name.
            if (IsIisForm) return;

            var ports = ProtocolIsTcp ? SplitPorts(TxtPorts.Text) : new List<string>();
            _autoName = string.Join(" + ", Presets
                .Where(p => ports.Contains(p.Port))
                .Select(p => p.Service)
                .Distinct());
            TxtName.Text = _autoName;
        }

        // ── Program path follow-ups ──────────────────────────────────────────

        private void TxtProgram_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            // Explorer's "Copy as path" wraps the path in quotes, which Windows would then keep
            // as part of the program's name: a rule that never matches. Typed or pasted, a path
            // in one pair of quotes loses them here, in the field, where it shows.
            if (TxtProgram.IsKeyboardFocusWithin && Unquoted(TxtProgram.Text) is { } unquoted)
            {
                TxtProgram.Text = unquoted;
                TxtProgram.CaretIndex = unquoted.Length;
                return;   // the change above runs this handler again with the plain path
            }

            var path   = TxtProgram.Text.Trim();
            var hasExe = path.Length > 0;

            // Clear any "no program path" validation error
            if (hasExe && ValidationMsg.Text.Contains("path"))
                ValidationMsg.Visibility = Visibility.Collapsed;

            ScheduleProgramNote();
        }

        // ── Populate ─────────────────────────────────────────────────────────

        private void PopulateFromRule(MainWindow.FirewallRule rule, bool asCopy = false)
        {
            // Viewed, not edited (see OpensReadOnly). A copy is a new rule of this app's own.
            var foreign = ForeignParts(rule.RawValue);
            _isReadOnly = !asCopy && OpensReadOnly(rule);
            if (!asCopy && foreign.Count > 0)
            {
                ForeignDetail.Text = $"This rule wasn't made by this editor: it also contains {JoinWords(foreign)}.";
                ForeignNote.Visibility = Visibility.Visible;
            }
            TitleText.Text           = _isReadOnly ? "View Rule" : "Edit Rule";
            ReadOnlyLabel.Visibility = _isReadOnly ? Visibility.Visible : Visibility.Collapsed;
            BtnSave.IsEnabled        = !_isReadOnly;
            SourceLabel.Text         = rule.Source;
            ShowSource(rule.Source);
            // The app's own rules show their plain name, as in the grid; saving puts CUSTOM back.
            TxtName.Text             = rule.Source == "GPO-Script" ? RuleWriter.Plain(rule.Name) : rule.Name;
            TxtName.IsReadOnly       = _isReadOnly;

            SelectCombo(CboDirection, rule.Direction);
            SelectCombo(CboAction,    rule.Action);
            // Read from the stored number, so the list shows exactly what the rule holds.
            var protocol = rule.RawValue.Split('|')
                .FirstOrDefault(p => p.StartsWith("Protocol=", StringComparison.OrdinalIgnoreCase))?["Protocol=".Length..].Trim() ?? "";
            SelectCombo(CboProtocol,  Protocols.Name(protocol));

            TxtPorts.Text = rule.Ports;

            TxtProgram.Text = ExtractFullProgram(rule.RawValue);
            CboService.Text = ExtractService(rule.RawValue);
            UpdateServiceRow();

            TogActive.IsChecked = RuleText.IsOn(rule.RawValue);

            if (string.IsNullOrEmpty(rule.RemoteAddress) || rule.RemoteAddress == "Any")
            {
                TogLimit.IsChecked = false;
            }
            else
            {
                TogLimit.IsChecked = true;
                _ips = rule.RemoteAddress.Split(',').Select(s => s.Trim())
                    .Where(s => !string.IsNullOrEmpty(s)).ToList();
                RefreshIPTags();
            }

            TxtLocalAddress.Text = string.Join(",", rule.RawValue.Split('|')
                .Where(p => p.StartsWith("LA4=", StringComparison.OrdinalIgnoreCase))
                .Select(p => p["LA4=".Length..].Trim()));

            SetFieldsReadOnly(_isReadOnly);
            UpdateOpenNote();
            // A stored name can hold what Save refuses (_ above all): name it and offer the
            // replacement now, rather than only failing on Save.
            if (!_isReadOnly) _nameHygiene?.NoteExisting();
        }

        private static string ExtractFullProgram(string raw)
        {
            var part = raw.Split('|')
                .FirstOrDefault(p => p.StartsWith("App=", StringComparison.OrdinalIgnoreCase));
            return part?["App=".Length..] ?? "";
        }

        private void SetFieldsReadOnly(bool ro)
        {
            TxtPorts.IsReadOnly    = ro;
            // Nothing to apply a preset to: the box goes, and the window keeps the form's width.
            if (ro && PresetBox.Visibility == Visibility.Visible)
            {
                PresetBox.Visibility = Visibility.Collapsed;
                Width -= PresetBox.Width + PresetBox.Margin.Left;
            }
            CboResolver.IsEnabled  = !ro;
            TxtProgram.IsReadOnly  = ro;
            // A scan or a browsed file would change the path shown, on a rule that can't be saved.
            BtnUpdateLocation.IsEnabled = !ro;
            if (ro) BtnUpdateLocation.ToolTip = "Read-only: this rule can't be changed here.";
            BtnBrowseExe.IsEnabled = !ro;
            if (ro) BtnBrowseExe.ToolTip = "Read-only: this rule can't be changed here.";
            BtnService.IsEnabled   = !ro;
            BtnStoreApp.IsEnabled  = !ro;
            if (ro) BtnService.ToolTip = BtnStoreApp.ToolTip = "Read-only: this rule can't be changed here.";
            TxtLocalAddress.IsReadOnly = ro;
            CboService.IsEnabled   = !ro;
            TxtNewIP.IsReadOnly    = ro;
            CboDirection.IsEnabled = !ro;
            CboAction.IsEnabled    = !ro;
            CboProtocol.IsEnabled  = !ro;
            TogLimit.IsEnabled     = !ro;
            TogActive.IsEnabled    = !ro;
        }

        // Shows the value as it is: no value selects nothing, and one the list doesn't have is
        // added to it, so a rule is never shown as something it isn't. Validate refuses those.
        private static void SelectCombo(ComboBox cbo, string value)
        {
            foreach (var item in cbo.Items.OfType<ComboBoxItem>())
                if (string.Equals(item.Content?.ToString(), value, StringComparison.OrdinalIgnoreCase))
                { cbo.SelectedItem = item; return; }
            if (string.IsNullOrWhiteSpace(value)) { cbo.SelectedIndex = -1; return; }
            var shown = new ComboBoxItem { Content = value.Trim() };
            cbo.Items.Add(shown);
            cbo.SelectedItem = shown;
        }

        private static string? Chosen(ComboBox cbo) => (cbo.SelectedItem as ComboBoxItem)?.Content?.ToString();

        // ── IP tag management ─────────────────────────────────────────────────

        private void RefreshIPTags()
        {
            IPTagPanel.Children.Clear();
            foreach (var ip in _ips)
            {
                var ip2 = ip;
                // A range or subnet shows its exact span; a single address needs no explaining.
                var span = Ipv4Scope.Describe(ip);
                var btn = new Button
                {
                    Content   = $"{ip}  ✕",
                    Style     = (Style)Resources["TagBtn"],
                    IsEnabled = !_isReadOnly,
                    ToolTip   = span.Length > 0 ? span : $"Remove {ip}"
                };
                System.Windows.Automation.AutomationProperties.SetName(btn, $"Remove {ip}");
                btn.Click += (s, e) => { _ips.Remove(ip2); RefreshIPTags(); };
                IPTagPanel.Children.Add(btn);
            }
            ShowCurrentResolver();               // the Resolver list follows the address list
        }

        private void BtnAddIP_Click(object sender, RoutedEventArgs e)
        {
            if (!AddRemote()) return;
            TxtNewIP.Focus();
            TxtNewIP.CaretIndex = TxtNewIP.Text.Length;
        }

        // The address box into the list. Also for addresses handed over with an observed rule,
        // so they are read and shown as typed ones are; a refused entry stays in the box.
        private bool AddRemote()
        {
            var text = TxtNewIP.Text.Trim();
            if (text.Length == 0 || text == _ipPrefill) return false;
            if (BadScope(text, AnyRemote) is { } why) { ShowError($"Remote address: {why}."); return false; }
            foreach (var entry in SplitEntries(text))
                if (!_ips.Contains(entry)) _ips.Add(entry);
            RefreshIPTags();
            ValidationMsg.Visibility = Visibility.Collapsed;
            // The next host starts from the same network part again.
            TxtNewIP.Text = _ipPrefill;
            return true;
        }

        // The network part the IIS preset puts in the address box; "" otherwise.
        private string _ipPrefill = "";

        // Same rule as the rule list: an Allow rule is scoped when it has a fixed address or a
        // fixed program. With neither, it's a blanket open in either direction: amber note.
        private void UpdateOpenNote()
        {
            if (OpenNote == null) return;
            var allow     = (CboAction.SelectedItem as ComboBoxItem)?.Content?.ToString() == "Allow";
            var inbound   = (CboDirection.SelectedItem as ComboBoxItem)?.Content?.ToString() == "In";
            var any       = TogLimit.IsChecked != true;
            // svchost.exe without a service scopes nothing: every service in every svchost matches.
            var noProgram = string.IsNullOrWhiteSpace(TxtProgram.Text) || (IsSvchost && SelectedService.Length == 0);

            if (allow && any && noProgram)
            {
                OpenNoteTitle.Text  = inbound ? "Any source, any program" : "Any destination, any program";
                // ICMP has no ports, and an inbound one is answered by Windows itself, not a program.
                var icmp = IsIcmp ? Chosen(CboProtocol) : null;
                // ICMPv6 takes no IPv4 address, and Save refuses one: no scoping to point to.
                OpenNoteDetail.Text = (inbound, icmp) switch
                {
                    (true,  "ICMPv6") => "Every machine on every network this PC is connected to can reach this PC with ICMPv6.",
                    (false, "ICMPv6") => "Every program on this PC can reach every address with ICMPv6.",
                    (true,  null) => "Every machine on every network this PC is connected to can reach these ports, whatever program listens. Set a program or restrict the source to scope it.",
                    (true,  _)    => $"Every machine on every network this PC is connected to can reach this PC with {icmp}. Restrict the source to scope it.",
                    (false, null) => "Every program on this PC can reach every address on these ports. Set a program or restrict the destination to scope it.",
                    (false, _)    => $"Every program on this PC can reach every address with {icmp}. Set a program or restrict the destination to scope it.",
                };
                OpenNote.Visibility = Visibility.Visible;
            }
            else
            {
                OpenNote.Visibility = Visibility.Collapsed;
            }
        }

        // ── Service scoping (svchost.exe only) ──────────────────────────────────

        private bool IsSvchost =>
            Path.GetFileName(TxtProgram.Text.Trim()).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase);

        private string SelectedService => ServiceRow.Visibility == Visibility.Visible ? CboService.Text.Trim() : "";

        private void UpdateServiceRow()
        {
            var show = IsSvchost;
            if (show && CboService.ItemsSource == null)
            {
                var text = CboService.Text;                              // keep what's typed or loaded
                CboService.ItemsSource = LiveDropSource.SharedProcessServices();
                CboService.Text = text;
            }
            ServiceRow.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            UpdateOpenNote();
        }

        private static string ExtractService(string raw) =>
            raw.Split('|').FirstOrDefault(p => p.StartsWith("Svc=", StringComparison.OrdinalIgnoreCase))?["Svc=".Length..] ?? "";

        // The switch turns the address limit on, and the box beneath it with it. Off, the box
        // stays in view but greyed, so it's clear what switching on gives. A new rule starts
        // with the limit on and nothing in it: "any" is chosen by switching off, never a default.
        private void TogLimit_Checked(object sender, RoutedEventArgs e)   => ShowLimit();
        private void TogLimit_Unchecked(object sender, RoutedEventArgs e) => ShowLimit();

        private void ShowLimit()
        {
            if (IPSection == null || AnyLabel == null) return;
            var on = TogLimit.IsChecked == true;
            IPSection.IsEnabled = on;
            IPSection.Opacity   = on ? 1.0 : 0.45;
            // On an inbound rule the remote address is where the traffic comes from.
            var inbound = (CboDirection.SelectedItem as ComboBoxItem)?.Content?.ToString() == "In";
            AnyLabel.Text = on ? "Only these addresses" : inbound ? "Any source" : "Any destination";
        }

        // ── Browse exe ───────────────────────────────────────────────────────

        private void BtnBrowseExe_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title = "Select executable", Filter = "Executables (*.exe)|*.exe",
                CheckFileExists = true
            };
            if (dlg.ShowDialog() == true) TxtProgram.Text = dlg.FileName;
        }

        // The update scan walks folders that can hold thousands of files: it runs off the window's
        // thread, and the buttons that start one stay off until it's done.
        private void SetScanning(bool on)
        {
            BtnStoreApp.IsEnabled        = !on && !_isReadOnly;
            BtnUpdateLocation.IsEnabled  = !on && !_isReadOnly;
            if (on) SetStatus("Scanning…");
        }

        // The window stays usable during a scan: a path typed meanwhile is the newer choice.
        private bool ProgramChangedDuringScan(string before)
        {
            if (TxtProgram.Text == before) return false;
            ShowError("Program was changed during the scan, so the scan's result wasn't used.");
            return true;
        }

        // ── Service, Store app, Pin ──────────────────────────────────────────

        // A rule for one Windows service: svchost.exe by its full path, then the list of the
        // services it hosts, open to pick from. A program typed by hand isn't needed (or risked:
        // "srvhost.exe" would be another file).
        private void BtnService_Click(object sender, RoutedEventArgs e)
        {
            if (!IsSvchost || !ProgramTrust.IsFullPath(Environment.ExpandEnvironmentVariables(TxtProgram.Text.Trim())))
            {
                TxtProgram.Text = NtpRule.Program;   // %SystemRoot%\system32\svchost.exe
                CboService.Text = "";
            }
            UpdateServiceRow();
            CboService.Focus();
            CboService.IsDropDownOpen = true;
        }

        // An installed Store app, by the exe it starts (see StoreApps).
        private void BtnStoreApp_Click(object sender, RoutedEventArgs e)
        {
            var picker = new StoreAppWindow { Owner = this };
            if (picker.ShowDialog() == true && picker.SelectedPath != null)
            {
                TxtProgram.Text = picker.SelectedPath;
                SetStatus($"✔ Selected: {picker.SelectedPath}");
            }
        }

        // Pins the file by its exact content, or removes the pin (see Pins). Pins belong to the
        // file, not the rule: every rule for it shows the result. Saved at once, rule or not.
        private async void BtnPin_Click(object sender, RoutedEventArgs e)
        {
            if (ProgramTrust.PathOf(TxtProgram.Text) is not { } path || !File.Exists(path))
            {
                ShowError("Pin: give the full path of a program file that is there.");
                return;
            }
            var pinned = Pins.For(path).State != Pins.State.None;
            BtnPin.IsEnabled = false;
            SetStatus(pinned ? "Removing the pin…" : "Pinning: computing the fingerprint (SHA-256)…");
            string? error;
            try { error = await Task.Run(() => pinned ? Pins.Remove(path) : Pins.Add(path)); }
            finally { if (!_closed) BtnPin.IsEnabled = true; }
            if (_closed) return;
            if (error != null) { ShowError($"Pin: {error}."); return; }
            SetStatus(pinned ? $"✔ Pin removed: {Path.GetFileName(path)}" : $"✔ Pinned: {Path.GetFileName(path)}");
            ScheduleProgramNote(immediately: true);
        }

        // ── What is known about the program ──────────────────────────────────
        // Under the buttons: the signer, a look-alike, the pin, a Store app's moving folder, in
        // the colours of the rules list. Looked up shortly after typing stops, off the window's thread.

        private System.Windows.Threading.DispatcherTimer? _noteTimer;
        private int _noteVersion;

        private void ScheduleProgramNote(bool immediately = false)
        {
            _noteTimer ??= CreateNoteTimer();
            _noteTimer.Stop();
            if (immediately) _ = ShowProgramNoteAsync();
            else _noteTimer.Start();
        }

        private System.Windows.Threading.DispatcherTimer CreateNoteTimer()
        {
            var t = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(350) };
            t.Tick += async (_, _) => { t.Stop(); await ShowProgramNoteAsync(); };
            Closed += (_, _) => t.Stop();
            return t;
        }

        private async Task ShowProgramNoteAsync()
        {
            var version = ++_noteVersion;
            var text    = TxtProgram.Text.Trim();
            var expanded = Environment.ExpandEnvironmentVariables(text);
            var store   = expanded.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);
            BtnPin.Visibility = Visibility.Collapsed;

            ProgramVerdict? verdict = null;
            string? plain = null;
            var tone = ProgramTone.None;
            if (text.Length == 0 || text.Equals("System", StringComparison.OrdinalIgnoreCase)) { }
            else if (!ProgramTrust.IsFullPath(expanded))
            {
                plain = "Not a full path: a rule matches a program by its full path, so this one would never match.";
                tone  = ProgramTone.Off;
            }
            else if (ProgramTrust.PathOf(text) is not { } path)
                plain = "On a network path: not looked at, as an unreachable share can stall for seconds.";
            else if (!File.Exists(path))
                plain = "No file at this path.";
            else
            {
                verdict = await Task.Run(() => ProgramTrust.Evaluate(path));
                if (_closed || version != _noteVersion) return;
                BtnPin.Visibility = _isReadOnly ? Visibility.Collapsed : Visibility.Visible;
                IconText.SetText(BtnPin, Pins.For(path).State != Pins.State.None ? "Unpin" : "Pin");
            }
            if (_closed || version != _noteVersion) return;

            ProgramNote.Inlines.Clear();
            var main = verdict?.Tip ?? plain;
            if (main != null)
                ProgramNote.Inlines.Add(new System.Windows.Documents.Run(main) { Foreground = ToneBrush(verdict?.Tone ?? tone) });
            if (store)
            {
                if (ProgramNote.Inlines.Count > 0) ProgramNote.Inlines.Add(new System.Windows.Documents.LineBreak());
                ProgramNote.Inlines.Add(new System.Windows.Documents.Run(
                    "Store app: its folder changes with every update, and this rule then points at nothing. " +
                    "The rules list marks it, and Update here finds the new folder.")
                    { Foreground = ToneBrush(ProgramTone.None) });
            }
            ProgramNote.Visibility = ProgramNote.Inlines.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        // The rules list's colours (see ProgramTone); the outlier colour comes from the window
        // that defines it, which also follows a contrast theme.
        private System.Windows.Media.Brush ToneBrush(ProgramTone tone)
        {
            var key = tone switch
            {
                ProgramTone.Windows  => "Brush.Ok",
                ProgramTone.Signed   => "Brush.OkText",
                ProgramTone.Pinned   => "Brush.OkText",
                ProgramTone.Unsigned => "Rare.Text",
                ProgramTone.Off      => "Brush.WarnText",
                ProgramTone.Mismatch => "Brush.ErrorText",
                _                    => "Brush.TextMuted",
            };
            var owner = (FrameworkElement?)Owner ?? Application.Current.MainWindow;
            return (owner?.TryFindResource(key) ?? TryFindResource(key) ?? TryFindResource("Brush.TextMuted")) as System.Windows.Media.Brush
                   ?? System.Windows.Media.Brushes.Gray;
        }

        // ── Update Location ──────────────────────────────────────────────────

        // A Store package folder is Name_Version_Architecture_ResourceId_PublisherId
        // (Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe). A package name has no "_",
        // so the name is everything before the first one, when a version follows it.
        private static readonly Regex PackageFolder =
            new(@"^(?<name>[^_]+)_\d+(\.\d+)*(_|$)", RegexOptions.CultureInvariant);

        /// <summary>The package name of a Store package folder (one directly in WindowsApps); null for any other folder.</summary>
        internal static string? PackageName(string folder) =>
            Path.GetFileName(Path.GetDirectoryName(folder) ?? "").Equals("WindowsApps", StringComparison.OrdinalIgnoreCase) &&
            PackageFolder.Match(Path.GetFileName(folder)) is { Success: true } m
                ? m.Groups["name"].Value
                : null;

        private async void BtnUpdateLocation_Click(object sender, RoutedEventArgs e)
        {
            // A saved rule holds %SystemDrive%\…: the folders are worked out on the real path, and
            // the one found goes back through the usual conversion on Save.
            var before      = TxtProgram.Text;
            var currentPath = Environment.ExpandEnvironmentVariables(before.Trim());
            if (string.IsNullOrEmpty(currentPath))
            { ShowError("No program path set — use … to browse first."); return; }
            // The exe is usually gone from this path (an update moved it): the scan looks for
            // its new location.

            SetScanning(true);
            (List<string> Found, string? Error) scan;
            try { scan = await Task.Run(() => FindMoved(currentPath)); }
            finally { SetScanning(false); }
            if (_closed || ProgramChangedDuringScan(before)) return;

            if (scan.Error != null) { ShowError(scan.Error); return; }
            if (scan.Found.Count == 1)
            {
                TxtProgram.Text = scan.Found[0];
                SetStatus($"✔ Updated: {scan.Found[0]}");
                return;
            }
            var picker = new ExePickerWindow(scan.Found, currentPath) { Owner = this };
            if (picker.ShowDialog() == true && picker.SelectedPath != null)
            {
                TxtProgram.Text = picker.SelectedPath;
                SetStatus($"✔ Updated: {picker.SelectedPath}");
            }
            else EditStatus.Text = "";
        }

        // Runs off the window's thread: files only, no controls. Likely matches (the same path
        // inside another version's folder) come first.
        private static (List<string> Found, string? Error) FindMoved(string currentPath)
        {
            try
            {
                var exeName = Path.GetFileName(currentPath);
                var exeDir  = Path.GetDirectoryName(currentPath) ?? "";

                // The version folder is the package folder the exe is in, directly or further down
                // (…\WindowsApps\Microsoft.WindowsTerminal_1.21…\WindowsTerminal.exe). Only a folder
                // inside WindowsApps counts: elsewhere a name like Backup_2024 is no package.
                Match? package = null;
                var versionDir = "";
                for (var d = exeDir; !string.IsNullOrEmpty(d); d = Path.GetDirectoryName(d))
                {
                    if (!Path.GetFileName(Path.GetDirectoryName(d) ?? "").Equals("WindowsApps", StringComparison.OrdinalIgnoreCase)) continue;
                    if (PackageFolder.Match(Path.GetFileName(d)) is { Success: true } m) { package = m; versionDir = d; }
                    break;
                }

                Func<string, bool> sameApp;
                string pattern;
                if (package != null)
                {
                    // Another version of the same package: the name matches exactly, so
                    // Microsoft.WindowsTerminalPreview isn't taken for Microsoft.WindowsTerminal.
                    var name = package.Groups["name"].Value;
                    sameApp = d => PackageFolder.Match(d) is { Success: true } m &&
                                   m.Groups["name"].Value.Equals(name, StringComparison.OrdinalIgnoreCase);
                    pattern = $"{name}_<version>";
                }
                else
                {
                    // Not in a package folder, so there's no name to read off.
                    // The exe's folder's parent is taken as the version folder, and another version's
                    // folder as one starting with the same five characters.
                    versionDir = Path.GetDirectoryName(exeDir) ?? "";
                    var folder  = Path.GetFileName(versionDir);
                    var prefix5 = folder.Length >= 5 ? folder[..5] : folder;
                    sameApp = d => d.Length >= 5 && d[..5].Equals(prefix5, StringComparison.OrdinalIgnoreCase);
                    pattern = $"{prefix5}*";
                }
                var baseDir = Path.GetDirectoryName(versionDir) ?? "";

                if (!Directory.Exists(baseDir)) return (new(), $"Base directory not found:\n{baseDir}");

                var candidateDirs = Directory.GetDirectories(baseDir)
                    .Where(d => sameApp(Path.GetFileName(d)))
                    .ToList();
                if (candidateDirs.Count == 0)
                    return (new(), $"No folders matching '{pattern}' found in:\n{baseDir}");

                var subPath = Path.GetRelativePath(versionDir, currentPath); // e.g. app\Claude.exe
                var results = new List<(string FullPath, bool SubPathMatch)>();
                foreach (var dir in candidateDirs)
                {
                    // The same relative path in a newer folder is the most likely match.
                    var subPathMatch = Path.Combine(dir, subPath);
                    if (File.Exists(subPathMatch))
                    {
                        results.Add((subPathMatch, true));
                        continue;
                    }

                    try
                    {
                        foreach (var f in Directory.GetFiles(dir, exeName, SearchOption.AllDirectories))
                            results.Add((f, false));
                    }
                    catch { /* access denied on some dirs */ }
                }

                var found = results
                    .DistinctBy(r => r.FullPath.ToLowerInvariant())
                    .OrderByDescending(r => r.SubPathMatch)
                    .ThenBy(r => r.FullPath)
                    .Select(r => r.FullPath)
                    .ToList();
                return found.Count == 0
                    ? (found, $"'{exeName}' not found under any '{pattern}' folder in:\n{baseDir}")
                    : (found, null);
            }
            catch (Exception ex) { return (new(), $"Scan error: {ex.Message}"); }
        }

        // ── Save ─────────────────────────────────────────────────────────────

        private async void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            if (_guarding || !Validate()) return;
            try
            {
                // The field holds the plain name; the rule stores it as "CUSTOM <name>", so Windows'
                // own tools show where it came from (RuleWriter). A rule being edited keeps its key:
                // the key is its identity (quick switches and Lock down find rules by it).
                var name   = RuleWriter.Plain(TxtName.Text);
                var regKey = _isNew ? RuleWriter.KeyFor(name) : _rule!.RegistryKey;

                var fields = new List<string>
                {
                    $"Action={(CboAction.SelectedItem as ComboBoxItem)?.Content}",
                    $"Dir={(CboDirection.SelectedItem as ComboBoxItem)?.Content}"
                };

                var proto = (CboProtocol.SelectedItem as ComboBoxItem)?.Content?.ToString();
                if (proto != "Any") fields.Add($"Protocol={Protocols.Number(proto)}");

                // In rules match on this machine's port (LPort), Out rules on the other side's (RPort).
                var ports    = TxtPorts.Text.Trim();
                var portKey  = (CboDirection.SelectedItem as ComboBoxItem)?.Content?.ToString() == "In" ? "LPort" : "RPort";
                if (!string.IsNullOrEmpty(ports) && !IsIcmp) fields.Add($"{portKey}={ports}");

                var ra = TogLimit.IsChecked != true ? "Any" : string.Join(",", _ips);
                if (!string.IsNullOrEmpty(ra)) fields.Add($"RA4={ra}");

                var la = TxtLocalAddress.Text.Trim();
                if (la.Length > 0) fields.Add($"LA4={la}");

                var prog = TxtProgram.Text.Trim();
                if (!string.IsNullOrEmpty(prog)) fields.Add($"App={prog}");

                var active = TogActive.IsChecked == true ? "Active=TRUE" : "Active=FALSE";

                if (!string.IsNullOrEmpty(prog))
                {
                    fields.RemoveAll(f => f.StartsWith("App="));
                    fields.Add($"App={PortablePath.ToPortable(prog)}");
                }

                // One service inside svchost.exe (only saved while the program is svchost.exe).
                var svc = SelectedService;
                if (svc.Length > 0) fields.Add($"Svc={svc}");

                // A missing RA4 already means any address.
                fields.RemoveAll(f => f == "RA4=Any");

                // WFP needs one field per value: a comma-joined RA4 makes it silently reject the rule.
                var expanded = new List<string>();
                foreach (var field in fields)
                {
                    if ((field.StartsWith("RPort=") || field.StartsWith("LPort=")) && field.Contains(","))
                    {
                        var portKind = field[..field.IndexOf('=')];   // "RPort" or "LPort"
                        foreach (var port in field[(portKind.Length + 1)..].Split(','))
                            expanded.Add($"{portKind}={port.Trim()}");
                    }
                    else if ((field.StartsWith("RA4=") || field.StartsWith("LA4=")) && field.Contains(","))
                    {
                        var kind = field[..3];                        // "RA4" or "LA4"
                        foreach (var addr4 in field[4..].Split(','))
                            if (addr4.Trim().Length > 0) expanded.Add($"{kind}={addr4.Trim()}");
                    }
                    else expanded.Add(field);
                }

                var val = $"v2.33|{string.Join("|", expanded)}|{active}|Name={RuleWriter.StoredName(name)}|";

                // Rewriting a rule of yours can take away what lets the current Remote Desktop
                // client in: the session guard judges that first (it writes nothing itself).
                if (!_isNew && !await RuleChangeAllowed(regKey, val)) return;

                // Only policy rules are saved here (Windows' local rules open read-only). A machine
                // with no policy rules yet has no rules key: it is made with the first one.
                using var key = Registry.LocalMachine.CreateSubKey(RegGPO);
                if (key == null) { ShowError("Cannot open registry for writing."); return; }

                // The key comes from the name. A new rule or a copy never replaces an existing
                // one: changing a rule goes through Edit, where it is clear which rule changes.
                if (_isNew && key.GetValue(regKey) != null)
                {
                    ShowError($"A rule named {name} already exists. To change it, select it and use Edit; " +
                              "to keep both, give this one another name.");
                    return;
                }

                key.SetValue(regKey, val, RegistryValueKind.String);

                // Applied and checked in the background; the main window's status line reports it.
                _ = PolicyApply.RunAsync($"Saved: {name}", new[] { regKey });

                SetStatus("Saved.");
                DialogResult = true;
                Close();
            }
            catch (Exception ex) { ShowError(ex.Message); }
        }

        private bool Validate()
        {
            if (string.IsNullOrWhiteSpace(TxtName.Text))
            { ShowError("Name is required."); return false; }
            if (TextHygiene.BadName(TxtName.Text.Trim()) is { } badName) { ShowError(badName); return false; }

            // Nothing is assumed: each is chosen, or filled in by a preset.
            var dir = Chosen(CboDirection);
            if (dir == null) { ShowError("Choose a direction."); return false; }
            if (dir is not ("In" or "Out")) { ShowError($"Direction {dir} isn't one the editor saves: choose In or Out."); return false; }
            var action = Chosen(CboAction);
            if (action == null) { ShowError("Choose an action."); return false; }
            if (action is not ("Allow" or "Block")) { ShowError($"Action {action} isn't one the editor saves: choose Allow or Block."); return false; }
            var proto = Chosen(CboProtocol);
            if (proto == null) { ShowError("Choose a protocol."); return false; }
            if (proto is not ("TCP" or "UDP" or "ICMP" or "ICMPv6" or "Any"))
            { ShowError($"Protocol {proto} isn't one the editor saves: choose TCP, UDP, ICMP, ICMPv6 or Any."); return false; }

            var ports = TxtPorts.Text.Trim();
            if (ports.Length > 0)
            {
                if (proto is not ("TCP" or "UDP")) { ShowError("Ports need TCP or UDP."); return false; }
                if (Ipv4Scope.BadPorts(ports) is { } badPorts) { ShowError($"Port(s): {badPorts}."); return false; }
            }

            // Every address the editor takes is IPv4 and ICMPv6 runs only over IPv6, so any
            // address limit, filled or not yet, leaves a rule that never matches.
            if (proto == "ICMPv6")
            {
                if (TogLimit.IsChecked == true)
                {
                    ShowError("ICMPv6 never carries an IPv4 address: this rule would match nothing. Switch the address limit off, or choose ICMP.");
                    return false;
                }
                if (TxtLocalAddress.Text.Trim().Length > 0)
                {
                    ShowError("ICMPv6 never carries an IPv4 address: this rule would match nothing. Clear the local address, or choose ICMP.");
                    return false;
                }
            }

            if (TogLimit.IsChecked == true)
            {
                // A box still holding only the prefilled network part ("192.168.0.") is empty.
                var pending = TxtNewIP.Text.Trim();
                if (pending == _ipPrefill) pending = "";
                if (pending.Length > 0 && BadScope(pending, AnyRemote) is { } badPending)
                { ShowError($"Remote address: {badPending}."); return false; }
                // Entries that came with the rule or a resolver are held to the same reading.
                foreach (var ip in _ips)
                    if (BadScope(ip, AnyRemote) is { } badIp) { ShowError($"Remote address: {badIp}."); return false; }
                if (_ips.Count == 0 && pending.Length == 0)
                {
                    var inbound = (CboDirection.SelectedItem as ComboBoxItem)?.Content?.ToString() == "In";
                    ShowError($"Add at least one address, or switch the limit off for any {(inbound ? "source" : "destination")}.");
                    return false;
                }
                if (pending.Length > 0)
                {
                    foreach (var entry in SplitEntries(pending))
                        if (!_ips.Contains(entry)) _ips.Add(entry);
                    RefreshIPTags();
                    TxtNewIP.Text = _ipPrefill;
                }
            }

            var local = TxtLocalAddress.Text.Trim();
            if (local.Length > 0 && BadScope(local, "leave it empty for every address") is { } badLocal)
            { ShowError($"Local address: {badLocal}."); return false; }

            // The program and service go into the rule as written; a character no Windows path
            // or service name holds would make a rule that never matches, and | would split it.
            if (BadProgram(TxtProgram.Text.Trim()) is { } badProgram) { ShowError($"Program: {badProgram}."); return false; }
            if (BadService(SelectedService) is { } badService) { ShowError($"Service: {badService}."); return false; }

            ValidationMsg.Visibility = Visibility.Collapsed;
            return true;
        }

        /// <summary>The path without the one pair of quotes around it, or null when it has none.</summary>
        private static string? Unquoted(string text)
        {
            var t = text.Trim();
            return t.Length >= 2 && t[0] == '"' && t[^1] == '"' && t.IndexOf('"', 1) == t.Length - 1
                ? t[1..^1].Trim()
                : null;
        }

        /// <summary>Null, or what in the path no Windows file name can hold.</summary>
        private static string? BadProgram(string path)
        {
            // A rule matches a program by its full path; a bare or relative name never matches.
            if (path.Length > 0 && !path.Equals("System", StringComparison.OrdinalIgnoreCase) &&
                !ProgramTrust.IsFullPath(Environment.ExpandEnvironmentVariables(path)))
                return @"give the full path (e.g. %SystemRoot%\system32\svchost.exe); a bare name never matches";
            foreach (var c in path)
            {
                if (char.IsControl(c)) return $"a control character (U+{(int)c:X4}) can't be in a path";
                if (c is '"' or '<' or '>' or '|' or '*' or '?') return $"{c} can't be in a Windows path";
            }
            return null;
        }

        /// <summary>Null, or what in the service name no Windows service name can hold.</summary>
        private static string? BadService(string name)
        {
            foreach (var c in name)
            {
                if (char.IsControl(c)) return $"a control character (U+{(int)c:X4}) can't be in a service name";
                if (c is '|' or '/' or '\\') return $"{c} can't be in a service name";
            }
            return null;
        }

        private const string AnyRemote = "switch the address limit off for every address";

        private static List<string> SplitEntries(string text) =>
            text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        /// <summary>
        /// Every comma-separated entry is an IPv4 address, range or subnet Windows loads; null,
        /// or why not. Format only: what an entry covers is the user's call.
        /// </summary>
        private static string? BadScope(string text, string everyAddress)
        {
            foreach (var raw in text.Split(','))
            {
                var entry = raw.Trim();
                if (entry.Length == 0) return "an empty entry between commas";
                if (entry.EndsWith('.')) return $"type the last number of \"{entry}\" first";
                if (Ipv4Scope.Parse(entry, out var error) == null)
                    return error != null && error.Contains(entry) ? error : $"\"{entry}\": {error}";
                if (Ipv4Scope.IsSlashZero(entry)) return $"Windows rejects /0; {everyAddress}";
            }
            return null;
        }

        // ── Session guard ────────────────────────────────────────────────────
        // The editor runs the guard itself, under its own overlay, so every caller (Edit, Allow…
        // extending a rule) gets it, and its questions sit on top of this window.

        private bool _guarding;

        private async Task<bool> RuleChangeAllowed(string regKey, string val)
        {
            MergeOffOutcome outcome;
            _guarding = true;
            try
            {
                outcome = await MergeOffGuard.RuleRemovalAsync(this, Busy, LockContent,
                    new RuleRemoval(new[] { regKey }, new Dictionary<string, string?> { [regKey] = val }));
            }
            finally { _guarding = false; }
            if (outcome.CallerMergesOff) return true;
            if (outcome.Error || outcome.Result == MergeOffResult.Refused) ShowError(outcome.Message);
            else
            {
                ValidationMsg.Visibility = Visibility.Collapsed;
                EditStatus.Text = outcome.Message;
                EditStatus.Ref(TextBlock.ForegroundProperty, "Brush.TextMuted");
            }
            return false;
        }

        // The overlay stops the mouse, not the keyboard: the form is switched off under it, and
        // each unlock puts back the state and focus its lock found.
        private readonly Stack<(bool Enabled, IInputElement? Focus)> _locks = new();

        private void LockContent(bool locked)
        {
            if (locked)
            {
                _locks.Push((Form.IsEnabled, FocusManager.GetFocusedElement(this)));
                Form.IsEnabled = false;
                return;
            }
            if (_locks.Count == 0) return;
            var (enabled, focus) = _locks.Pop();
            Form.IsEnabled = enabled;
            if (IsActive && focus is UIElement { IsEnabled: true, IsVisible: true } f) f.Focus();
        }

        private void ShowError(string msg)
        {
            ValidationMsg.Text       = msg;
            ValidationMsg.Visibility = Visibility.Visible;
            if (_openingNote == null || EditStatus.Text != _openingNote) EditStatus.Text = "";
        }

        private void SetStatus(string msg)
        {
            EditStatus.Text       = msg;
            EditStatus.Ref(TextBlock.ForegroundProperty, "Brush.OkText");
            ValidationMsg.Visibility = Visibility.Collapsed;
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e) => Close();

        // Source tag, same as the rule list: GPO-Manual is imposed from outside (accent + lock).
        private void ShowSource(string source)
        {
            var imposed = source == "GPO-Manual";
            SourceBadge.Styled(imposed ? "Hue.Tag.Accent" : "Hue.Tag");
            SourceLock.Visibility = imposed ? Visibility.Visible : Visibility.Collapsed;
            SourceBadge.ToolTip = imposed ? "Managed in Group Policy, not by this app" : null;
        }
    }
}
