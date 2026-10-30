using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;

using HueThemeKit;

namespace FirewallManager
{
    /// <summary>
    /// Setup: one recipe per thing you set up on purpose (Remote Desktop, file sharing, time,
    /// browsers, a few internet services). Each writes one GPO-Script rule per machine or
    /// program, after showing in one sentence what it will allow. Everything a program tries
    /// on its own is handled from the Connection Log instead (Live, Talkers, Allow…).
    ///
    /// Rules are named SERVICE-LAST (RDP-51, SMB-22-IN): the service, the machine's last
    /// number, "-IN" for incoming. When local merge is on for a profile, Create asks once per
    /// window whether to turn it off: Windows' local rules would count alongside these.
    /// </summary>
    public partial class SetupWindow : Window
    {
        private sealed record Recipe(
            string Key, string Title, string Subtitle, string Icon, bool Inbound, string Text);

        private static Recipe[] AllRecipes(int rdpInPort, bool rdpPortRead) => new Recipe[]
        {
            new("rdp-out", "Remote Desktop to a machine", "out · TCP 3389 or another · mstsc.exe", "Icon.Rdp", false,
                "Lets this PC's Remote Desktop client (mstsc.exe) connect to one machine. TCP only: the client tries UDP first and then falls back, so you'll see those UDP attempts as blocked in the log — harmless. The port is 3389 unless that machine was set to another one."),
            new("rdp-in", "Remote Desktop from a machine", $"in · TCP {rdpInPort} · Remote Desktop service", "Icon.Rdp", true,
                $"Lets one machine connect to this PC by Remote Desktop, and only to the Remote Desktop service, on TCP {rdpInPort}: {(rdpPortRead ? "the port this machine's Remote Desktop is set to" : "assumed, as the port setting couldn't be read")}. Remote Desktop itself has to be on for the rule to be of use."),
            new("smb-out", "File server", "out · TCP 445 · Windows (System)", "Icon.Smb", false,
                "Lets this PC reach one file server's shares. Windows' file-sharing client runs in the System process, so that's the program the rule is for. By address (\\\\192.168.7.17), no names."),
            new("smb-in", "This PC is the file server", "in · TCP 445 · one rule per machine", "Icon.Smb", true,
                "Lets one machine reach this PC's shares. Add one rule per machine that needs access; each needs a fixed address (set on the machine or reserved on the router). No fixed address: make that rule by hand."),
            new("ntp", "Time sync",
                NtpRule.CanBind ? "out · UDP 123 · Windows Time service" : "out · UDP 123 · any program", "Icon.Clock", false,
                "Lets time requests out to one time server — your gateway, or another (e.g. a VM running a time server). " +
                (NtpRule.CanBind
                    ? "Only for the Windows Time service (svchost.exe, W32Time), the one that sets the clock. "
                    : NtpRule.UnboundNote + " ") +
                "Only the rule: which server Windows asks is set in Windows, not here."),
            new("browsers", "Browsers", "out · TCP 80 and 443 · per browser", "Icon.Https", false,
                "Found browsers are listed; tick the ones to allow. Each gets its own rule, tied to its program: web (80) and secure web (443), nothing else. Custom… for a portable or unusual one."),
            new("claude", "Claude", "out · TCP 443 · Anthropic's addresses", "Icon.Out", false,
                "Lets any program reach Claude (claude.ai and api.anthropic.com) on 443, by address. Choose one: Anthropic's published range, or one of the addresses claude.ai and api.anthropic.com have now. Those are looked up when you open this."),
            new("github", "GitHub", "out · TCP 443 · GitHub's ranges", "Icon.Out", false,
                "Lets any program reach GitHub on 443, by GitHub's published address ranges (built-in; config.json if chosen in Setup)."),
            new("nuget", "NuGet", "out · TCP 443 · api.nuget.org", "Icon.Out", false,
                "Lets any program reach the NuGet package feed on 443. The addresses are looked up when you open this, and the rule uses what was found."),
        };

        // Anthropic's published fixed range; the date says how old this knowledge is.
        private const string ClaudeRange       = "160.79.104.0/23";
        private const string ClaudeRangeOrigin = "as published by Anthropic (platform.claude.com/docs/en/api/ip-addresses), looked up 2026-10-08";

        private readonly Recipe[] _recipes;
        private readonly int _rdpInPort;   // read once, so the tile and the rule say the same port
        private readonly bool _rdpPortRead; // false: 3389 assumed
        private Recipe? _recipe;
        private int _opened;               // counts openings: a lookup answers only the opening that asked
        private bool _lookupPending;
        private string? _claudeChoice;     // the range or one looked-up address; null until chosen
        private LocalNet.Info? _net;
        private bool _nameEdited;          // the user typed a name: stop suggesting one
        private bool _settingName;         // the app is filling the name box
        private List<string> _fixed = new(); // addresses for the internet-service recipes
        private bool? _mergeOff;           // the answer to the local-merge question, asked once per window
        private readonly ObservableCollection<BrowserChoice> _browsers = new();
        private bool _creating;            // a Create is running: a second one would race it
        private bool _failsafeRunning;     // from saving the state until Keep or the put-back has ended
        private bool _closed;              // a Create still waiting must not open dialogs on a closed window
        private readonly Dictionary<UIElement, bool> _inputLocked = new();

        public SetupWindow()
        {
            InitializeComponent();
            HueTitleBar.Attach(this);
            ScreenFit.Cap(this);
            Loaded += (_, _) => ConfigService.ReconcileOnSetup(this);   // asks once if config.json changed
            // Closed mid-failsafe, the window couldn't own the countdown or say how it ended.
            Closing += (_, e) => { if (_failsafeRunning) e.Cancel = true; };
            Closed  += (_, _) => _closed = true;

            _rdpPortRead = Lockdown.TryRdpPort(out _rdpInPort);
            _recipes   = AllRecipes(_rdpInPort, _rdpPortRead);
            foreach (var tile in Tiles)
                if (_recipes.FirstOrDefault(x => x.Key == (string)tile.Tag) is { } recipe) tile.Content = TileContent(recipe);

            _net = LocalNet.Primary();
            NetInfo.Text = _net == null
                ? "No network with a gateway found: type full addresses."
                : $"This network: {_net.Prefix}x/{_net.PrefixLength} ({_net.Adapter}) · gateway {_net.Gateway}. Addresses are pre-filled with it; type the last number, or clear it and type any address.";
            BrowserList.ItemsSource = _browsers;

            // Names, addresses and ports take plain characters.
            TxtRuleName.ToolTip = TextHygiene.NameRule;
            InputHygiene.ForName(TxtRuleName, NameNote);
            InputHygiene.ForPlain(TxtAddress, AddressNote);
            InputHygiene.ForPlain(TxtPort, PortNote);
        }

        // A browser's name box comes from the list's template: its note is the panel below it.
        private void BrowserName_Loaded(object sender, RoutedEventArgs e)
        {
            if (sender is not TextBox box || box.Tag is InputHygiene) return;
            if (box.Parent is not Grid row || row.Children.OfType<StackPanel>().FirstOrDefault() is not { } note) return;
            box.ToolTip = $"Rule name. {TextHygiene.NameRule}";
            box.Tag = InputHygiene.ForName(box, note);
        }

        private IEnumerable<ToggleButton> Tiles => TilePanel.Children.OfType<ToggleButton>();

        // ── Tiles ──────────────────────────────────────────────────────────────

        private static UIElement TileContent(Recipe r)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            var box = new Grid { Width = 28, Height = 28, Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center };
            var path = new System.Windows.Shapes.Path { Width = 20, Height = 20, Stretch = Stretch.Uniform, StrokeThickness = 1.6 }
                .Styled("Hue.Icon");
            path.SetResourceReference(System.Windows.Shapes.Path.DataProperty, r.Icon);
            box.Children.Add(path);
            row.Children.Add(box);

            var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            text.Children.Add(new TextBlock { Text = r.Title, FontWeight = FontWeights.SemiBold, FontSize = 14 });
            text.Children.Add(new TextBlock { Text = r.Subtitle, FontSize = 11, Margin = new Thickness(0, 2, 0, 0) }
                .Ref(TextBlock.ForegroundProperty, "Brush.TextDim"));
            row.Children.Add(text);
            return row;
        }

        private void Tile_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleButton clicked) return;
            foreach (var t in Tiles) t.IsChecked = t == clicked;       // one open at a time
            Open(_recipes.First(r => r.Key == (string)clicked.Tag));
        }

        // ── Opening a recipe ───────────────────────────────────────────────────

        private void Open(Recipe r)
        {
            _recipe = r;
            _opened++;
            PickHint.Visibility    = Visibility.Collapsed;
            RecipePanel.Visibility = Visibility.Visible;
            RecipeTitle.Text = r.Title;
            RecipeText.Text  = r.Text;
            SetStatus("");

            var address  = r.Key is "rdp-out" or "rdp-in" or "smb-out" or "smb-in" or "ntp";
            var browsers = r.Key == "browsers";
            var fixedSet = r.Key is "claude" or "github" or "nuget";

            AddressPanel.Visibility = address  ? Visibility.Visible : Visibility.Collapsed;
            NamePanel.Visibility    = browsers ? Visibility.Collapsed : Visibility.Visible;
            BrowserPanel.Visibility = browsers ? Visibility.Visible : Visibility.Collapsed;
            FixedPanel.Visibility   = fixedSet ? Visibility.Visible : Visibility.Collapsed;
            RdpState.Visibility     = r.Key == "rdp-in" ? Visibility.Visible : Visibility.Collapsed;
            PortPanel.Visibility    = r.Key is "rdp-out" or "rdp-in" ? Visibility.Visible : Visibility.Collapsed;
            BtnCreate.Content       = browsers ? "Create rules" : "Create rule";

            if (r.Key == "rdp-out")
            {
                TxtPort.Visibility   = Visibility.Visible;
                PortValue.Visibility = Visibility.Collapsed;
                TxtPort.Text  = "3389";
                PortHint.Text = "Remote Desktop's usual port; type the machine's own if it was set to another";
            }
            else if (r.Key == "rdp-in")
            {
                TxtPort.Visibility   = Visibility.Collapsed;
                PortValue.Visibility = Visibility.Visible;
                PortValue.Text = _rdpPortRead ? $"TCP {_rdpInPort}, this machine's setting" : $"TCP {_rdpInPort}";
                PortHint.Text  = RdpPortNotes(Lockdown.RdpListeningPorts());
            }

            _nameEdited = false;
            if (address)
            {
                AddressLabel.Text = r.Inbound ? "From" : "To";
                TxtAddress.Text = r.Key == "ntp" && _net != null ? _net.Gateway : _net?.Prefix ?? "";
                AddressHint.Text = r.Key == "ntp" ? "your gateway; change it for another time server" : "the machine's address";
                TxtAddress.Focus();
                TxtAddress.CaretIndex = TxtAddress.Text.Length;
            }
            if (r.Key == "rdp-in") ShowRdpState();
            if (browsers) LoadBrowsers();
            if (fixedSet) LoadFixed(r.Key);
            Refresh();
        }

        // Everything that follows the inputs: the suggested name, the sentence, the notices.
        private void Refresh()
        {
            if (_recipe == null) return;
            // The suggested name first: the rules below are made from the name box as it then reads.
            if (!_nameEdited && NamePanel.Visibility == Visibility.Visible)
                SetName(SuggestedName());
            var specs = Specs(out var problem);

            if (problem != null)
            {
                PreviewText.Text = problem;
                PreviewText.ToolTip = null;
                ExistingNote.Visibility = Visibility.Collapsed;
                BtnCreate.IsEnabled = false;
                return;
            }

            PreviewText.Text = string.Join("\n", specs.Select(s => $"{s.Name}: {RuleWriter.Describe(s)}"));
            PreviewText.ToolTip = Ipv4Scope.Describe(string.Join(",", specs.SelectMany(s => s.Remote))) is { Length: > 0 } spans ? spans : null;
            var existing = specs.Select(s => (Spec: s, Same: RuleWriter.FindEquivalent(s), Taken: RuleWriter.KeyExists(s.Name)))
                                .Where(x => x.Same != null || x.Taken).ToList();
            ExistingNote.Visibility = existing.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            ExistingText.Text = string.Join("\n", existing.Select(x =>
                x.Same is { On: true } active ? $"{x.Spec.Name}: a rule doing the same already exists ({active.Name})."
                : x.Same is { } switchedOff    ? $"{x.Spec.Name}: {switchedOff.Name} does the same but is switched off."
                                               : $"{x.Spec.Name}: a rule with this name already exists; creating replaces it."));
            // A running Create keeps it greyed, whatever is typed meanwhile.
            BtnCreate.IsEnabled = specs.Count > 0 && !_creating;
        }

        private string SuggestedName()
        {
            var last = LocalNet.IsAddress(TxtAddress.Text) ? LocalNet.LastOctet(TxtAddress.Text) : "x";
            return _recipe!.Key switch
            {
                "rdp-out" => $"RDP-{last}",
                "rdp-in"  => $"RDP-{last}-IN",
                "smb-out" => $"SMB-{last}",
                "smb-in"  => $"SMB-{last}-IN",
                "ntp"     => $"NTP-{last}",
                "claude"  => "Claude",
                "github"  => "GitHub",
                "nuget"   => "NuGet",
                _         => "",
            };
        }

        private void SetName(string name)
        {
            _settingName = true;
            TxtRuleName.Text = name;
            _settingName = false;
        }

        private void Address_TextChanged(object s, TextChangedEventArgs e) => Refresh();

        private void Port_TextChanged(object s, TextChangedEventArgs e) => Refresh();

        private void RuleName_TextChanged(object s, TextChangedEventArgs e)
        {
            if (!_settingName) _nameEdited = true;
            Refresh();
        }

        // The rules the current inputs make, or why they can't be made yet.
        private List<RuleWriter.Spec> Specs(out string? problem)
        {
            problem = null;
            var r = _recipe!;
            var name = TxtRuleName.Text.Trim();
            var addr = TxtAddress.Text.Trim();
            var list = new List<RuleWriter.Spec>();

            if (r.Key is "rdp-out" or "rdp-in" or "smb-out" or "smb-in" or "ntp")
            {
                if (!LocalNet.IsAddress(addr)) { problem = "Type the machine's address (four numbers, e.g. 192.168.7.51)."; return list; }
                var outPorts = Array.Empty<string>();
                if (r.Key == "rdp-out")
                {
                    var portText = TxtPort.Text.Trim();
                    if (portText.Length == 0) { problem = "Type the port the machine's Remote Desktop listens on."; return list; }
                    if (Ipv4Scope.BadPorts(portText) is { } bad) { problem = $"Port: {bad}."; return list; }
                    outPorts = portText.Split(',').Select(p => p.Trim()).ToArray();
                }
                if (name.Length == 0) { problem = "Give the rule a name."; return list; }
                if (TextHygiene.BadName(name) is { } badName) { problem = badName; return list; }
                var one = new[] { addr };
                list.Add(r.Key switch
                {
                    "rdp-out" => new RuleWriter.Spec(name, false, RuleWriter.Tcp, outPorts, one,
                                     System.IO.Path.Combine(Environment.SystemDirectory, "mstsc.exe")),
                    "rdp-in"  => new RuleWriter.Spec(name, true,  RuleWriter.Tcp, new[] { _rdpInPort.ToString() }, one,
                                     System.IO.Path.Combine(Environment.SystemDirectory, "svchost.exe"), "TermService"),
                    "smb-out" => new RuleWriter.Spec(name, false, RuleWriter.Tcp, new[] { "445" }, one, "System"),
                    "smb-in"  => new RuleWriter.Spec(name, true,  RuleWriter.Tcp, new[] { "445" }, one, "System"),
                    // Time sync: for W32Time only, where it can be tied to (see NtpRule).
                    _         => NtpRule.CanBind
                                     ? new RuleWriter.Spec(name, false, RuleWriter.Udp, new[] { NtpRule.Port }, one,
                                           System.IO.Path.Combine(Environment.SystemDirectory, "svchost.exe"), NtpRule.Service)
                                     : new RuleWriter.Spec(name, false, RuleWriter.Udp, new[] { NtpRule.Port }, one),
                });
                return list;
            }

            if (r.Key == "browsers")
            {
                var picked = _browsers.Where(b => b.Selected).ToList();
                if (picked.Count == 0) { problem = "Tick the browsers to allow."; return list; }
                if (picked.Any(b => b.Name.Trim().Length == 0)) { problem = "Every ticked browser needs a rule name."; return list; }
                if (picked.FirstOrDefault(b => TextHygiene.BadName(b.Name.Trim()) != null) is { } misnamed)
                { problem = $"{misnamed.Name.Trim()}: {TextHygiene.BadName(misnamed.Name.Trim())}"; return list; }
                // Names that differ only in case are one registry value (registry names ignore
                // case): the second would replace the first.
                if (picked.GroupBy(b => RuleWriter.KeyFor(b.Name.Trim()), StringComparer.OrdinalIgnoreCase)
                          .FirstOrDefault(g => g.Count() > 1) is { } same)
                {
                    problem = $"{string.Join(" and ", same.Select(b => $"\"{b.Name.Trim()}\""))} would be one rule: give each ticked browser its own name.";
                    return list;
                }
                list.AddRange(picked.Select(b => new RuleWriter.Spec(
                    b.Name.Trim(), false, RuleWriter.Tcp, new[] { "80", "443" }, Array.Empty<string>(), b.Path)));
                return list;
            }

            // Internet services: by address, any program.
            if (r.Key == "claude")
            {
                if (_claudeChoice == null)
                {
                    problem = _lookupPending
                        ? "Choose Anthropic's published range, or wait for the lookup and choose one of its addresses."
                        : "Choose Anthropic's published range or one of the looked-up addresses.";
                    return list;
                }
                if (name.Length == 0) { problem = "Give the rule a name."; return list; }
                if (TextHygiene.BadName(name) is { } badName) { problem = badName; return list; }
                list.Add(new RuleWriter.Spec(name, false, RuleWriter.Tcp, new[] { "443" }, new[] { _claudeChoice }));
                return list;
            }
            if (_lookupPending) { problem = "Looking up the addresses…"; return list; }
            if (_fixed.Count == 0)
            {
                problem = r.Key == "github"
                    ? "No GitHub ranges in the configuration."
                    : "No address could be looked up (the reasons are above), so there is no rule to make.";
                return list;
            }
            if (name.Length == 0) { problem = "Give the rule a name."; return list; }
            if (TextHygiene.BadName(name) is { } badFixedName) { problem = badFixedName; return list; }
            list.Add(new RuleWriter.Spec(name, false, RuleWriter.Tcp, new[] { "443" }, _fixed));
            return list;
        }

        // ── Remote Desktop (incoming) ──────────────────────────────────────────

        private void ShowRdpState()
        {
            var state = RemoteDesktop.Current();
            BtnEnableRdp.Visibility = state == RemoteDesktop.State.Off ? Visibility.Visible : Visibility.Collapsed;
            (RdpStateTitle.Text, RdpStateText.Text) = state switch
            {
                RemoteDesktop.State.On          => ("Remote Desktop is on", "This PC accepts Remote Desktop; the rule decides from which machine."),
                RemoteDesktop.State.OnByPolicy  => ("Remote Desktop is on (by policy)", "A Group Policy keeps it on; the rule decides from which machine."),
                RemoteDesktop.State.OffByPolicy => ("Remote Desktop is off (by policy)", "A Group Policy keeps it off, so the rule would have nothing to let through. Change that policy first."),
                RemoteDesktop.State.NotAvailable=> ("Remote Desktop isn't available", "This edition of Windows can connect out, but can't accept Remote Desktop connections."),
                _                               => ("Remote Desktop is off", "The rule alone won't let anyone in. Turning it on keeps Network Level Authentication required: nobody gets a sign-in screen without valid credentials first."),
            };
            RdpState.Styled(state is RemoteDesktop.State.On or RemoteDesktop.State.OnByPolicy ? "Hue.Callout.Ok" : "Hue.Callout.Warn");
        }

        // What the port line can't show by itself: an assumed port, or a service still on an old one.
        private string RdpPortNotes(List<int>? listening)
        {
            var notes = new List<string>();
            if (!_rdpPortRead) notes.Add("RDP port couldn't be read; 3389 assumed.");
            if (listening is { Count: > 0 } && !listening.Contains(_rdpInPort))
                notes.Add(_rdpPortRead
                    ? $"Remote Desktop is set to {_rdpInPort} but still listens on {Ports(listening)} until its service restarts."
                    : $"Remote Desktop listens on {Ports(listening)}.");
            return string.Join(" ", notes);
        }

        private void BtnEnableRdp_Click(object s, RoutedEventArgs e)
        {
            if (!HueConfirm.Ask(this, "Turn on Remote Desktop?",
                    "This PC will accept Remote Desktop connections, with Network Level Authentication " +
                    "required. The firewall still decides from which machines: only those with an RDP-…-IN rule.",
                    "Turn on"))
                return;
            var problem = RemoteDesktop.Enable();
            SetStatus(problem == null ? "Remote Desktop is on." : $"Couldn't turn on Remote Desktop: {problem}", error: problem != null);
            ShowRdpState();
        }

        // ── Browsers ───────────────────────────────────────────────────────────

        public sealed class BrowserChoice : INotifyPropertyChanged
        {
            private bool _selected;
            private string _name = "";
            public string Path { get; init; } = "";
            public bool Selected { get => _selected; set { _selected = value; Changed(nameof(Selected)); } }
            public string Name   { get => _name;     set { _name = value;     Changed(nameof(Name)); } }
            public event PropertyChangedEventHandler? PropertyChanged;
            private void Changed(string p) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
        }

        // Where the three majors install themselves, per machine and per user.
        private static IEnumerable<(string Name, string Path)> KnownBrowsers()
        {
            var pf    = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var pf86  = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return new (string, string)[]
            {
                ("Firefox",         System.IO.Path.Combine(pf,   @"Mozilla Firefox\firefox.exe")),
                ("Firefox",         System.IO.Path.Combine(pf86, @"Mozilla Firefox\firefox.exe")),
                ("Firefox-Dev",     System.IO.Path.Combine(pf,   @"Firefox Developer Edition\firefox.exe")),
                ("Firefox-Nightly", System.IO.Path.Combine(pf,   @"Firefox Nightly\firefox.exe")),
                ("Firefox",         System.IO.Path.Combine(local, @"Mozilla Firefox\firefox.exe")),
                ("Chrome",          System.IO.Path.Combine(pf,   @"Google\Chrome\Application\chrome.exe")),
                ("Chrome",          System.IO.Path.Combine(pf86, @"Google\Chrome\Application\chrome.exe")),
                ("Chrome",          System.IO.Path.Combine(local, @"Google\Chrome\Application\chrome.exe")),
                ("Edge",            System.IO.Path.Combine(pf86, @"Microsoft\Edge\Application\msedge.exe")),
                ("Edge",            System.IO.Path.Combine(pf,   @"Microsoft\Edge\Application\msedge.exe")),
            };
        }

        private void LoadBrowsers()
        {
            // Keep custom entries and ticks across re-opening; add what's installed, unticked.
            foreach (var (name, path) in KnownBrowsers())
                if (File.Exists(path) && !_browsers.Any(b => b.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
                    Add(name, path);
            NoBrowsers.Visibility = _browsers.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void Add(string name, string path, bool selected = false)
        {
            // Two found under the same name (e.g. Firefox per machine and per user): keep them apart.
            var unique = name;
            for (var n = 2; _browsers.Any(b => b.Name.Equals(unique, StringComparison.OrdinalIgnoreCase)); n++) unique = $"{name}-{n}";
            var b = new BrowserChoice { Path = path, Name = unique, Selected = selected };
            b.PropertyChanged += (_, _) => Refresh();
            _browsers.Add(b);
        }

        private void Browser_Changed(object s, RoutedEventArgs e) => Refresh();

        // A name the app makes from a file name, in the characters a rule name takes: _ is a
        // space (as in the registry name), others take their first plain alternative, and one
        // with none is left out. The user sees the result in the box and can change it.
        private static string PlainName(string text)
        {
            var name = new System.Text.StringBuilder(text.Length);
            foreach (var r in text.EnumerateRunes())
            {
                if (r.Value == '_') name.Append(' ');
                else if (TextHygiene.IsNameChar(r.Value)) name.Append(r.ToString());
                else if (TextHygiene.Alternatives(r).FirstOrDefault(a => a.EnumerateRunes().All(x => TextHygiene.IsNameChar(x.Value))) is { } plain)
                    name.Append(plain);
            }
            return string.Join(' ', name.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries));
        }

        private void BtnCustomBrowser_Click(object s, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title  = "Pick the browser's program",
                Filter = "Programs (*.exe)|*.exe",
            };
            if (dlg.ShowDialog(this) != true) return;
            if (_browsers.FirstOrDefault(b => b.Path.Equals(dlg.FileName, StringComparison.OrdinalIgnoreCase)) is { } known)
            {
                known.Selected = true;
                return;
            }
            // A portable Firefox sits in e.g. …\FirefoxPortable\App\Firefox64\firefox.exe: name it by its folder.
            var folder = new DirectoryInfo(System.IO.Path.GetDirectoryName(dlg.FileName) ?? "").Name;
            var exe    = System.IO.Path.GetFileNameWithoutExtension(dlg.FileName);
            Add(PlainName(folder.Length > 0 ? $"{exe}-{folder}" : exe), dlg.FileName, selected: true);
            NoBrowsers.Visibility = Visibility.Collapsed;
        }

        // ── Internet services ──────────────────────────────────────────────────

        private async void LoadFixed(string key)
        {
            var opened = _opened;
            _fixed = new();
            _lookupPending = false;
            _claudeChoice  = null;
            LookupNote.Visibility   = Visibility.Collapsed;
            AddressesRow.Visibility = key == "claude" ? Visibility.Collapsed : Visibility.Visible;
            ClaudePanel.Visibility  = key == "claude" ? Visibility.Visible : Visibility.Collapsed;
            DriftNote.Visibility = key is "github" or "nuget" ? Visibility.Visible : Visibility.Collapsed;
            DriftText.Text = key == "github"
                ? "GitHub's address ranges change now and then. When GitHub stops working, the Connection Log shows its connections as blocked: then update the ranges in config.json and create the rule again."
                : "NuGet's addresses change now and then. When restores stop working, the Connection Log shows the blocked connections: then open this again, which looks them up afresh, and create the rule again.";

            if (key == "github")
            {
                var svc = ConfigService.Effective().Services
                    .FirstOrDefault(s => s.Name.Equals("GitHub", StringComparison.OrdinalIgnoreCase));
                _fixed = svc?.Cidrs.ToList() ?? new();
            }
            else
            {
                var hosts = key == "claude" ? new[] { "claude.ai", "api.anthropic.com" } : new[] { "api.nuget.org" };
                if (key == "claude")
                {
                    RbClaudeRange.IsChecked = false;
                    ClaudeRangeText.Text    = ClaudeRange;
                    ClaudeRangeSource.Text  = ClaudeRangeOrigin;
                    var span = Ipv4Scope.Describe(ClaudeRange);
                    RbClaudeRange.ToolTip   = span.Length > 0 ? span : null;
                    ClaudeLookupList.Children.Clear();
                    ClaudeLookupHead.Text   = $"Or one address {string.Join(" or ", hosts)} has now: looking up…";
                }
                else FixedAddresses.Text = "looking up…";
                _lookupPending = true;

                var found = await Task.Run(() => Resolve(hosts));
                if (opened != _opened) return;                         // its tile is no longer the open one

                _lookupPending = false;
                _fixed = found.Addresses.Select(a => a.Address).ToList();
                if (found.Failures.Count > 0)
                {
                    LookupNote.Visibility = Visibility.Visible;
                    LookupText.Text = (key == "nuget" && _fixed.Count > 0 ? "Couldn't look up, so missing from the rule:\n" : "Couldn't look up:\n")
                                    + string.Join("\n", found.Failures);
                }
                if (key == "claude")
                {
                    ClaudeLookupHead.Text = _fixed.Count > 0
                        ? $"Or one address {string.Join(" or ", hosts)} has now:"
                        : $"Or one address {string.Join(" or ", hosts)} has now: none found.";
                    foreach (var (address, names) in found.Addresses)
                    {
                        var rb = new RadioButton
                        {
                            GroupName = RbClaudeRange.GroupName,
                            Tag       = address,
                            Content   = $"{address}   ({string.Join(", ", names)})",
                            Margin    = new Thickness(0, 0, 0, 4),
                        };
                        rb.Checked += ClaudeChoice_Checked;
                        ClaudeLookupList.Children.Add(rb);
                    }
                    Refresh();
                    return;
                }
            }
            FixedAddresses.Text = _fixed.Count > 0 ? string.Join(", ", _fixed) : "none found";
            FixedAddresses.ToolTip = Ipv4Scope.Describe(string.Join(",", _fixed)) is { Length: > 0 } spans ? spans : null;
            Refresh();
        }

        private void ClaudeChoice_Checked(object s, RoutedEventArgs e)
        {
            if (s is not RadioButton rb) return;
            _claudeChoice = rb == RbClaudeRange ? ClaudeRange : rb.Tag as string;
            Refresh();
        }

        private sealed record Lookup(List<(string Address, List<string> Hosts)> Addresses, List<string> Failures);

        // Every IPv4 address found, with the names that gave it; every name that failed, with Windows' reason.
        private static Lookup Resolve(IEnumerable<string> hosts)
        {
            var found    = new List<(string Address, List<string> Hosts)>();
            var failures = new List<string>();
            foreach (var host in hosts)
            {
                try
                {
                    var v4 = System.Net.Dns.GetHostAddresses(host)
                        .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                        .Select(a => a.ToString()).Distinct().ToList();
                    if (v4.Count == 0) { failures.Add($"{host}: the answer had no IPv4 address"); continue; }
                    foreach (var ip in v4)
                    {
                        var i = found.FindIndex(f => f.Address == ip);
                        if (i >= 0) found[i].Hosts.Add(host);
                        else found.Add((ip, new List<string> { host }));
                    }
                }
                catch (Exception ex) { failures.Add($"{host}: {ex.Message}"); }
            }
            return new Lookup(found, failures);
        }

        // ── Create ─────────────────────────────────────────────────────────────

        // A Remote Desktop rule made over Remote Desktop runs like Lock down's failsafe: the user
        // proves a new connection works, or the saved state comes back (this window after
        // KeepSeconds, the scheduled task after BackstopSeconds if the app is gone).
        private const int KeepSeconds = 180, BackstopSeconds = 360;
        // While the rule is written, applied and checked, the task must not fire before the
        // countdown even starts.
        private const int BackstopWhileApplying = 900;

        // One Create at a time: a second one during the first one's waits would write over it,
        // and with the failsafe its saved state would be the first one's result.
        private async void BtnCreate_Click(object s, RoutedEventArgs e)
        {
            if (_recipe == null || _creating) return;
            _creating = true;
            BtnCreate.IsEnabled = false;
            try { await CreateAsync(_recipe); }
            finally
            {
                _creating = false;
                if (!_closed) Refresh();
            }
        }

        // The tile being applied is passed in: another one may be open by the time it ends.
        private async Task CreateAsync(Recipe applied)
        {
            var specs = Specs(out var problem);
            if (problem != null || specs.Count == 0) return;

            // Ranges from config.json: never write impossible values into a rule.
            if (applied.Key == "github")
            {
                ConfigService.Reload();
                var impossible = ConfigService.ImpossibleValues();
                if (impossible.Count > 0)
                {
                    new ConsentWindow(impossible) { Owner = this }.ShowDialog();
                    SetStatus("Not created: config.json has impossible values. Fix them first.", error: true);
                    return;
                }
            }

            // Same name: replacing is a choice. Same rule under another name: say so, then allow.
            foreach (var spec in specs)
            {
                if (RuleWriter.KeyExists(spec.Name) &&
                    !ThemedDialog.Confirm(this, "Replace the rule?",
                        $"A rule named {spec.Name} already exists. Replace it with this one?", "Replace", danger: true))
                    return;
                // One that is switched off isn't the same: no question, it is just created.
                if (RuleWriter.FindEquivalent(spec) is { On: true } same &&
                    !same.Name.Equals(spec.Name, StringComparison.OrdinalIgnoreCase) &&
                    !ThemedDialog.Confirm(this, "It already exists",
                        $"{same.Name} already allows the same. Create {spec.Name} as well?", "Create anyway"))
                    return;
            }

            // A replaced rule of the app may be what lets this Remote Desktop session in: the
            // guard judges that before anything is written, the failsafe path included.
            var replaced = specs.Where(x => RuleWriter.KeyExists(x.Name))
                                .GroupBy(x => RuleWriter.KeyFor(x.Name), StringComparer.OrdinalIgnoreCase)
                                .ToDictionary(g => g.Key, g => (string?)RuleWriter.Value(g.Last()), StringComparer.OrdinalIgnoreCase);
            if (replaced.Count > 0)
            {
                MergeOffOutcome check;
                _failsafeRunning = true;
                try { check = await MergeOffGuard.RuleRemovalAsync(this, Busy, LockInput, new RuleRemoval(replaced.Keys.ToList(), replaced)); }
                finally { _failsafeRunning = false; }
                if (_closed) return;
                if (!check.CallerMergesOff)
                {
                    // The answer to the merge question stands only for a Create that goes ahead.
                    _mergeOff = null;
                    if (check.Result == MergeOffResult.Cancelled) SetStatus("");
                    else
                    {
                        SetStatus($"Not created. {check.Message}", error: true);
                        SetupStatus.ToolTip = check.Detail;
                    }
                    Refresh();
                    return;
                }
            }

            // Local merge: asked once per window, before anything is written. Closing the
            // question cancels the Create.
            var mergeOn = RuleWriter.ProfilesWithMergeOn();
            if (mergeOn.Count > 0 && _mergeOff == null)
            {
                var answer = ThemedDialog.TwoWay(this, "Local merge is on",
                    $"Local merge is on for {JoinWords(mergeOn)}: Windows' local rules ({LocalRules.Count()}) count " +
                    "alongside yours. Turn it off on all profiles?",
                    "Turn off", "Leave on");
                if (answer == null) return;
                _mergeOff = answer;
            }
            var turnOff = mergeOn.Count > 0 && _mergeOff == true;

            // The Remote Desktop rule can cut only the operator's own session: at the console it is
            // just written, whoever else is connected. Over Remote Desktop, a connected client gets
            // the failsafe; unreadable connections can't rule one out.
            RdpSession? session = null;
            if (applied.Key == "rdp-in" && Lockdown.IsRemoteSession())
            {
                SetStatus("Reading the Remote Desktop connections…");
                var setting = _rdpInPort;
                session = await Task.Run(() => ReadRdpSession(setting));
                if (_closed) return;
                if (session.Clients == null)
                {
                    _mergeOff = null;
                    SetStatus("Not created: the machine's connections could not be read, so a Remote Desktop session can't be ruled out.", error: true);
                    Refresh();
                    return;
                }
            }
            var failsafe = session?.Clients is { Count: > 0 };

            // Merge off can cut a Remote Desktop session that only Windows' own rule lets in. With
            // the Remote Desktop rule's failsafe, that covers the merge off; otherwise the guard
            // judges from the facts.
            var kept = "";
            var keptError = false;
            if (turnOff && !failsafe)
            {
                MergeOffOutcome guard;
                _failsafeRunning = true;
                try { guard = await MergeOffGuard.RunAsync(this, Busy, LockInput, RuleWriter.MergeOffAllProfiles); }
                finally { _failsafeRunning = false; }
                if (_closed) return;
                switch (guard.Result)
                {
                    case MergeOffResult.Cancelled:
                        // The answer to the merge question stands only for a Create that goes ahead.
                        _mergeOff = null;
                        SetStatus("");
                        Refresh();
                        return;
                    case MergeOffResult.Refused:
                    case MergeOffResult.PutBack:
                        SetStatus($"Not created. {guard.Message}", error: guard.Error);
                        SetupStatus.ToolTip = guard.Detail;
                        Refresh();
                        return;
                    case MergeOffResult.Kept:
                        // Merge is off and applied already; the rules below are written and applied on their own.
                        turnOff = false;
                        kept = guard.Message + " ";
                        keptError = guard.Error;
                        break;
                }
            }

            if (failsafe)
            {
                await CreateWithFailsafeAsync(applied, specs, turnOff, session!.Clients!, session);
                return;
            }

            SetStatus("Creating…");
            // Each rule stands on its own: one that can't be written doesn't stop the others, and
            // the ones written stay and are applied.
            var created = new List<RuleWriter.Spec>();
            var failed  = new List<string>();
            foreach (var spec in specs)
            {
                try { RuleWriter.Write(spec); created.Add(spec); }
                catch (Exception ex) { failed.Add($"{spec.Name} ({ex.Message.TrimEnd('.')})"); }
            }
            var notCreated = failed.Count > 0 ? $" Not created: {string.Join(", ", failed)}." : "";
            if (created.Count == 0)
            {
                // Nothing written, so merge isn't touched either.
                var left = turnOff ? "; local merge left as it was" : "";
                SetStatus($"{kept}{notCreated.TrimStart().TrimEnd('.')}{left}.", error: true);
                Refresh();
                return;
            }

            var names = string.Join(", ", created.Select(x => x.Name));
            var merge = "";
            try
            {
                var mergeFailed = false;
                if (turnOff)
                {
                    try { RuleWriter.MergeOffAllProfiles(); merge = "; local merge turned off"; }
                    catch (Exception ex) { merge = $"; local merge not turned off: {ex.Message.TrimEnd('.')}"; mergeFailed = true; }
                }
                SetStatus($"Created {names}{merge}.{notCreated} Applying (gpupdate)…", error: failed.Count > 0, tone: Tone.Applying);
                var check = await PolicyApply.RunAsync($"Created {names}", created.Select(x => RuleWriter.KeyFor(x.Name)));
                var summary = merge.Length > 0 ? $"{check.Summary.TrimEnd().TrimEnd('.')}{merge}." : check.Summary;
                SetStatus(kept + summary + notCreated + RdpOffHint(applied), error: check.IsProblem || mergeFailed || failed.Count > 0 || keptError,
                          tone: check.InForce ? Tone.InForce : Tone.Normal);
                SetupStatus.ToolTip = check.Detail;    // after SetStatus, which clears it
            }
            catch (Exception ex)
            {
                SetStatus($"{kept}Created {names}{merge}.{notCreated} Couldn't apply: {ex.Message}", error: true);
            }
            Refresh();
        }

        // Only for the tile that was applied, and only while it is still the open one: under
        // another tile the hint would read as that tile's. Read once the rule is in.
        private string RdpOffHint(Recipe applied) =>
            applied.Key == "rdp-in" && ReferenceEquals(_recipe, applied) && RemoteDesktop.Current() == RemoteDesktop.State.Off
                ? " Remote Desktop itself is still off." : "";

        // Who is connected over Remote Desktop, on the ports the service listens on now (else
        // the setting). Clients null: the connection table couldn't be read.
        private sealed record RdpSession(List<string>? Clients, List<int> OnPorts, List<int>? Listening);

        private static RdpSession ReadRdpSession(int setting)
        {
            var listening = Lockdown.RdpListeningPorts();
            var ports     = listening is { Count: > 0 } ? listening : new List<int> { setting };
            var clients   = new List<string>();
            var onPorts   = new List<int>();
            foreach (var port in ports)
            {
                if (Lockdown.RdpClients(port) is not { } found) return new RdpSession(null, onPorts, listening);
                if (found.Count > 0) onPorts.Add(port);
                clients.AddRange(found);
            }
            return new RdpSession(clients.Distinct().ToList(), onPorts, listening);
        }

        private async Task CreateWithFailsafeAsync(Recipe applied, List<RuleWriter.Spec> specs, bool turnOff,
                                                   List<string> clients, RdpSession session)
        {
            // The restore needs the firewall's own export and import; without netsh there is none.
            // The answer to the merge question stands only for a Create that goes ahead.
            if (WindowsTools.NotFound(WindowsTools.Tool.Netsh, "the firewall state can't be saved and put back, so nothing was changed") is { } noNetsh)
            {
                _mergeOff = null;
                SetStatus($"Not created: {noNetsh}.", error: true);
                Refresh();
                return;
            }
            // The failsafe is a scheduled task; without schtasks it can't be armed or found.
            if (WindowsTools.NotFound(WindowsTools.Tool.Schtasks, "the failsafe task can't be armed, so nothing was changed") is { } noSchtasks)
            {
                _mergeOff = null;
                SetStatus($"Not created: {noSchtasks}.", error: true);
                Refresh();
                return;
            }

            // Arming replaces a task of the same name: one still armed (an earlier lock-down or
            // rule whose put-back is still pending) would lose its saved state without a word. One
            // that may be there (no clear answer) is refused the same way.
            if (await Task.Run(Lockdown.BackstopState) is var there && there != false)
            {
                if (_closed) return;
                _mergeOff = null;
                StillArmed(unsure: there == null);
                Refresh();
                return;
            }
            if (_closed) return;

            var from = string.Join(", ", clients);
            var listening = session.Listening is { Count: > 0 } l && !l.Contains(_rdpInPort) ? l : null;
            var allows = _rdpPortRead
                ? $"This rule allows {_rdpInPort}, the port in the setting"
                : $"This rule allows {_rdpInPort}, assumed: the port setting couldn't be read";
            var still = listening == null ? "."
                : _rdpPortRead ? $"; the service keeps listening on {Ports(listening)} until it restarts."
                               : $"; the service listens on {Ports(listening)}.";
            var msg = $"You are connected over Remote Desktop from {from} on port {Ports(session.OnPorts)}. {allows}{still} " +
                      (turnOff ? "Local merge is turned off with it. " : "") +
                      "A wrong rule cuts this session off.\n\n" +
                      $"The current state is saved first. Then you reconnect within {KeepSeconds} s and click Keep, " +
                      "or the firewall is put back as it was.";
            if (!ThemedDialog.Confirm(this, "Connected over Remote Desktop", msg, "Apply with failsafe", danger: true))
            {
                _mergeOff = null;
                SetStatus("");
                Refresh();
                return;
            }

            _failsafeRunning = true;
            LockInput(true);
            try { await FailsafeAsync(applied, specs, turnOff, from); }
            finally
            {
                LockInput(false);
                _failsafeRunning = false;
                Refresh();
            }
        }

        // Lock down's order: save, arm the task, write, apply and check, then the countdown.
        // The work runs on the overlay's worker and touches no control; what it found is drawn
        // once the overlay is down.
        private async Task FailsafeAsync(Recipe applied, List<RuleWriter.Spec> specs, bool turnOff, string from)
        {
            SetStatus("Creating…");
            var backstopAt = DateTime.Now.AddSeconds(BackstopWhileApplying);
            string? snapshot = null, notCreatedAtAll = null, failedPartWay = null;
            var armedBefore = false;
            var armedUnsure = false;
            string? valuesAfter = null;   // the merge values as written, when merge goes off with the rule
            var created = new List<RuleWriter.Spec>();
            var failed  = new List<string>();
            var written = new Dictionary<string, string?>();   // name → the rule as written
            var merge = "";
            var mergeFailed = false;
            var disarmed = false;
            PolicyApply.Result? check = null;
            Lockdown.PutBackResult? undo = null;

            await Busy.RunAsync<object?>("Creating the Remote Desktop rule", async report =>
            {
                // Checked again right before anything is written: the dialog may have stood open a while.
                if (Lockdown.BackstopState() is var state && state != false) { armedBefore = true; armedUnsure = state == null; return null; }

                report.Say("Saving the current state…");
                try { snapshot = Lockdown.Snapshot("before-rdp-rule").Reg; }
                catch (Exception ex) { notCreatedAtAll = $"Not created: the current state could not be saved ({ex.Message.TrimEnd('.')})."; return null; }

                report.Say("Arming the failsafe…");
                try { Lockdown.ArmBackstop(snapshot, backstopAt); }
                catch (Exception ex)
                {
                    // A creation that timed out may have left the task anyway: it would put the
                    // saved state back over whatever is done meanwhile.
                    notCreatedAtAll = $"Not created: {ex.Message.TrimEnd('.')}." +
                                      (Lockdown.DisarmBackstop() ? "" :
                                       $" The failsafe task may exist anyway and could not be confirmed removed: if \"{Lockdown.BackstopTask}\" " +
                                       $"is in Task Scheduler, delete it, or it puts the saved state back at {backstopAt:HH:mm:ss}.");
                    return null;
                }

                try
                {
                    report.Say("Writing the rule…");
                    foreach (var spec in specs)
                    {
                        try { RuleWriter.Write(spec); }
                        catch (Exception ex) { failed.Add($"{spec.Name} ({ex.Message.TrimEnd('.')})"); continue; }
                        created.Add(spec);
                    }
                    if (created.Count == 0)
                    {
                        // Nothing written, so nothing to put back: only the task goes.
                        disarmed = Lockdown.DisarmBackstop();
                        return null;
                    }
                    if (turnOff)
                    {
                        try { RuleWriter.MergeOffAllProfiles(); merge = "; local merge turned off"; }
                        catch (Exception ex) { merge = $"; local merge not turned off: {ex.Message.TrimEnd('.')}"; mergeFailed = true; }
                    }
                    report.Say("Applying the policy (gpupdate) and checking that the firewall applies it…");
                    check = await PolicyApply.RunAsync($"Created {string.Join(", ", created.Select(x => x.Name))}",
                                                       created.Select(x => RuleWriter.KeyFor(x.Name)));
                    // Read once gpupdate is done (a GPO may rewrite merge there): if they change
                    // before Keep, the task fired.
                    foreach (var spec in created) written[spec.Name] = RuleValue(spec.Name);
                    if (turnOff) valuesAfter = MergeValues();
                }
                catch (Exception ex)
                {
                    // Anything unforeseen once writing began: the saved state goes back in the same run.
                    failedPartWay = $"Not created: failed part way ({ex.Message.TrimEnd('.')})";
                    undo = await Lockdown.PutBackAsync(snapshot, failedPartWay, backstopArmed: true, t => report.Say(t));
                }
                return null;
            });

            if (armedBefore) { _mergeOff = null; StillArmed(armedUnsure); return; }
            if (notCreatedAtAll != null) { SetStatus(notCreatedAtAll, error: true); return; }
            if (failedPartWay != null) { ShowPutBack(undo!, snapshot!, failedPartWay); return; }

            var notCreated = failed.Count > 0 ? $" Not created: {string.Join(", ", failed)}." : "";
            if (created.Count == 0)
            {
                var left = turnOff ? "; local merge left as it was" : "";
                var task = disarmed ? "" :
                    $" The failsafe task could not be confirmed removed: if \"{Lockdown.BackstopTask}\" is in Task Scheduler, delete it, or it puts the saved state back at {backstopAt:HH:mm:ss}.";
                SetStatus($"{notCreated.TrimStart().TrimEnd('.')}{left}.{task}", error: true);
                return;
            }

            var names = string.Join(", ", created.Select(x => x.Name));
            // From here the rule is live with the task armed: whatever goes wrong, the saved state
            // goes back, never an exception that leaves the rule in place.
            var armed = true;
            string why;
            try
            {
                var inForce = check!;
                var summary = (merge.Length > 0 ? $"{inForce.Summary.TrimEnd().TrimEnd('.')}{merge}." : inForce.Summary) +
                              notCreated + RdpOffHint(applied);
                var isProblem = inForce.IsProblem || mergeFailed || failed.Count > 0;
                SetStatus(summary, error: isProblem, tone: inForce.InForce ? Tone.InForce : Tone.Normal);
                SetupStatus.ToolTip = inForce.Detail;

                var ours = created.Select(x => RuleWriter.KeyFor(x.Name)["CUSTOM_".Length..]).ToList();
                var refused = inForce.Rejected?.Where(r => ours.Contains(r, StringComparer.OrdinalIgnoreCase)).ToList() ?? new List<string>();
                if (refused.Count > 0)
                    // A rule Windows didn't load lets nobody in: nothing to test, nothing to keep.
                    why = $"{names} not kept: Windows refused " +
                          (refused.Count < created.Count ? JoinWords(refused) : created.Count == 1 ? "it" : "them");
                else
                {
                    // The countdown starts now, so the task moves to now as well. If moving fails,
                    // it stays armed at its first time.
                    var moved = DateTime.Now.AddSeconds(BackstopSeconds);
                    try { await Task.Run(() => Lockdown.ArmBackstop(snapshot!, moved)); backstopAt = moved; }
                    catch { }

                    var win = new LockdownCountdownWindow(this,
                        $"You are connected over Remote Desktop from {from}. The rule is in place.\n\n" +
                        (inForce.InForce
                            ? "Disconnect and reconnect now. If the new connection works, click Keep."
                            : $"{inForce.Summary}\n\n" +
                              (inForce.Problem != null ? "Whether the firewall applies it couldn't be checked" : "The firewall doesn't apply all of it yet") +
                              ", so a reconnect now may not test the rule."),
                        KeepSeconds, backstopAt, heading: "Keep the rule?", closing: null);
                    win.ShowDialog();

                    if (win.Kept)
                    {
                        var task = await Task.Run(Lockdown.RemoveBackstop);
                        var gone = task == false;
                        armed = !gone;
                        string? problem = null;
                        if (written.Any(w => RuleValue(w.Key) != w.Value) || (valuesAfter != null && MergeValues() != valuesAfter))
                            problem = "Keep came too late: the failsafe had already put the firewall back as it was.";
                        else if (task == null)
                            problem = $"{names} kept, but whether the failsafe task is gone couldn't be told (Task Scheduler gave no clear answer). " +
                                      $"If \"{Lockdown.BackstopTask}\" is in Task Scheduler, delete it, or it will put the old firewall back.";
                        else if (!gone)
                            problem = $"{names} kept, but the failsafe task could not be removed. Delete \"{Lockdown.BackstopTask}\" in Task Scheduler, or it will put the old firewall back.";

                        if (problem == null)
                        {
                            SetStatus($"{summary} Kept; the failsafe task is removed.", error: isProblem,
                                      tone: inForce.InForce ? Tone.InForce : Tone.Normal);
                            SetupStatus.ToolTip = inForce.Detail;
                        }
                        else
                        {
                            // The status line is the next action's to overwrite; this one must be seen.
                            SetStatus(problem, error: true);
                            ThemedDialog.Info(this, "Remote Desktop rule", problem, danger: true);
                        }
                        return;
                    }
                    why = $"{names} not kept";
                }
            }
            catch (Exception ex)
            {
                why = $"{names} not kept: failed part way ({ex.Message.TrimEnd('.')})";
            }

            Lockdown.PutBackResult? back = null;
            await Busy.RunAsync<object?>("Putting the firewall back", async report =>
            {
                back = await Lockdown.PutBackAsync(snapshot!, why, backstopArmed: armed, t => report.Say(t));
                return null;
            });
            ShowPutBack(back!, snapshot!, why);
        }

        private void StillArmed(bool unsure)
        {
            var text = unsure
                ? $"Not created: whether the failsafe task \"{Lockdown.BackstopTask}\" is still armed from an earlier lock-down or rule " +
                  "can't be told (Task Scheduler gave no clear answer), so Setup won't replace it. Nothing was written."
                : $"Not created: the failsafe task \"{Lockdown.BackstopTask}\" is still armed from an earlier lock-down or rule, " +
                  "so Setup won't replace it. Nothing was written.";
            SetStatus(text, error: true);
            ThemedDialog.Info(this, "Failsafe task still armed", text, danger: true);
        }

        // The rule as it stands in the policy store: after Keep, a different one means the
        // failsafe task already put the old state back.
        private static string? RuleValue(string name)
        {
            using var key = Registry.LocalMachine.OpenSubKey(RuleWriter.RegGPO);
            return key?.GetValue(RuleWriter.KeyFor(name)) as string;
        }

        // The three profiles' merge values as they stand, for the same purpose: the only policy
        // values the failsafe path writes besides the rule (as RuleWriter.MergeOffAllProfiles does).
        private static string MergeValues()
        {
            using var root = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\WindowsFirewall");
            return string.Join(",", new[] { "Domain", "Private", "Public" }.SelectMany(p =>
            {
                using var k = root?.OpenSubKey($"{p}Profile");
                return new[] { "AllowLocalPolicyMerge", "AllowLocalIPsecPolicyMerge" }
                    .Select(v => k?.GetValue(v)?.ToString() ?? "-").ToList();
            }));
        }

        private void ShowPutBack(Lockdown.PutBackResult u, string snapshot, string why)
        {
            var (text, error, detail) = Lockdown.PutBackText(u, snapshot, why);
            // Without a problem the old state is back and in force.
            SetStatus(text, error, tone: u.Check is { InForce: true } ? Tone.InForce : Tone.Normal);
            SetupStatus.ToolTip = detail;    // after SetStatus, which clears it
        }

        // While the failsafe runs, the window's content takes no input, keyboard included; the
        // overlay only covers it. Each part gets back the state it had.
        private void LockInput(bool locked)
        {
            if (locked)
            {
                foreach (var child in SetupRoot.Children.OfType<UIElement>().Where(c => !ReferenceEquals(c, Busy)))
                {
                    _inputLocked[child] = child.IsEnabled;
                    child.IsEnabled = false;
                }
                return;
            }
            foreach (var (child, wasEnabled) in _inputLocked) child.IsEnabled = wasEnabled;
            _inputLocked.Clear();
        }

        // "3389", "3389 and 3390"
        private static string Ports(IEnumerable<int> ports) => JoinWords(ports.Select(p => p.ToString()).ToList());

        // "a, b and c"
        private static string JoinWords(IReadOnlyList<string> parts) =>
            parts.Count <= 1 ? string.Join("", parts) : $"{string.Join(", ", parts.Take(parts.Count - 1))} and {parts[^1]}";

        // ── Footer ─────────────────────────────────────────────────────────────

        private void BtnExportJson_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Title      = "Export config.json template",
                Filter     = "JSON config (*.json)|*.json",
                FileName   = "config.json",
                DefaultExt = ".json"
            };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                AppConfig.WriteTemplate(dlg.FileName);
                SetStatus($"Template written → {System.IO.Path.GetFileName(dlg.FileName)}. Put it next to the exe to use it.");
            }
            catch (Exception ex) { SetStatus($"Export error: {ex.Message}", error: true); }
        }

        // The status line's text colour, chosen where the message is made: amber while a change is
        // being applied, green once it is in force; an error stays red whatever the tone.
        private enum Tone { Normal, Applying, InForce }

        private void SetStatus(string msg, bool error = false, Tone tone = Tone.Normal)
        {
            SetupStatus.Text = msg;
            SetupStatus.ToolTip = null;
            SetupStatus.Ref(TextBlock.ForegroundProperty,
                error ? "Brush.ErrorText" : tone switch
                {
                    Tone.Applying => "Brush.WarnText",
                    Tone.InForce  => "Brush.OkText",
                    _             => "Brush.TextDim",
                });
            // An error sits on a pale error tint until the next message, as in the main window.
            if (error) SetupStatusFrame.Ref(Border.BackgroundProperty, "Brush.ErrorSoft");
            else       SetupStatusFrame.ClearValue(Border.BackgroundProperty);
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();
    }
}
