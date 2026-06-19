using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace FirewallManager
{
    public partial class MainWindow : Window
    {
        private const string RegGPO        = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";
        private const string RegLocal      = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        private const string RegGPOProfiles= @"SOFTWARE\Policies\Microsoft\WindowsFirewall";

        private ObservableCollection<FirewallRule>  _allRules = new();
        private ObservableCollection<FirewallRule>  _filtered = new();
        private ObservableCollection<ProfileStatus> _profiles = new();
        private bool _isAdmin;

        public MainWindow()
        {
            InitializeComponent();
            _isAdmin = IsRunningAsAdmin();
            if (!_isAdmin) AdminWarning.Visibility = Visibility.Visible;
            ProfilePanel.ItemsSource = _profiles;
            LoadRules();
            SizeChanged += (_, __) => ScheduleBottomLayout();
            Loaded     += (_, __) => ScheduleBottomLayout();
        }

        // ── Tight-space layout ────────────────────────────────────────────────
        //  Trigger is based on ACTUAL CONTENT OVERFLOW, not window width: when the
        //  bottom panel can't fit status + controls side by side, switch to tabs.
        //  (Window width is the wrong measure — chrome/margins mean the window is
        //  wider than the point where the panel content stops fitting.)
        //
        //  We cache the combined desired width of both halves while roomy, then
        //  compare the panel's available width against it:
        //    available < need + 12  → tabs (flip just before they'd clip)
        //    available > need + 60  → back to dual (hysteresis buffer, no flutter)
        private bool _tabMode;
        private bool _showStatusTab;
        private bool _layoutQueued;
        private bool _applyingLayout;
        private double _bothHalvesNeed;                // cached combined desired width (roomy)
        private const double EnterMargin = 12;
        private const double LeaveBuffer = 60;

        private void ScheduleBottomLayout()
        {
            if (_layoutQueued) return;
            _layoutQueued = true;
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, new System.Action(() =>
            {
                _layoutQueued = false;
                ApplyBottomLayout();
            }));
        }

        private void ApplyBottomLayout()
        {
            if (GpoHalf == null || ControlsHalf == null || BottomTabs == null || BottomPanel == null) return;
            if (_applyingLayout) return;
            _applyingLayout = true;
            try
            {
                double available = BottomPanel.ActualWidth;

                // While both halves are showing, (re)cache how much they need together.
                if (!_tabMode)
                {
                    GpoHalf.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                    ControlsHalf.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                    var need = GpoHalf.DesiredSize.Width + ControlsHalf.DesiredSize.Width;
                    if (need > 0) _bothHalvesNeed = need;
                }

                // Hysteresis on content overflow.
                if (!_tabMode && available > 0 && available < _bothHalvesNeed + EnterMargin) _tabMode = true;
                else if (_tabMode && available > _bothHalvesNeed + LeaveBuffer)              _tabMode = false;

                if (!_tabMode)
                {
                    GpoHalf.Visibility      = Visibility.Visible;
                    ControlsHalf.Visibility = Visibility.Visible;
                    GpoCol.Width            = new GridLength(1, GridUnitType.Star);
                    BottomTabs.Visibility   = Visibility.Collapsed;
                    StatusBar.Visibility    = Visibility.Visible;
                }
                else
                {
                    BottomTabs.Visibility = Visibility.Visible;
                    StatusBar.Visibility  = Visibility.Collapsed;
                    if (_showStatusTab)
                    {
                        GpoHalf.Visibility      = Visibility.Visible;
                        ControlsHalf.Visibility = Visibility.Collapsed;
                        GpoCol.Width            = new GridLength(1, GridUnitType.Star);
                    }
                    else
                    {
                        GpoHalf.Visibility      = Visibility.Collapsed;
                        ControlsHalf.Visibility = Visibility.Visible;
                        GpoCol.Width            = new GridLength(0);
                    }
                    TabStatus.IsChecked   = _showStatusTab;
                    TabControls.IsChecked = !_showStatusTab;
                }
            }
            finally { _applyingLayout = false; }
        }

        private void TabStatus_Checked(object sender, RoutedEventArgs e)
        {
            if (!_tabMode) return;
            _showStatusTab = true;
            ApplyBottomLayout();
        }

        private void TabControls_Checked(object sender, RoutedEventArgs e)
        {
            if (!_tabMode) return;
            _showStatusTab = false;
            ApplyBottomLayout();
        }

        // ── Models ───────────────────────────────────────────────────────────

        public class FirewallRule : INotifyPropertyChanged
        {
            public string RegistryKey   { get; set; } = "";
            public string RegistryPath  { get; set; } = "";
            public string Name          { get; set; } = "";
            // Display-only: strip the redundant CUSTOM prefix. Raw Name/RegistryKey keep it.
            public string NameDisplay
            {
                get
                {
                    var n = Name;
                    if (n.StartsWith("CUSTOM ", StringComparison.Ordinal))
                        return n["CUSTOM ".Length..];
                    if (n.StartsWith("CUSTOM_", StringComparison.Ordinal))
                        return n["CUSTOM_".Length..].Replace('_', ' ');
                    return n;
                }
            }
            public string Direction     { get; set; } = "";
            public string Action        { get; set; } = "";
            public string Protocol      { get; set; } = "";
            public string Ports         { get; set; } = "";
            public string RemoteAddress { get; set; } = "";
            public string Program       { get; set; } = "";  // full path
            public string ProgramDisplay => string.IsNullOrEmpty(Program) ? "" : System.IO.Path.GetFileName(Program);
            public string Active        { get; set; } = "";
            public string Source        { get; set; } = "";
            public string RawValue      { get; set; } = "";

            public bool  ActiveBool => Active == "TRUE";

            public Brush StateDot => Action == "Block"
                ? (ActiveBool ? new SolidColorBrush(Color.FromRgb(0xf8,0x71,0x71))
                              : new SolidColorBrush(Color.FromRgb(0x37,0x41,0x51)))
                : (ActiveBool ? new SolidColorBrush(Color.FromRgb(0x34,0xd3,0x99))
                              : new SolidColorBrush(Color.FromRgb(0x37,0x41,0x51)));

            public Brush SourceBadgeBrush => Source switch
            {
                "GPO-Script" => new SolidColorBrush(Color.FromRgb(0x1d,0x4e,0xd8)),
                "GPO-Manual" => new SolidColorBrush(Color.FromRgb(0x6d,0x28,0xd9)),
                "Local"      => new SolidColorBrush(Color.FromRgb(0x05,0x7a,0x55)),
                _            => new SolidColorBrush(Color.FromRgb(0x37,0x41,0x51))
            };

            // Direction as a glyph: ⬆ Out (to the sky), ⬇ In (to the ground) — heavy block arrows
            public string DirGlyph => Direction switch
            {
                "Out" => "⬆",
                "In"  => "⬇",
                _     => Direction
            };

            // Colour: red if it Blocks (either way); else green Out / orange In
            public Brush DirBrush => Action == "Block"
                ? new SolidColorBrush(Color.FromRgb(0xf8,0x71,0x71))   // red — block
                : Direction == "In"
                    ? new SolidColorBrush(Color.FromRgb(0xfb,0x92,0x3c))   // orange — in
                    : new SolidColorBrush(Color.FromRgb(0x34,0xd3,0x99)); // green — out

            public event PropertyChangedEventHandler? PropertyChanged;
            public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(""));
        }

        public enum Safety { Safe, Unsafe, Unset }

        // One editable firewall setting (an iOS-style toggle). Color & knob position
        // track SAFETY, not the raw DWORD: green/right = safe, red/left = unsafe,
        // amber/center = unset (registry has no value). So an all-green tile = a
        // fully hardened profile at a glance.
        public class ProfileToggle : INotifyPropertyChanged
        {
            public string Label     { get; set; } = "";
            public string RegValue  { get; set; } = "";   // EnableFirewall, etc.
            public int    SafeDword { get; set; }          // the DWORD that means "safe"
            public string SafeWord  { get; set; } = "";    // e.g. "ON" / "Block" / "No"
            public string UnsafeWord{ get; set; } = "";    // e.g. "OFF" / "Allow" / "Yes"
            public System.Collections.Generic.List<string> RegKeys { get; set; } = new(); // target subkeys

            private Safety _state;
            public Safety State
            {
                get => _state;
                set { _state = value;
                      OnChanged(nameof(State)); OnChanged(nameof(PillBrush));
                      OnChanged(nameof(KnobAlign)); OnChanged(nameof(ValueText)); }
            }

            public Brush PillBrush => _state switch
            {
                Safety.Safe   => new SolidColorBrush(Color.FromRgb(0x34,0xd3,0x99)),
                Safety.Unsafe => new SolidColorBrush(Color.FromRgb(0xf8,0x71,0x71)),
                _             => new SolidColorBrush(Color.FromRgb(0xfb,0xbf,0x24)),
            };
            public HorizontalAlignment KnobAlign => _state switch
            {
                Safety.Safe   => HorizontalAlignment.Right,
                Safety.Unsafe => HorizontalAlignment.Left,
                _             => HorizontalAlignment.Center,
            };
            public string ValueText => _state switch
            {
                Safety.Safe   => SafeWord,
                Safety.Unsafe => UnsafeWord,
                _             => "—",
            };

            public event PropertyChangedEventHandler? PropertyChanged;
            private void OnChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
        }

        public class ProfileStatus
        {
            public string ProfileName { get; set; } = "";
            public System.Collections.Generic.List<ProfileToggle> Toggles { get; set; } = new();
        }

        // ── Loading ──────────────────────────────────────────────────────────

        private void LoadRules()
        {
            _allRules.Clear();
            LoadFromRegistry(RegGPO,   isGPO: true);
            LoadFromRegistry(RegLocal, isGPO: false);
            LoadProfileStatus();
            ApplyFilter();
            RefreshQuickButtons();
            RefreshPurgeButton();
            RefreshDnsClientButton();
            SetStatus($"Loaded {_allRules.Count} rules  —  " +
                      $"{_allRules.Count(r => r.Source == "GPO-Script")} GPO-Script  " +
                      $"{_allRules.Count(r => r.Source == "GPO-Manual")} GPO-Manual  " +
                      $"{_allRules.Count(r => r.Source == "Local")} Local");
        }

        private void LoadFromRegistry(string path, bool isGPO)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
                if (key == null) return;
                foreach (var name in key.GetValueNames())
                {
                    if (name.StartsWith("PS")) continue;
                    var raw = key.GetValue(name)?.ToString() ?? "";
                    _allRules.Add(ParseRule(name, raw, path, isGPO));
                }
            }
            catch (UnauthorizedAccessException)
            {
                SetStatus($"Access denied reading {(isGPO ? "GPO" : "Local")} rules.", error: true);
            }
        }

        private void LoadProfileStatus()
        {
            _profiles.Clear();

            // Three profiles. Private/Public fall back to the legacy StandardProfile
            // Three independent, individually-editable profiles. No fusion: the
            // toggles carry settings, not just status, so collapsing identical tiles
            // would remove the ability to edit a profile on its own (and trap you
            // once they matched). The tab layout already handles tight space.
            var (domain, _) = ReadProfile("Domain",  "DomainProfile");
            var (priv,   _) = ReadProfile("Private", "PrivateProfile", "StandardProfile");
            var (pub,    _) = ReadProfile("Public",  "PublicProfile",  "StandardProfile");
            _profiles.Add(domain);
            _profiles.Add(priv);
            _profiles.Add(pub);
        }

        private (ProfileStatus, string) ReadProfile(string label, params string[] regKeysInPreference)
        {
            string keyUsed = regKeysInPreference[0];   // default target for writes if none exist yet
            int fw = -1, inb = -1, outb = -1, mrg = -1;

            foreach (var regKey in regKeysInPreference)
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey($@"{RegGPOProfiles}\{regKey}");
                    if (k == null) continue;
                    keyUsed = regKey;
                    fw   = ReadDword(k, "EnableFirewall", -1);
                    inb  = ReadDword(k, "DefaultInboundAction", -1);
                    outb = ReadDword(k, "DefaultOutboundAction", -1);
                    mrg  = ReadDword(k, "AllowLocalPolicyMerge", -1);
                    break;
                }
                catch { /* fall through to defaults */ }
            }

            var keys = new System.Collections.Generic.List<string> { keyUsed };
            ProfileToggle Mk(string lbl, string val, int safe, string sw, string uw, int raw) => new()
            {
                Label = lbl, RegValue = val, SafeDword = safe, SafeWord = sw, UnsafeWord = uw,
                RegKeys = keys,
                State = raw == -1 ? Safety.Unset : (raw == safe ? Safety.Safe : Safety.Unsafe)
            };

            var ps = new ProfileStatus
            {
                ProfileName = label,
                Toggles =
                {
                    Mk("Firewall", "EnableFirewall",        1, "ON",    "OFF",   fw),
                    Mk("Inbound",  "DefaultInboundAction",  1, "Block", "Allow", inb),
                    Mk("Outbound", "DefaultOutboundAction", 1, "Block", "Allow", outb),
                    Mk("Merge",    "AllowLocalPolicyMerge", 0, "No",    "Yes",   mrg),
                }
            };
            return (ps, keyUsed);
        }

        // Click on a profile toggle. Flips it; writes the registry DWORD to the
        // toggle's target key (this single profile), then gpupdate. Open-direction
        // flips (toward red/unsafe) require confirmation via an app-styled dialog;
        // locked-direction flips apply directly.
        private void ProfileToggle_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is not FrameworkElement fe || fe.DataContext is not ProfileToggle t) return;

            // Determine the new safety after the flip:
            //   Unset (amber) → Safe (pin the secure value, locked direction)
            //   Safe  (green) → Unsafe (open direction — confirm)
            //   Unsafe(red)   → Safe   (locked direction)
            bool goingUnsafe = t.State == Safety.Safe;
            int newDword = goingUnsafe ? (t.SafeDword == 1 ? 0 : 1) : t.SafeDword;
            var newState = goingUnsafe ? Safety.Unsafe : Safety.Safe;

            if (goingUnsafe)
            {
                var msg = $"This sets {t.Label} to “{t.UnsafeWord}” on " +
                          $"{(t.RegKeys.Count > 1 ? "all profiles" : "this profile")}.\n\n" +
                          $"That moves away from the locked-down default. It writes Group Policy " +
                          $"and runs gpupdate. Continue?";
                if (!ThemedDialog.Confirm(this, "Open a firewall default?", msg, "Set " + t.UnsafeWord, danger: true))
                    return;
            }

            try
            {
                foreach (var subkey in t.RegKeys)
                {
                    using var k = Registry.LocalMachine.CreateSubKey($@"{RegGPOProfiles}\{subkey}");
                    k?.SetValue(t.RegValue, newDword, RegistryValueKind.DWord);
                }
                t.State = newState;
                RunGpupdate();
                SetStatus($"{t.Label} → {t.ValueText} ({t.RegKeys.Count} profile{(t.RegKeys.Count>1?"s":"")}). gpupdate run.");
                LoadProfileStatus();   // re-read; may now fuse or split
            }
            catch (Exception ex)
            {
                SetStatus($"Couldn't write {t.Label}: {ex.Message}", error: true);
            }
        }

        private void RunGpupdate()
        {
            try
            {
                var psi = new ProcessStartInfo("gpupdate", "/force")
                { CreateNoWindow = true, UseShellExecute = false };
                Process.Start(psi);
            }
            catch { /* non-fatal */ }
        }

        private static int ReadDword(RegistryKey? k, string name, int fallback)
            => k?.GetValue(name) is int v ? v : fallback;

        // ── Parsing ──────────────────────────────────────────────────────────

        private static FirewallRule ParseRule(string regKey, string raw, string regPath, bool isGPO)
        {
            var rule = new FirewallRule
            {
                RegistryKey  = regKey,
                RegistryPath = regPath,
                RawValue     = raw,
                Source       = !isGPO ? "Local" : regKey.StartsWith("CUSTOM_") ? "GPO-Script" : "GPO-Manual"
            };

            foreach (var part in raw.Split('|'))
            {
                if (!part.Contains('=')) continue;
                var idx = part.IndexOf('=');
                var k   = part[..idx].Trim().ToUpperInvariant();
                var v   = part[(idx+1)..].Trim();
                switch (k)
                {
                    case "NAME":     rule.Name      = v; break;
                    case "DIR":      rule.Direction = v; break;
                    case "ACTION":   rule.Action    = v; break;
                    case "ACTIVE":   rule.Active    = v.ToUpperInvariant(); break;
                    case "APP":      rule.Program   = v; break; // store full path
                    case "PROTOCOL": rule.Protocol  = v switch{"6"=>"TCP","17"=>"UDP","0"=>"Any","1"=>"ICMP",_=>v}; break;
                    case "RPORT":
                        rule.Ports = string.IsNullOrEmpty(rule.Ports)
                            ? v
                            : rule.Ports + "," + v;
                        break;
                    case "LPORT":    if (string.IsNullOrEmpty(rule.Ports)) rule.Ports = $"In:{v}"; break;
                    case "RA4":      rule.RemoteAddress = string.IsNullOrEmpty(rule.RemoteAddress)
                                         ? v : rule.RemoteAddress + "," + v; break;
                    case "RA6":      if (string.IsNullOrEmpty(rule.RemoteAddress)) rule.RemoteAddress = $"IPv6:{v}"; break;
                }
            }

            if (string.IsNullOrEmpty(rule.Name)) rule.Name = regKey;
            if (string.IsNullOrEmpty(rule.RemoteAddress)) rule.RemoteAddress = "Any";
            return rule;
        }

        // ── Filtering ────────────────────────────────────────────────────────

        private void ApplyFilter()
        {
            if (SearchBox == null || FilterCombo == null) return;
            var search = SearchBox.Text.Trim().ToLowerInvariant();
            var filter = (FilterCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All Rules";

            var result = _allRules.AsEnumerable();
            result = filter switch
            {
                "Enabled Only"    => result.Where(r => r.Active == "TRUE"),
                "Disabled Only"   => result.Where(r => r.Active == "FALSE"),
                "Inbound Only"    => result.Where(r => r.Direction == "In"),
                "Outbound Only"   => result.Where(r => r.Direction == "Out"),
                "Allow Only"      => result.Where(r => r.Action == "Allow"),
                "Block Only"      => result.Where(r => r.Action == "Block"),
                "GPO-Script Only" => result.Where(r => r.Source == "GPO-Script"),
                "GPO-Manual Only" => result.Where(r => r.Source == "GPO-Manual"),
                "Local Only"      => result.Where(r => r.Source == "Local"),
                _                 => result
            };

            if (!string.IsNullOrEmpty(search))
                result = result.Where(r =>
                    r.Name.ToLower().Contains(search)          ||
                    r.RemoteAddress.ToLower().Contains(search) ||
                    r.Program.ToLower().Contains(search)       ||
                    r.Ports.ToLower().Contains(search)         ||
                    r.Source.ToLower().Contains(search));

            _filtered = new ObservableCollection<FirewallRule>(result);
            if (RulesGrid != null) RulesGrid.ItemsSource = _filtered;
            if (CountText != null) CountText.Text = $"{_filtered.Count} / {_allRules.Count} rules";
        }

        // ── Toggle ───────────────────────────────────────────────────────────

        private void ToggleSelected(bool enable)
        {
            if (!_isAdmin)
            {
                MessageBox.Show("Administrator privileges required to modify rules.",
                    "Access Denied", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(rule.RegistryPath, writable: true);
                if (key == null) { SetStatus("Cannot open registry key for writing.", error: true); return; }

                var newVal = rule.RawValue
                    .Replace("Active=TRUE",  "Active=__X__")
                    .Replace("Active=FALSE", "Active=__X__")
                    .Replace("Active=__X__", enable ? "Active=TRUE" : "Active=FALSE")
                    .Replace("v2.30|", "v2.33|")
                    .Replace("v2.31|", "v2.33|")
                    .Replace("v2.32|", "v2.33|");

                key.SetValue(rule.RegistryKey, newVal, RegistryValueKind.String);
                rule.RawValue = newVal;
                rule.Active   = enable ? "TRUE" : "FALSE";
                rule.Refresh();

                Process.Start(new ProcessStartInfo
                {
                    FileName="gpupdate", Arguments="/force",
                    CreateNoWindow=true, UseShellExecute=false, RedirectStandardOutput=true
                });

                SetStatus($"{(enable?"Enabled":"Disabled")}: {rule.Name}");
                ApplyFilter();

                // ApplyFilter() rebuilt the collection. If the toggled rule
                // still passes the active filter, keep its row selected;
                // either way refresh the toggle button to its new state
                // (SelectionChanged won't fire when the row stays selected).
                if (_filtered.Contains(rule))
                    RulesGrid.SelectedItem = rule;
                UpdateToggleButtonState(RulesGrid.SelectedItem as FirewallRule);
            }
            catch (Exception ex) { SetStatus($"Error: {ex.Message}", error: true); }
        }

        // ── Events ───────────────────────────────────────────────────────────

        private void BtnRefresh_Click(object s, RoutedEventArgs e) => LoadRules();

        private void Logo_Click(object sender, MouseButtonEventArgs e)
            => new ConsentWindow(reviewMode: true) { Owner = this }.ShowDialog();

        private void BtnExportRules_Click(object s, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title      = "Export Rule List",
                Filter     = "Text file (*.txt)|*.txt",
                FileName   = $"firewall-rules-{DateTime.Now:yyyyMMdd-HHmm}.txt",
                DefaultExt = ".txt"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"Firewall Rule Manager — Rule Export");
                sb.AppendLine($"Exported : {DateTime.Now:yyyy-MM-dd HH:mm}");
                sb.AppendLine($"Filter   : {(FilterCombo.SelectedItem as ComboBoxItem)?.Content}");
                sb.AppendLine($"Total    : {_filtered.Count} / {_allRules.Count} rules");
                sb.AppendLine();
                sb.AppendLine($"{"St",-4} {"Source",-12} {"Name",-35} {"Dir",-5} {"Action",-7} {"Proto",-6} {"Port(s)",-10} {"Active",-7} {"Remote Address",-40} {"Program"}");
                sb.AppendLine(new string('-', 160));

                foreach (var r in _filtered)
                {
                    sb.AppendLine($"{(r.ActiveBool ? "ON" : "off"),-4} {r.Source,-12} {r.Name,-35} {r.Direction,-5} {r.Action,-7} {r.Protocol,-6} {r.Ports,-10} {r.Active,-7} {r.RemoteAddress,-40} {r.Program}");
                }

                sb.AppendLine();
                sb.AppendLine("--- Raw Registry Values ---");
                foreach (var r in _filtered)
                {
                    sb.AppendLine($"{r.RegistryKey}");
                    sb.AppendLine($"  {r.RawValue}");
                }

                System.IO.File.WriteAllText(dlg.FileName, sb.ToString(), System.Text.Encoding.UTF8);
                SetStatus($"Exported {_filtered.Count} rules → {System.IO.Path.GetFileName(dlg.FileName)}");
            }
            catch (Exception ex) { SetStatus($"Export error: {ex.Message}", error: true); }
        }
        private void BtnSetup_Click  (object s, RoutedEventArgs e)
        {
            var win = new SetupWindow { Owner = this };
            win.ShowDialog();
            LoadRules(); // refresh after setup
        }

        private LogViewerWindow? _logWindow;

        private void BtnLogging_Click(object s, RoutedEventArgs e)
        {
            if (_logWindow == null || !_logWindow.IsVisible)
            {
                _logWindow = new LogViewerWindow();
                // No Owner — independent window
                _logWindow.Show();
            }
            else
            {
                _logWindow.Activate();
            }
        }

        private void SearchBox_TextChanged(object s, TextChangedEventArgs e)      => ApplyFilter();
        private void FilterCombo_SelectionChanged(object s, SelectionChangedEventArgs e) => ApplyFilter();

        private void RulesGrid_SelectionChanged(object s, SelectionChangedEventArgs e)
        {
            var rule      = RulesGrid.SelectedItem as FirewallRule;
            var canEdit   = rule != null && _isAdmin;
            var canDelete = rule != null && _isAdmin && rule.Source != "GPO-Manual";

            BtnEditRule.IsEnabled   = canEdit;
            BtnDeleteRule.IsEnabled = canDelete;

            UpdateToggleButtonState(rule);
        }

        // Recompute the context-sensitive Enable/Disable button from a rule's
        // current state. Called both on selection change AND after a toggle —
        // a toggle keeps the same row selected (so SelectionChanged doesn't
        // re-fire), and the button would otherwise show the pre-toggle state.
        private void UpdateToggleButtonState(FirewallRule? rule)
        {
            var canToggle = rule != null && _isAdmin && rule.Source != "GPO-Manual";
            if (canToggle)
            {
                BtnToggleRule.IsEnabled  = true;
                BtnToggleRule.Content    = rule!.ActiveBool ? "✖ Disable" : "✔ Enable";
                BtnToggleRule.Background = rule.ActiveBool
                    ? new SolidColorBrush(Color.FromRgb(0xb9, 0x1c, 0x1c))
                    : new SolidColorBrush(Color.FromRgb(0x15, 0x80, 0x3d));
            }
            else
            {
                BtnToggleRule.IsEnabled  = false;
                BtnToggleRule.Content    = "Enable";
                BtnToggleRule.Background = new SolidColorBrush(Color.FromRgb(0x37, 0x41, 0x51));
            }
        }

        private void BtnToggleRule_Click(object s, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            ToggleSelected(!rule.ActiveBool);
        }

        // ── Quick toggle buttons ──────────────────────────────────────────────

        private void BtnQuickHTTPS_Click(object s, RoutedEventArgs e) => QuickToggle("CUSTOM_HTTPS_Out",    "HTTPS", "Action=Allow|Dir=Out|Protocol=6|RPort=443", BtnQuickHTTPS);
        private void BtnQuickHTTP_Click (object s, RoutedEventArgs e) => QuickToggle("CUSTOM_HTTP_Out",     "HTTP",  "Action=Allow|Dir=Out|Protocol=6|RPort=80",  BtnQuickHTTP);
        private void BtnQuickDNS_Click  (object s, RoutedEventArgs e) => QuickToggle("CUSTOM_DNS_UDP_Out",  "DNS",   null, BtnQuickDNS);

        private void QuickToggle(string ruleKey, string label, string? defaultFields, Button btn)
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules", writable: true);
                if (key == null) { SetStatus("Cannot open registry.", error: true); return; }

                var existing = key.GetValue(ruleKey)?.ToString();

                if (existing == null)
                {
                    // Rule missing — recreate it
                    if (ruleKey == "CUSTOM_DNS_UDP_Out")
                    {
                        // Try to get DNS IP from NTP rule as gateway hint
                        var ntpRaw = key.GetValue("CUSTOM_NTP_Out")?.ToString() ?? "";
                        var gwIP   = ntpRaw.Split('|')
                            .FirstOrDefault(p => p.StartsWith("RA4=", StringComparison.OrdinalIgnoreCase))
                            ?["RA4=".Length..] ?? "";

                        if (string.IsNullOrEmpty(gwIP))
                        {
                            // Show input dialog using existing InputDialog pattern
                            var dlg = new InputDialog("DNS Server IP", "DNS rule not found.\nEnter your DNS server IP:") { Owner = this };
                            if (dlg.ShowDialog() != true || string.IsNullOrEmpty(dlg.Value)) return;
                            gwIP = dlg.Value.Trim();
                        }

                        defaultFields = $"Action=Allow|Dir=Out|Protocol=17|RPort=53|RA4={gwIP}";
                    }

                    var newVal = $"v2.33|{defaultFields}|Active=TRUE|Name=CUSTOM {label} Out|";
                    key.SetValue(ruleKey, newVal, RegistryValueKind.String);
                    SetStatus($"Recreated and enabled: CUSTOM {label} Out");
                }
                else
                {
                    // Toggle existing
                    var isActive = existing.Contains("Active=TRUE");
                    var newVal   = existing
                        .Replace("Active=TRUE",  "Active=__X__")
                        .Replace("Active=FALSE", "Active=__X__")
                        .Replace("Active=__X__", isActive ? "Active=FALSE" : "Active=TRUE");
                    key.SetValue(ruleKey, newVal, RegistryValueKind.String);
                    SetStatus($"{(isActive ? "Disabled" : "Enabled")}: CUSTOM {label} Out");
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = "gpupdate", Arguments = "/force",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                });

                LoadRules();
                RefreshQuickButtons();
            }
            catch (Exception ex) { SetStatus($"Error: {ex.Message}", error: true); }
        }

        private void RefreshQuickButtons()
        {
            RefreshQuickButton(BtnQuickHTTPS, "CUSTOM_HTTPS_Out",   "🌐 HTTPS");
            RefreshQuickButton(BtnQuickHTTP,  "CUSTOM_HTTP_Out",    "🌐 HTTP");
            RefreshQuickButton(BtnQuickDNS,   "CUSTOM_DNS_UDP_Out", "🔍 DNS");
        }

        private void RefreshQuickButton(Button btn, string ruleKey, string label)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules", writable: false);
                var val = key?.GetValue(ruleKey)?.ToString();

                if (val == null)
                {
                    // Missing
                    btn.Background = new SolidColorBrush(Color.FromRgb(0x37, 0x41, 0x51));
                    btn.Foreground = new SolidColorBrush(Color.FromRgb(0x6b, 0x72, 0x80));
                    btn.Content    = $"{label} ?";
                    btn.ToolTip    = $"{ruleKey} — rule missing, click to recreate";
                }
                else if (val.Contains("Active=TRUE"))
                {
                    btn.Background = new SolidColorBrush(Color.FromRgb(0x05, 0x7a, 0x55));
                    btn.Foreground = new SolidColorBrush(Colors.White);
                    btn.Content    = $"{label} ✓";
                    btn.ToolTip    = $"{ruleKey} — enabled, click to disable";
                }
                else
                {
                    btn.Background = new SolidColorBrush(Color.FromRgb(0x7f, 0x1d, 0x1d));
                    btn.Foreground = new SolidColorBrush(Color.FromRgb(0xfc, 0xa5, 0xa5));
                    btn.Content    = $"{label} ✗";
                    btn.ToolTip    = $"{ruleKey} — disabled, click to enable";
                }
            }
            catch
            {
                btn.Content = $"{label} ?";
            }
        }

        private void RulesGrid_DoubleClick(object s, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (RulesGrid.SelectedItem is FirewallRule) OpenEditDialog();
        }

        // ── Edit / Add / Delete ───────────────────────────────────────────────

        private void BtnAddRule_Click   (object s, RoutedEventArgs e) => OpenAddDialog();
        private void BtnEditRule_Click  (object s, RoutedEventArgs e) => OpenEditDialog();
        private void BtnDeleteRule_Click(object s, RoutedEventArgs e) => DeleteSelected();

        private void OpenEditDialog()
        {
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            RuleEditWindow.OpenEdit(rule, this);
            LoadRules();
        }

        private void OpenAddDialog()
        {
            RuleEditWindow.OpenNew(this);
            LoadRules();
        }

        private void OpenDuplicateDialog()
        {
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            RuleEditWindow.OpenDuplicate(rule, this);
            LoadRules();
        }

        private void DeleteSelected()
        {
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            if (rule.Source == "GPO-Manual") { SetStatus("GPO-Manual rules cannot be deleted here.", error: true); return; }

            var result = MessageBox.Show(
                $"Delete rule '{rule.Name}'?\n\nThis cannot be undone.",
                "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (result != MessageBoxResult.Yes) return;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(rule.RegistryPath, writable: true);
                key?.DeleteValue(rule.RegistryKey, false);

                Process.Start(new ProcessStartInfo
                {
                    FileName = "gpupdate", Arguments = "/force",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                });

                SetStatus($"Deleted: {rule.Name}");
                LoadRules();
            }
            catch (Exception ex) { SetStatus($"Delete error: {ex.Message}", error: true); }
        }

        // ── Purge Local (Windows auto-generated) rules ────────────────────────

        private void RefreshPurgeButton()
        {
            var count = CountLocalRules();
            BtnPurgeLocal.Content   = count > 0 ? $"🧹 Purge Local ({count})" : "🧹 Purge Local";
            BtnPurgeLocal.IsEnabled = _isAdmin && count > 0;
            BtnPurgeLocal.ToolTip   = !_isAdmin
                ? "Administrator required"
                : count == 0
                    ? "No Local rules to purge"
                    : $"Back up and delete all {count} Windows-generated Local rules";
        }

        // Count deletable Local-store rules (excludes PS-prefixed metadata, matching the loader)
        private static int CountLocalRules()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(RegLocal, writable: false);
                if (key == null) return 0;
                return key.GetValueNames().Count(n => !n.StartsWith("PS"));
            }
            catch { return 0; }
        }

        private void BtnPurgeLocal_Click(object s, RoutedEventArgs e)
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }

            try
            {
                // 1. Snapshot everything (incl. PS metadata) for a complete, restorable backup
                Dictionary<string, string> all;
                using (var ro = Registry.LocalMachine.OpenSubKey(RegLocal, writable: false))
                {
                    if (ro == null) { SetStatus("Cannot open Local rules key.", error: true); return; }
                    all = ro.GetValueNames()
                            .ToDictionary(n => n, n => ro.GetValue(n)?.ToString() ?? "");
                }

                var toDelete = all.Keys.Where(n => !n.StartsWith("PS")).ToList();
                if (toDelete.Count == 0) { SetStatus("No Local rules to purge."); return; }

                // 2. Write .reg backup before touching anything
                var backupPath = WriteRegBackup(all);

                // 3. Delete the rule values
                using (var rw = Registry.LocalMachine.OpenSubKey(RegLocal, writable: true))
                {
                    if (rw == null) { SetStatus("Cannot open Local rules key for writing.", error: true); return; }
                    foreach (var name in toDelete) rw.DeleteValue(name, throwOnMissingValue: false);
                }

                // 4. Refresh policy + UI
                Process.Start(new ProcessStartInfo
                {
                    FileName = "gpupdate", Arguments = "/force",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                });

                LoadRules();
                SetStatus($"Purged {toDelete.Count} Local rules.  Backup → {backupPath}");
            }
            catch (Exception ex) { SetStatus($"Purge error: {ex.Message}", error: true); }
        }

        // Writes a regedit-mergeable .reg file. Double-click it in Explorer to restore.
        private static string WriteRegBackup(Dictionary<string, string> values)
        {
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FirewallManager", "Backups");
            System.IO.Directory.CreateDirectory(dir);

            var path = System.IO.Path.Combine(dir, $"local-rules-{DateTime.Now:yyyyMMdd-HHmmss}.reg");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Windows Registry Editor Version 5.00");
            sb.AppendLine();
            sb.AppendLine($@"[HKEY_LOCAL_MACHINE\{RegLocal}]");
            foreach (var kv in values)
                sb.AppendLine($"\"{RegEscape(kv.Key)}\"=\"{RegEscape(kv.Value)}\"");

            // UTF-16 LE w/ BOM + CRLF — what regedit expects for v5.00 files
            System.IO.File.WriteAllText(path, sb.ToString(), System.Text.Encoding.Unicode);
            return path;
        }

        // .reg string escaping: backslash and double-quote must be escaped
        private static string RegEscape(string raw) =>
            raw.Replace(@"\", @"\\").Replace("\"", "\\\"");

        // ── DNS Client (Dnscache) status + scheduled disable ──────────────────

        private const string RegDnscache = @"SYSTEM\CurrentControlSet\Services\Dnscache";

        // Service start type: 2=Automatic, 3=Manual, 4=Disabled
        private static int GetDnscacheStart()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(RegDnscache, writable: false);
                return k?.GetValue("Start") is int v ? v : -1;
            }
            catch { return -1; }
        }

        // Live run-state via `sc query` (no extra package dependency)
        private static bool IsDnscacheRunning()
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "sc", Arguments = "query Dnscache",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                });
                var output = p?.StandardOutput.ReadToEnd() ?? "";
                p?.WaitForExit();
                return output.Contains("RUNNING");
            }
            catch { return false; }
        }

        // Windows build number; 24H2 == 26100. Used to warn that disabling breaks resolution.
        private static int GetWindowsBuild()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
                var s = k?.GetValue("CurrentBuildNumber")?.ToString() ?? "0";
                return int.TryParse(s, out var b) ? b : 0;
            }
            catch { return 0; }
        }

        private void RefreshDnsClientButton()
        {
            var start   = GetDnscacheStart();
            var running = IsDnscacheRunning();

            // Disabled in registry but still running == pending reboot / manual stop
            if (start == 4 && running)
            {
                BtnDnsClient.Content    = "⏳ Disable pending";
                BtnDnsClient.Background  = new SolidColorBrush(Color.FromRgb(0x92, 0x40, 0x0e));
                BtnDnsClient.Foreground  = new SolidColorBrush(Colors.White);
                BtnDnsClient.ToolTip     = "Start=Disabled, but service still running. Reboot or manually stop to take effect. Click to re-enable.";
            }
            else if (start == 4)
            {
                BtnDnsClient.Content    = "✗ Disabled";
                BtnDnsClient.Background  = new SolidColorBrush(Color.FromRgb(0x7f, 0x1d, 0x1d));
                BtnDnsClient.Foreground  = new SolidColorBrush(Color.FromRgb(0xfc, 0xa5, 0xa5));
                BtnDnsClient.ToolTip     = "DNS Client disabled and stopped. Click to re-enable (Start=Automatic).";
            }
            else if (running)
            {
                BtnDnsClient.Content    = "● Running";
                BtnDnsClient.Background  = new SolidColorBrush(Color.FromRgb(0x05, 0x7a, 0x55));
                BtnDnsClient.Foreground  = new SolidColorBrush(Colors.White);
                BtnDnsClient.ToolTip     = $"Dnscache running (Start={StartLabel(start)}). Click to schedule disable.";
            }
            else
            {
                BtnDnsClient.Content    = "■ Stopped";
                BtnDnsClient.Background  = new SolidColorBrush(Color.FromRgb(0x37, 0x41, 0x51));
                BtnDnsClient.Foreground  = new SolidColorBrush(Color.FromRgb(0x9c, 0xa3, 0xaf));
                BtnDnsClient.ToolTip     = $"Dnscache stopped (Start={StartLabel(start)}). Click to schedule disable.";
            }

            BtnDnsClient.IsEnabled = _isAdmin && start != -1;
        }

        private static string StartLabel(int start) => start switch
        {
            2 => "Automatic", 3 => "Manual", 4 => "Disabled", _ => "?"
        };

        private void BtnDnsClient_Click(object s, RoutedEventArgs e)
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }

            var start = GetDnscacheStart();
            if (start == -1) { SetStatus("Cannot read Dnscache service key.", error: true); return; }

            // Re-enable path
            if (start == 4)
            {
                var ok = MessageBox.Show(
                    "Re-enable DNS Client?\n\nSets Dnscache Start = 2 (Automatic).\nTakes effect after reboot (or start the service manually).",
                    "Re-enable DNS Client", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (ok != MessageBoxResult.Yes) return;
                SetDnscacheStart(2, "re-enabled (Automatic)");
                return;
            }

            // Disable path
            var build = GetWindowsBuild();
            var warn  = build >= 26100
                ? $"\n\n⚠ This build is {build} (24H2+). On 24H2+, disabling DNS Client can break ALL name " +
                  "resolution rather than moving it per-process — the stub resolver is mandatory. Proceed only " +
                  "if you have confirmed this box's behavior."
                : "";

            var msg = "Schedule DNS Client (Dnscache) for disable?\n\n" +
                      $"Current Start = {StartLabel(start)} ({start})  →  Disabled (4)\n\n" +
                      "This is a registry write only. It does NOT stop the running service — " +
                      "the change takes effect on reboot, or when you stop the process manually.\n\n" +
                      "Current Start value is backed up first." + warn;

            var res = MessageBox.Show(msg, "Disable DNS Client",
                MessageBoxButton.YesNo, build >= 26100 ? MessageBoxImage.Warning : MessageBoxImage.Question);
            if (res != MessageBoxResult.Yes) return;

            // Back up current Start value before writing
            var backupPath = WriteDnscacheBackup(start);
            SetDnscacheStart(4, $"scheduled disable — reboot or stop the process to apply.  Backup → {backupPath}");
        }

        private void SetDnscacheStart(int value, string statusVerb)
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(RegDnscache, writable: true);
                if (k == null) { SetStatus("Cannot open Dnscache key for writing.", error: true); return; }
                k.SetValue("Start", value, RegistryValueKind.DWord);
                RefreshDnsClientButton();
                SetStatus($"DNS Client {statusVerb}");
            }
            catch (Exception ex) { SetStatus($"DNS Client error: {ex.Message}", error: true); }
        }

        // Backup the prior Start value as a mergeable .reg (double-click to restore)
        private static string WriteDnscacheBackup(int currentStart)
        {
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FirewallManager", "Backups");
            System.IO.Directory.CreateDirectory(dir);
            var path = System.IO.Path.Combine(dir, $"dnscache-start-{DateTime.Now:yyyyMMdd-HHmmss}.reg");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Windows Registry Editor Version 5.00");
            sb.AppendLine();
            sb.AppendLine($@"[HKEY_LOCAL_MACHINE\{RegDnscache}]");
            sb.AppendLine($"\"Start\"=dword:{currentStart:x8}");

            System.IO.File.WriteAllText(path, sb.ToString(), System.Text.Encoding.Unicode);
            return path;
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private void SetStatus(string msg, bool error = false)
        {
            StatusText.Text       = msg;
            StatusText.Foreground = error
                ? new SolidColorBrush(Color.FromRgb(0xf8,0x71,0x71))
                : new SolidColorBrush(Color.FromRgb(0x6b,0x72,0x80));
        }

        private static bool IsRunningAsAdmin()
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
