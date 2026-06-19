using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FirewallManager
{
    public partial class RuleEditWindow : Window
    {
        private const string RegGPO   = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";
        private const string RegLocal = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

        private MainWindow.FirewallRule? _rule;
        private bool _isReadOnly  = false;
        private bool _isNew       = false;
        private List<string> _ips = new();

        // ── Entry points ─────────────────────────────────────────────────────

        public static void OpenEdit(MainWindow.FirewallRule rule, Window owner)
        {
            var w = new RuleEditWindow { Owner = owner };
            w._rule = rule;
            w.PopulateFromRule(rule);
            w.ShowDialog();
        }

        public static void OpenNew(Window owner)
        {
            var w = new RuleEditWindow { Owner = owner };
            w._isNew             = true;
            w.TitleText.Text     = "New Rule";
            w.SourceBadge.Background = new SolidColorBrush(Color.FromRgb(0x1d, 0x4e, 0xd8));
            w.SourceLabel.Text   = "GPO-Script";
            w.CboDirection.SelectedIndex = 1;
            w.CboAction.SelectedIndex    = 0;
            w.CboProtocol.SelectedIndex  = 0;
            w.TogActive.IsChecked        = true;
            w.ShowDialog();
        }

        public static void OpenDuplicate(MainWindow.FirewallRule rule, Window owner)
        {
            var w = new RuleEditWindow { Owner = owner };
            w._isNew = true;
            w.TitleText.Text = "Duplicate Rule";
            w.PopulateFromRule(rule);
            w.TxtName.Text = rule.Name + " copy";
            w._rule = null;
            w.ShowDialog();
        }

        public RuleEditWindow()
        {
            InitializeComponent();
            TogActive.Checked   += (s, e) => ActiveLabel.Text = "Enabled";
            TogActive.Unchecked += (s, e) => ActiveLabel.Text = "Disabled";
            TxtProgram.TextChanged += TxtProgram_TextChanged;
        }

        // ── DNS server IPs (read from existing rule) ─────────────────────────

        private string _standardDnsIPs = "";

        private string GetStandardDNSIPs()
        {
            if (!string.IsNullOrEmpty(_standardDnsIPs)) return _standardDnsIPs;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(RegGPO, writable: false);
                var raw = key?.GetValue("CUSTOM_DNS_UDP_Out")?.ToString() ?? "";
                var part = raw.Split('|').FirstOrDefault(p =>
                    p.StartsWith("RA4=", StringComparison.OrdinalIgnoreCase));
                _standardDnsIPs = part?["RA4=".Length..] ?? "";
            }
            catch { }
            return _standardDnsIPs;
        }

        // ── DNS companion panel visibility ────────────────────────────────────

        private void TxtProgram_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            var hasExe = !string.IsNullOrWhiteSpace(TxtProgram.Text);
            DnsCompanionPanel.Visibility = hasExe && !_isReadOnly ? Visibility.Visible : Visibility.Collapsed;

            // Clear any "no program path" validation error
            if (hasExe && ValidationMsg.Text.Contains("path"))
                ValidationMsg.Visibility = Visibility.Collapsed;

            if (hasExe)
            {
                var dnsIPs = GetStandardDNSIPs();
                DnsIPsLabel.Text = string.IsNullOrEmpty(dnsIPs) ? "(no DNS rule found)" : $"({dnsIPs})";
            }
        }

        private void TogCreateDNS_Changed(object sender, RoutedEventArgs e)
        {
            var on = TogCreateDNS.IsChecked == true;
            DnsRestrictPanel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }

        // ── Populate ─────────────────────────────────────────────────────────

        private void PopulateFromRule(MainWindow.FirewallRule rule)
        {
            _isReadOnly = rule.Source == "GPO-Manual";
            TitleText.Text           = _isReadOnly ? "View Rule" : "Edit Rule";
            ReadOnlyLabel.Visibility = _isReadOnly ? Visibility.Visible : Visibility.Collapsed;
            BtnSave.IsEnabled        = !_isReadOnly;
            SourceLabel.Text         = rule.Source;
            SourceBadge.Background   = rule.SourceBadgeBrush;
            TxtName.Text             = rule.Name;
            TxtName.IsReadOnly       = _isReadOnly;

            SelectCombo(CboDirection, rule.Direction);
            SelectCombo(CboAction,    rule.Action);
            SelectCombo(CboProtocol,  rule.Protocol);

            TxtPorts.Text = rule.Ports;

            // Use full program path from raw value, not the display name
            TxtProgram.Text = ExtractFullProgram(rule.RawValue);

            TogActive.IsChecked = rule.Active == "TRUE";

            // Show DNS restriction toggle for UDP port 53 rules
            var isUDP53 = rule.Protocol == "UDP" &&
                (rule.Ports == "53" || rule.RawValue.Contains("RPort=53"));
            DnsRulePanel.Visibility = isUDP53 && !_isReadOnly ? Visibility.Visible : Visibility.Collapsed;
            if (isUDP53)
            {
                var dnsIPs  = GetStandardDNSIPs();
                DnsRestrictIPsLabel.Text = string.IsNullOrEmpty(dnsIPs) ? "(no DNS rule found)" : $"({dnsIPs})";
                // Pre-set toggle if current RA4 matches standard DNS IPs
                var currentRA = rule.RemoteAddress;
                TogDNSRestrict.IsChecked = !string.IsNullOrEmpty(dnsIPs) &&
                    currentRA.Equals(dnsIPs, StringComparison.OrdinalIgnoreCase);
            }

            if (string.IsNullOrEmpty(rule.RemoteAddress) || rule.RemoteAddress == "Any")
            {
                TogAny.IsChecked = true;
            }
            else
            {
                TogAny.IsChecked = false;
                _ips = rule.RemoteAddress.Split(',').Select(s => s.Trim())
                    .Where(s => !string.IsNullOrEmpty(s)).ToList();
                RefreshIPTags();
            }

            SetFieldsReadOnly(_isReadOnly);
        }

        // Extract full App= path from raw registry value
        private static string ExtractFullProgram(string raw)
        {
            var part = raw.Split('|')
                .FirstOrDefault(p => p.StartsWith("App=", StringComparison.OrdinalIgnoreCase));
            return part?["App=".Length..] ?? "";
        }

        private void SetFieldsReadOnly(bool ro)
        {
            TxtPorts.IsReadOnly    = ro;
            TxtProgram.IsReadOnly  = ro;
            TxtNewIP.IsReadOnly    = ro;
            CboDirection.IsEnabled = !ro;
            CboAction.IsEnabled    = !ro;
            CboProtocol.IsEnabled  = !ro;
            TogAny.IsEnabled       = !ro;
            TogActive.IsEnabled    = !ro;
        }

        private static void SelectCombo(ComboBox cbo, string value)
        {
            foreach (ComboBoxItem item in cbo.Items)
                if (item.Content?.ToString() == value)
                { cbo.SelectedItem = item; return; }
            if (cbo.Items.Count > 0) cbo.SelectedIndex = 0;
        }

        // ── IP tag management ─────────────────────────────────────────────────

        private void RefreshIPTags()
        {
            IPTagPanel.Children.Clear();
            foreach (var ip in _ips)
            {
                var ip2 = ip;
                var btn = new Button
                {
                    Content   = $"{ip}  ✕",
                    Style     = (Style)Resources["TagBtn"],
                    IsEnabled = !_isReadOnly
                };
                btn.Click += (s, e) => { _ips.Remove(ip2); RefreshIPTags(); };
                IPTagPanel.Children.Add(btn);
            }
        }

        private void BtnAddIP_Click(object sender, RoutedEventArgs e)
        {
            var ip = TxtNewIP.Text.Trim();
            if (string.IsNullOrEmpty(ip)) return;
            if (!_ips.Contains(ip)) { _ips.Add(ip); RefreshIPTags(); }
            TxtNewIP.Clear();
        }

        private void TogAny_Checked(object sender, RoutedEventArgs e)   => IPSection.Visibility = Visibility.Collapsed;
        private void TogAny_Unchecked(object sender, RoutedEventArgs e) => IPSection.Visibility = Visibility.Visible;

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

        private void BtnScanWindowsApps_Click(object sender, RoutedEventArgs e)
        {
            var exeName = TxtWindowsAppsSearch.Text.Trim();
            if (string.IsNullOrEmpty(exeName))
            {
                ShowError("Type an exe name to scan (e.g. Claude.exe)");
                return;
            }
            if (!exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                exeName += ".exe";

            var baseDir = @"C:\Program Files\WindowsApps";
            if (!Directory.Exists(baseDir))
            { ShowError("WindowsApps folder not found."); return; }

            SetStatus("Scanning WindowsApps…");

            try
            {
                var results = new List<string>();
                foreach (var dir in Directory.GetDirectories(baseDir))
                {
                    try
                    {
                        var found = Directory.GetFiles(dir, exeName, SearchOption.AllDirectories);
                        results.AddRange(found);
                    }
                    catch { /* access denied on some dirs */ }
                }

                if (results.Count == 0)
                {
                    ShowError($"'{exeName}' not found in WindowsApps.");
                }
                else if (results.Count == 1)
                {
                    TxtProgram.Text = results[0];
                    SetStatus($"✔ Found: {results[0]}");
                }
                else
                {
                    var picker = new ExePickerWindow(results, TxtProgram.Text) { Owner = this };
                    if (picker.ShowDialog() == true && picker.SelectedPath != null)
                    {
                        TxtProgram.Text = picker.SelectedPath;
                        SetStatus($"✔ Selected: {picker.SelectedPath}");
                    }
                }
            }
            catch (Exception ex) { ShowError($"Scan error: {ex.Message}"); }
        }

        // ── Update Location ──────────────────────────────────────────────────

        private void BtnUpdateLocation_Click(object sender, RoutedEventArgs e)
        {
            var currentPath = TxtProgram.Text.Trim();
            if (string.IsNullOrEmpty(currentPath))
            { ShowError("No program path set — use … to browse first."); return; }
            if (!File.Exists(currentPath))
            {
                // Path no longer valid — try to find updated location
            }

            var exeName    = Path.GetFileName(currentPath);           // Claude.exe
            var exeDir     = Path.GetDirectoryName(currentPath) ?? ""; // …\app
            var versionDir = Path.GetDirectoryName(exeDir) ?? "";      // …\Claude_1.5354…
            var baseDir    = Path.GetDirectoryName(versionDir) ?? "";  // …\OWS Apps
            var prefix     = Path.GetFileName(versionDir);             // Claude_1.5354…
            var prefix5    = prefix.Length >= 5 ? prefix[..5] : prefix; // Claud

            if (!Directory.Exists(baseDir))
            { ShowError($"Base directory not found:\n{baseDir}"); return; }

            SetStatus("Scanning…");

            try
            {
                // Find all candidate versioned folders
                var candidateDirs = Directory.GetDirectories(baseDir)
                    .Where(d =>
                    {
                        var name = Path.GetFileName(d);
                        return name.Length >= 5 && name[..5].Equals(prefix5, StringComparison.OrdinalIgnoreCase);
                    })
                    .ToList();

                if (candidateDirs.Count == 0)
                { ShowError($"No folders starting with '{prefix5}' found in:\n{baseDir}"); return; }

                // Search each candidate dir for the exe
                var subPath = Path.GetRelativePath(versionDir, currentPath); // e.g. app\Claude.exe

                var results = new List<(string FullPath, bool SubPathMatch)>();

                foreach (var dir in candidateDirs)
                {
                    // First check sub-path match (preferred)
                    var subPathMatch = Path.Combine(dir, subPath);
                    if (File.Exists(subPathMatch))
                    {
                        results.Add((subPathMatch, true));
                        continue;
                    }

                    // Full recursive search
                    try
                    {
                        var found = Directory.GetFiles(dir, exeName, SearchOption.AllDirectories);
                        foreach (var f in found)
                            results.Add((f, false));
                    }
                    catch { /* access denied on some dirs */ }
                }

                // Remove duplicates, sort: sub-path matches first
                results = results
                    .DistinctBy(r => r.FullPath.ToLowerInvariant())
                    .OrderByDescending(r => r.SubPathMatch)
                    .ThenBy(r => r.FullPath)
                    .ToList();

                if (results.Count == 0)
                {
                    ShowError($"'{exeName}' not found under any '{prefix5}*' folder in:\n{baseDir}");
                }
                else if (results.Count == 1)
                {
                    TxtProgram.Text = results[0].FullPath;
                    SetStatus($"✔ Updated: {results[0].FullPath}");
                }
                else
                {
                    // Multiple results — show picker
                    var picker = new ExePickerWindow(results.Select(r => r.FullPath).ToList(),
                        currentPath) { Owner = this };
                    if (picker.ShowDialog() == true && picker.SelectedPath != null)
                    {
                        TxtProgram.Text = picker.SelectedPath;
                        SetStatus($"✔ Updated: {picker.SelectedPath}");
                    }
                }
            }
            catch (Exception ex) { ShowError($"Scan error: {ex.Message}"); }
        }

        // ── Save ─────────────────────────────────────────────────────────────

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            if (!Validate()) return;
            try
            {
                var regPath = _rule?.RegistryPath ?? RegGPO;
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: true);
                if (key == null) { ShowError("Cannot open registry for writing."); return; }

                var name = TxtName.Text.Trim();

                // Fix: avoid double CUSTOM_ prefix
                var rawKey = name.Replace(" ", "_");
                if (!rawKey.StartsWith("CUSTOM_")) rawKey = "CUSTOM_" + rawKey;
                var regKey = _isNew ? rawKey : _rule!.RegistryKey;

                var fields = new List<string>
                {
                    $"Action={(CboAction.SelectedItem as ComboBoxItem)?.Content}",
                    $"Dir={(CboDirection.SelectedItem as ComboBoxItem)?.Content}"
                };

                var proto = (CboProtocol.SelectedItem as ComboBoxItem)?.Content?.ToString();
                if (proto != "Any") fields.Add($"Protocol={ProtoToNum(proto!)}");

                var ports = TxtPorts.Text.Trim();
                if (!string.IsNullOrEmpty(ports)) fields.Add($"RPort={ports}");

                var ra = TogAny.IsChecked == true ? "Any" : string.Join(",", _ips);
                if (!string.IsNullOrEmpty(ra)) fields.Add($"RA4={ra}");

                var prog = TxtProgram.Text.Trim();
                if (!string.IsNullOrEmpty(prog)) fields.Add($"App={prog}");

                var active = TogActive.IsChecked == true ? "Active=TRUE" : "Active=FALSE";

                // Convert App= path to %SystemDrive% format
                if (!string.IsNullOrEmpty(prog))
                {
                    var envProg = prog
                        .Replace(@"C:\Program Files (x86)\", @"%SystemDrive%\Program Files (x86)\")
                        .Replace(@"C:\Program Files\",       @"%SystemDrive%\Program Files\")
                        .Replace(@"C:\Windows\",             @"%SystemRoot%\")
                        .Replace(@"%ProgramFiles(x86)%\",    @"%SystemDrive%\Program Files (x86)\")
                        .Replace(@"%ProgramFiles%\",         @"%SystemDrive%\Program Files\");
                    fields.RemoveAll(f => f.StartsWith("App="));
                    fields.Add($"App={envProg}");
                }

                // Remove RA4=Any — omitting is equivalent
                fields.RemoveAll(f => f == "RA4=Any");

                // WFP needs one field per value. Expand comma lists in RPort= and RA4=/RA6=
                // (comma-joined RA4 makes WFP silently reject the rule — see SetupWindow note).
                var expanded = new List<string>();
                foreach (var field in fields)
                {
                    if (field.StartsWith("RPort=") && field.Contains(","))
                    {
                        foreach (var port in field["RPort=".Length..].Split(','))
                            expanded.Add($"RPort={port.Trim()}");
                    }
                    else if (field.StartsWith("RA4=") && field.Contains(","))
                    {
                        foreach (var addr4 in field["RA4=".Length..].Split(','))
                            expanded.Add($"RA4={addr4.Trim()}");
                    }
                    else if (field.StartsWith("RA6=") && field.Contains(","))
                    {
                        foreach (var addr6 in field["RA6=".Length..].Split(','))
                            expanded.Add($"RA6={addr6.Trim()}");
                    }
                    else expanded.Add(field);
                }

                var val = $"v2.33|{string.Join("|", expanded)}|{active}|Name={name}|";

                key.SetValue(regKey, val, RegistryValueKind.String);

                // DNS restriction toggle — if editing a UDP 53 rule and restriction toggled
                if (TogDNSRestrict.IsChecked == true && DnsRulePanel.Visibility == Visibility.Visible)
                {
                    var dnsIPs = GetStandardDNSIPs();
                    if (!string.IsNullOrEmpty(dnsIPs))
                    {
                        var restricted = val.Replace("RA4=Any", $"RA4={dnsIPs}");
                        // Also remove Any if it was set differently
                        if (!restricted.Contains($"RA4={dnsIPs}"))
                        {
                            var parts2 = val.Split('|').ToList();
                            var idx2   = parts2.FindIndex(p => p.StartsWith("RA4="));
                            if (idx2 >= 0) parts2[idx2] = $"RA4={dnsIPs}";
                            else parts2.Insert(parts2.Count - 2, $"RA4={dnsIPs}");
                            restricted = string.Join("|", parts2);
                        }
                        key.SetValue(regKey, restricted, RegistryValueKind.String);
                    }
                }

                // Companion DNS rule creation
                if (TogCreateDNS.IsChecked == true && DnsCompanionPanel.Visibility == Visibility.Visible)
                {
                    var dnsRA      = TogStandardDNS.IsChecked == true ? GetStandardDNSIPs() : "";
                    if (string.IsNullOrEmpty(dnsRA)) dnsRA = "Any";
                    var dnsRuleKey = regKey + "_DNS";
                    var dnsName    = name + " DNS";
                    var envProg2   = prog
                        .Replace(@"C:\Program Files (x86)\", @"%SystemDrive%\Program Files (x86)\")
                        .Replace(@"C:\Program Files\",       @"%SystemDrive%\Program Files\")
                        .Replace(@"C:\Windows\",             @"%SystemRoot%\")
                        .Replace(@"%ProgramFiles(x86)%\",    @"%SystemDrive%\Program Files (x86)\")
                        .Replace(@"%ProgramFiles%\",         @"%SystemDrive%\Program Files\");
                    var dnsAppPart = string.IsNullOrEmpty(prog) ? "" : $"|App={envProg2}";
                    var dnsRAPart  = dnsRA == "Any" ? "" : $"|RA4={dnsRA}";
                    var dnsVal     = $"v2.33|Action=Allow|Dir=Out|Protocol=17|RPort=53{dnsRAPart}{dnsAppPart}|{active}|Name={dnsName}|";
                    key.SetValue(dnsRuleKey, dnsVal, RegistryValueKind.String);
                }

                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "gpupdate", Arguments = "/force",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                });

                SetStatus("Saved.");
                DialogResult = true;
                Close();
            }
            catch (Exception ex) { ShowError(ex.Message); }
        }

        private static string ProtoToNum(string proto) => proto switch
        {
            "TCP" => "6", "UDP" => "17", _ => "0"
        };

        private bool Validate()
        {
            if (string.IsNullOrWhiteSpace(TxtName.Text))
            { ShowError("Name is required."); return false; }
            if (TogAny.IsChecked == false && _ips.Count == 0 && string.IsNullOrWhiteSpace(TxtNewIP.Text))
            { ShowError("Add at least one IP, or toggle Any."); return false; }
            if (!string.IsNullOrWhiteSpace(TxtNewIP.Text))
            { _ips.Add(TxtNewIP.Text.Trim()); RefreshIPTags(); TxtNewIP.Clear(); }
            ValidationMsg.Visibility = Visibility.Collapsed;
            return true;
        }

        private void ShowError(string msg)
        {
            ValidationMsg.Text       = msg;
            ValidationMsg.Visibility = Visibility.Visible;
            EditStatus.Text          = "";
        }

        private void SetStatus(string msg)
        {
            EditStatus.Text       = msg;
            EditStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0xd3, 0x99));
            ValidationMsg.Visibility = Visibility.Collapsed;
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e) => Close();
    }
}
