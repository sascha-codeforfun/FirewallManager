using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using HueThemeKit;

namespace FirewallManager
{
    /// <summary>
    /// Windows' service-hardening rules (see ServiceHardening), read only but for purging
    /// obsolete Configurable rules. They only ever take
    /// away: a service gets through where they and the firewall's own rules both allow it, so
    /// they explain a service that stays blocked although a rule here allows it. The exception
    /// would be a hard permit, which is why each rule's live filters are checked for one.
    /// No way to remove or switch off any other rule, blocks above all: see "Purging obsolete
    /// rules" in ServiceHardening before adding one.
    /// </summary>
    public sealed class ServiceHardeningWindow : Window
    {
        private readonly DataGrid _grid;
        private readonly TextBlock _count;
        private readonly TextBox _filter;
        private readonly Button _purge, _refresh, _copy;
        private List<ServiceHardening.Rule> _rules = new();
        private List<ServiceHardening.Rule> _shown = new();
        private List<string> _problems = new();
        private List<WfpFilters.Filter>? _hardPermits;
        private ServiceHardening.FirewallSubLayer? _firewall;

        public ServiceHardeningWindow(Window owner)
        {
            SetResourceReference(StyleProperty, "Hue.Window");
            HueTitleBar.Attach(this);
            Owner = owner;
            Title = "Service hardening rules (Windows)";
            ScreenFit.Apply(this, new ScreenFit.Sizing(0.88, 0.75, 1760, 900, 900, 420), owner);

            var root = new DockPanel { Margin = new Thickness(18, 14, 18, 14) };

            var intro = new TextBlock
            {
                Text =
                    "Windows keeps these rules for its own services, apart from the firewall policy and the local rules. " +
                    "They apply whatever the merge setting says, and Purge Local, merge off and Lock down leave them as they are. " +
                    "They restrict Windows' services in a sublayer of their own: a service gets through only where these rules " +
                    "and your rules both allow it. A normal permit here opens nothing your rules block; a block here can " +
                    "stop a service your rules allow. The one exception would be a hard permit in a sublayer that outranks " +
                    "your rules': their blocks can't override it. The Hard column checks each rule's live filters for that. " +
                    "Static ones ship with Windows; Configurable ones are added by services such as Defender.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10),
            }.Styled("Text.Body");
            DockPanel.SetDock(intro, Dock.Top);
            root.Children.Add(intro);

            var bar = new DockPanel { Margin = new Thickness(0, 0, 0, 8), LastChildFill = true };
            _refresh = new Button { Margin = new Thickness(8, 0, 0, 0) };
            IconText.Set(_refresh, "Icon.Refresh", "Refresh");
            _refresh.Click += async (_, _) => await LoadAsync();
            DockPanel.SetDock(_refresh, Dock.Right);
            bar.Children.Add(_refresh);
            _copy = new Button
            {
                Content = "Copy for AI", Margin = new Thickness(8, 0, 0, 0),
                ToolTip = "Copy the rules in view, by service, with what each means here, as text to paste into an AI chat.",
            };
            _copy.Click += (_, _) => CopyForAi();
            DockPanel.SetDock(_copy, Dock.Right);
            bar.Children.Add(_copy);
            _purge = new Button
            {
                Margin = new Thickness(8, 0, 0, 0), IsEnabled = false,
                ToolTip = "Remove the Configurable rules whose program is no longer on this machine, after a backup. " +
                          "Static rules are never touched.",
            };
            IconText.Set(_purge, "Icon.Clean", "Purge obsolete");
            _purge.Click += async (_, _) => await PurgeAsync();
            DockPanel.SetDock(_purge, Dock.Right);
            bar.Children.Add(_purge);
            _filter = new TextBox { Width = 260, Margin = new Thickness(0, 0, 12, 0), VerticalContentAlignment = VerticalAlignment.Center,
                                    ToolTip = "Show only rules containing this text (service, program, who may run it, name, address, port, hard, missing)." };
            // While busy the text waits: a load applies it when the read is done.
            _filter.TextChanged += (_, _) => { if (!_busy) ShowRules(); };
            DockPanel.SetDock(_filter, Dock.Left);
            bar.Children.Add(_filter);
            var chips = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
            Chip(chips, "worth", "Only rules with a HARD verdict, \"?\" or \"not parsed\" under Hard, a missing program, or unusual run rights.",
                 () => _worth = !_worth);
            Chip(chips, "out", "Outbound rules only. Click again to show both directions.",
                 () => _dir = _dir == "Outbound" ? null : "Outbound");
            Chip(chips, "in", "Inbound rules only. Click again to show both directions.",
                 () => _dir = _dir == "Inbound" ? null : "Inbound");
            Chip(chips, "permits", "Permits only: what could matter for getting past your rules. Click again to clear.",
                 () => _action = _action == "Allow" ? null : "Allow");
            Chip(chips, "blocks", "Blocks only. Click again to clear.",
                 () => _action = _action == "Block" ? null : "Block");
            Chip(chips, "configurable", "Only rules added by services such as Defender: the ones that change over time and go stale.",
                 () => _configurable = !_configurable);
            Chip(chips, "off", "Leave out switched-off rules: they take no part in any decision. The number is how many it hides.",
                 () => _hideOff = !_hideOff);
            bar.Children.Add(chips);
            RefreshChips();
            DockPanel.SetDock(bar, Dock.Top);
            root.Children.Add(bar);

            _count = new TextBlock { Margin = new Thickness(0, 0, 0, 8), TextWrapping = TextWrapping.Wrap }.Styled("Text.Caption");
            DockPanel.SetDock(_count, Dock.Top);
            root.Children.Add(_count);

            _grid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                SelectionMode = DataGridSelectionMode.Extended,
                SelectionUnit = DataGridSelectionUnit.Cell,
                ClipboardCopyMode = DataGridClipboardCopyMode.IncludeHeader,
            };
            // Short columns fixed; program, who can run it, remote and name share what's left, so
            // the grid fits the window without a horizontal scrollbar. Cut-off text is in each
            // cell's tooltip.
            Column("Service",          nameof(ServiceHardening.Rule.ServiceShown), 110, nameof(ServiceHardening.Rule.ServiceShown));
            Column("Program",          nameof(ServiceHardening.Rule.ProgramShown), 0,   nameof(ServiceHardening.Rule.ProgramTip), star: 2,   min: 140,
                   warnWhen: nameof(ServiceHardening.Rule.ProgramMissing), badWhen: nameof(ServiceHardening.Rule.UnscopedProgram));
            Column("Can run the file", nameof(ServiceHardening.Rule.CanRunShown),  0,   nameof(ServiceHardening.Rule.ProgramTip), star: 1.3, min: 90,
                   warnWhen: nameof(ServiceHardening.Rule.UnusualRun));
            // Direction and On look as in the main list; Action is coloured here on purpose (an
            // Allow is what could widen access), unlike the main list's plain tags.
            IconTagColumn("Dir",       nameof(ServiceHardening.Rule.DirShort),     90,
                          r => r.Direction == "Inbound" ? ("Hue.Tag.Caution", "Icon.In") : ("Hue.Tag.Safe", "Icon.Out"));
            IconTagColumn("Action",    nameof(ServiceHardening.Rule.Action),       100,
                          r => r.Action == "Block" ? ("Hue.Tag.Safe", "Icon.Block") : ("Hue.Tag.Caution", "Icon.Check"));
            IconTagColumn("On",        nameof(ServiceHardening.Rule.EnabledShown), 75,
                          r => (r.Enabled ? "Hue.Pill.Ok" : "Hue.Pill.Stale", null));
            TagColumn("Hard",          nameof(ServiceHardening.Rule.Hard),         155,  nameof(ServiceHardening.Rule.HardTip),
                      r => r.HardLevel switch { "Above" => "Hue.Tag.Unsafe", "Unknown" => "Hue.Tag.Caution", "Outlier" => "Tag.Rare", _ => null },
                      "No hard permit has turned up in normal use on Windows 10, 11 or Server 2019. " +
                      "The verdicts were checked against test filters on Windows 10 22H2.");
            // On an Allow rule, "Any" in a scope field is red: the permit isn't limited there.
            Column("Proto",            nameof(ServiceHardening.Rule.Protocol),     62,  badWhen: nameof(ServiceHardening.Rule.UnscopedProtocol));
            Column("Remote port",      nameof(ServiceHardening.Rule.RemotePorts),  96,  nameof(ServiceHardening.Rule.RemotePorts),
                   badWhen: nameof(ServiceHardening.Rule.UnscopedRemotePort));
            Column("Remote",           nameof(ServiceHardening.Rule.Remote),       0,   nameof(ServiceHardening.Rule.RemoteTip), star: 0.6, min: 70,
                   badWhen: nameof(ServiceHardening.Rule.UnscopedRemote));
            Column("Local port",       nameof(ServiceHardening.Rule.LocalPorts),   86,  nameof(ServiceHardening.Rule.LocalPorts),
                   badWhen: nameof(ServiceHardening.Rule.UnscopedLocalPort));
            TagColumn("Store",         nameof(ServiceHardening.Rule.Store),        122, null,
                      r => r.IsConfigurable ? "Hue.Tag.Accent" : null);
            Column("Name",             nameof(ServiceHardening.Rule.NameShown),    0,   nameof(ServiceHardening.Rule.NameTip), star: 2.2, min: 110);
            _grid.RowStyle = RowStyle();
            root.Children.Add(_grid);

            DefineRareTag();
            HueContrast.Changed += OnContrastChanged;
            // A purge runs to the end with the window open, so its report is never lost.
            Closing += (_, e) =>
            {
                if (!_purging) return;
                e.Cancel = true;
                _count.Text = "Purging… the window can close when it's done";
            };
            Closed += (_, _) =>
            {
                _closed = true;
                _messageTimer.Stop();
                HueContrast.Changed -= OnContrastChanged;
            };

            Content = root;
            Loaded += async (_, _) => await LoadAsync();
        }

        // ── Columns and colours ──────────────────────────────────────────────
        // Only what deserves a second look is coloured, by what to do: red could get past your
        // rules, amber can't be told, indigo is an outlier that provably doesn't get past them,
        // dimmed takes no part.

        private static DataGridLength ColumnWidth(double width, double star) =>
            star > 0 ? new DataGridLength(star, DataGridLengthUnitType.Star) : new DataGridLength(width);

        // tipPath: a tooltip for values the column cuts off or that need explaining.
        // star > 0: the column takes that share of the space left over, never less than min.
        // warnWhen: a true/false property that turns the text amber; badWhen: one that turns it red
        // (applied after, so red wins).
        private void Column(string header, string path, double width, string? tipPath = null, double star = 0, double min = 40,
                            string? warnWhen = null, string? badWhen = null)
        {
            var column = new DataGridTextColumn { Header = header, Binding = new Binding(path), Width = ColumnWidth(width, star), MinWidth = min };
            if (tipPath != null || warnWhen != null || badWhen != null)
            {
                var style = new Style(typeof(TextBlock));
                if (tipPath != null) style.Setters.Add(new Setter(TextBlock.ToolTipProperty, new Binding(tipPath)));
                style.Setters.Add(new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis));
                if (warnWhen != null)
                {
                    var warn = new DataTrigger { Binding = new Binding(warnWhen), Value = true };
                    warn.Setters.Add(new Setter(TextBlock.ForegroundProperty, new DynamicResourceExtension("Brush.WarnText")));
                    style.Triggers.Add(warn);
                }
                if (badWhen != null)
                {
                    var bad = new DataTrigger { Binding = new Binding(badWhen), Value = true };
                    bad.Setters.Add(new Setter(TextBlock.ForegroundProperty, new DynamicResourceExtension("Brush.ErrorText")));
                    bad.Setters.Add(new Setter(TextBlock.FontWeightProperty, FontWeights.SemiBold));
                    style.Triggers.Add(bad);
                }
                column.ElementStyle = style;
            }
            _grid.Columns.Add(column);
        }

        // A column whose value shows as a tag when tagStyle names one for the row, plain otherwise.
        // headerTip: a tooltip on the column header; the header itself stays text, so a copy
        // with headers still reads it.
        private void TagColumn(string header, string path, double width, string? tipPath,
                               Func<ServiceHardening.Rule, string?> tagStyle, string? headerTip = null)
        {
            var plain = CellTemplate(path, tipPath, null);
            var tags = new Dictionary<string, DataTemplate>();
            // The tip goes on the header's template, which leaves the header's style to the theme.
            // A header style set here went with another header losing the theme (Windows 11).
            DataTemplate? headerTemplate = null;
            if (headerTip != null)
            {
                var text = new FrameworkElementFactory(typeof(TextBlock));
                text.SetBinding(TextBlock.TextProperty, new Binding());
                text.SetValue(ToolTipProperty, headerTip);
                headerTemplate = new DataTemplate { VisualTree = text };
            }
            _grid.Columns.Add(new DataGridTemplateColumn
            {
                Header = header, Width = new DataGridLength(width), MinWidth = 40, HeaderTemplate = headerTemplate,
                SortMemberPath = path, ClipboardContentBinding = new Binding(path),
                CellTemplateSelector = new PickTemplate(item =>
                {
                    if (item is not ServiceHardening.Rule r || tagStyle(r) is not { } key) return plain;
                    if (!tags.TryGetValue(key, out var t)) tags[key] = t = CellTemplate(path, tipPath, key);
                    return t;
                }),
            });
        }

        // A tag on every row, its style (and icon, if any) picked per row.
        private void IconTagColumn(string header, string path, double width,
                                   Func<ServiceHardening.Rule, (string Style, string? Icon)> pick)
        {
            var templates = new Dictionary<(string, string?), DataTemplate>();
            _grid.Columns.Add(new DataGridTemplateColumn
            {
                Header = header, Width = new DataGridLength(width), MinWidth = 40,
                SortMemberPath = path, ClipboardContentBinding = new Binding(path),
                CellTemplateSelector = new PickTemplate(item =>
                {
                    var look = item is ServiceHardening.Rule r ? pick(r) : ("Hue.Tag", null);
                    if (!templates.TryGetValue(look, out var t)) templates[look] = t = IconTagTemplate(path, look.Style, look.Icon);
                    return t;
                }),
            });
        }

        private static DataTemplate IconTagTemplate(string path, string style, string? icon)
        {
            var tag = new FrameworkElementFactory(typeof(ContentControl));
            tag.SetResourceReference(FrameworkElement.StyleProperty, style);
            tag.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Left);
            tag.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            if (icon == null)
            {
                tag.SetBinding(ContentControl.ContentProperty, new Binding(path));
                return new DataTemplate { VisualTree = tag };
            }
            var row = new FrameworkElementFactory(typeof(StackPanel));
            row.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
            var glyph = new FrameworkElementFactory(typeof(System.Windows.Shapes.Path));
            glyph.SetResourceReference(FrameworkElement.StyleProperty, "Hue.Icon");
            glyph.SetResourceReference(System.Windows.Shapes.Path.DataProperty, icon);
            var text = new FrameworkElementFactory(typeof(TextBlock));
            text.SetBinding(TextBlock.TextProperty, new Binding(path));
            text.SetValue(FrameworkElement.MarginProperty, new Thickness(5, 0, 0, 0));
            text.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            row.AppendChild(glyph);
            row.AppendChild(text);
            tag.AppendChild(row);
            return new DataTemplate { VisualTree = tag };
        }

        private static DataTemplate CellTemplate(string path, string? tipPath, string? tagStyle)
        {
            FrameworkElementFactory cell;
            if (tagStyle == null)
            {
                cell = new FrameworkElementFactory(typeof(TextBlock));
                cell.SetBinding(TextBlock.TextProperty, new Binding(path));
                cell.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
            }
            else
            {
                cell = new FrameworkElementFactory(typeof(ContentControl));
                cell.SetBinding(ContentControl.ContentProperty, new Binding(path));
                cell.SetResourceReference(FrameworkElement.StyleProperty, tagStyle);
                cell.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Left);
            }
            cell.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            if (tipPath != null) cell.SetBinding(FrameworkElement.ToolTipProperty, new Binding(tipPath));
            return new DataTemplate { VisualTree = cell };
        }

        private sealed class PickTemplate : DataTemplateSelector
        {
            private readonly Func<object, DataTemplate> _pick;
            public PickTemplate(Func<object, DataTemplate> pick) => _pick = pick;
            public override DataTemplate SelectTemplate(object item, DependencyObject container) => _pick(item);
        }

        // A hard permit above your rules tints its row red; a rule switched off is dimmed.
        private Style RowStyle()
        {
            var style = new Style(typeof(DataGridRow), TryFindResource(typeof(DataGridRow)) as Style);
            var above = new DataTrigger { Binding = new Binding(nameof(ServiceHardening.Rule.HardLevel)), Value = "Above" };
            above.Setters.Add(new Setter(BackgroundProperty, new DynamicResourceExtension("Brush.ErrorSoft")));
            style.Triggers.Add(above);
            var off = new DataTrigger { Binding = new Binding(nameof(ServiceHardening.Rule.Enabled)), Value = false };
            off.Setters.Add(new Setter(OpacityProperty, 0.5));
            style.Triggers.Add(off);
            return style;
        }

        // Indigo for the outlier, outside the Cyan family on purpose, as in the connection log;
        // the system's own colours while a contrast theme is on.
        private void DefineRareTag()
        {
            var rare = new Style(typeof(ContentControl), TryFindResource("Hue.Tag") as Style);
            rare.Setters.Add(new Setter(ForegroundProperty,  new DynamicResourceExtension("Rare.Text")));
            rare.Setters.Add(new Setter(BackgroundProperty,  new DynamicResourceExtension("Rare.Soft")));
            rare.Setters.Add(new Setter(BorderBrushProperty, new DynamicResourceExtension("Rare.Edge")));
            Resources["Tag.Rare"] = rare;
            ApplyRareHue();
        }

        private void OnContrastChanged(object? sender, EventArgs e) => ApplyRareHue();

        private void ApplyRareHue()
        {
            Brush Indigo(string key) => TryFindResource(key) is Color c ? new SolidColorBrush(c) : SystemColors.WindowTextBrush;
            var contrast = HueContrast.IsActive;
            Resources["Rare.Text"] = contrast ? SystemColors.WindowTextBrush : Indigo("Indigo.Light");
            Resources["Rare.Soft"] = contrast ? SystemColors.WindowBrush     : Indigo("Indigo.Soft");
            Resources["Rare.Edge"] = contrast ? SystemColors.WindowTextBrush : Indigo("Indigo.Edge");
        }

        // ── Busy ─────────────────────────────────────────────────────────────
        // One flag for loading and purging: nothing that would start another read or purge, or
        // act on a list about to change, can be clicked meanwhile. The text box stays typeable.

        private bool _busy, _purging, _closed;

        // Counted over all windows: the main window holds its own closing while any purge runs.
        private static int _purges;
        public static bool AnyPurging => _purges > 0;

        private void SetBusy(bool busy, string status = "")
        {
            _busy = busy;
            if (busy)
            {
                _messageTimer.Stop();
                _count.Text = status;
            }
            _refresh.IsEnabled = !busy;
            _copy.IsEnabled = !busy;
            foreach (var chip in _chips.Values) chip.IsEnabled = !busy;
            RefreshPurge();
        }

        private async Task LoadAsync()
        {
            if (_busy) return;
            SetBusy(true, "Reading… (can take a minute)");
            _grid.ItemsSource = null;
            ServiceHardening.Snapshot snapshot;
            try { snapshot = await Task.Run(ServiceHardening.Read); }
            catch (Exception ex) { snapshot = new ServiceHardening.Snapshot(new(), new List<string> { ex.Message }, null, null); }
            // Closing during a read is allowed; the result then has nowhere to go.
            if (_closed) return;
            // By service, so each service's permits and the block that follows them read together.
            _rules = snapshot.Rules
                .OrderBy(r => r.Service, StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => r.Direction == "Outbound" ? 0 : 1)
                .ThenBy(r => r.Action == "Allow" ? 0 : 1)
                .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            _problems = snapshot.Problems;
            _hardPermits = snapshot.HardPermits;
            _firewall = snapshot.Firewall;
            SetBusy(false);
            ShowRules();
        }

        // ── Filter buttons ───────────────────────────────────────────────────
        // Combined with each other and with the text box. Each shows how many rules it would
        // leave given the other filters, so a click is never a guess.

        private bool _worth, _configurable, _hideOff;
        private string? _dir, _action;
        private readonly Dictionary<string, Button> _chips = new();

        private void Chip(Panel panel, string key, string tip, Action toggle)
        {
            var button = new Button { Margin = new Thickness(0, 0, 6, 0), ToolTip = tip };
            button.Click += (_, _) => { toggle(); ShowRules(); };
            _chips[key] = button;
            panel.Children.Add(button);
        }

        private static bool Worth(ServiceHardening.Rule r) => r.HardLevel.Length > 0 || r.ProgramMissing || r.UnusualRun;

        // skip: the filter group whose own effect is left out, for that group's counts.
        private bool Passes(ServiceHardening.Rule r, string? skip = null)
        {
            if (skip != "worth"        && _worth && !Worth(r))                   return false;
            if (skip != "dir"          && _dir != null && r.Direction != _dir)   return false;
            if (skip != "action"       && _action != null && r.Action != _action) return false;
            if (skip != "configurable" && _configurable && !r.IsConfigurable)    return false;
            if (skip != "off"          && _hideOff && !r.Enabled)                return false;
            var text = _filter.Text.Trim();
            return text.Length == 0 ||
                   new[] { r.Service, r.ServiceShown, r.Program, r.ProgramShown, r.CanRun, r.UnusualWhat, r.Name, r.NameShown, r.Remote, r.RemotePorts, r.LocalPorts, r.Protocol, r.Store, r.Direction, r.Action, r.Hard }
                       .Any(v => v.Contains(text, StringComparison.OrdinalIgnoreCase));
        }

        private void RefreshChips()
        {
            void Set(string key, string label, string group, Func<ServiceHardening.Rule, bool> match, bool on)
            {
                var button = _chips[key];
                button.Content = $"{label} ({_rules.Count(r => Passes(r, group) && match(r))})";
                button.Styled(on ? "Hue.Button.Tonal" : "Hue.Button");
            }
            Set("worth",        "Worth a look", "worth",        Worth,                        _worth);
            Set("out",          "Out",          "dir",          r => r.Direction == "Outbound", _dir == "Outbound");
            Set("in",           "In",           "dir",          r => r.Direction == "Inbound",  _dir == "Inbound");
            Set("permits",      "Permits",      "action",       r => r.Action == "Allow",       _action == "Allow");
            Set("blocks",       "Blocks",       "action",       r => r.Action == "Block",       _action == "Block");
            Set("configurable", "Configurable", "configurable", r => r.IsConfigurable,          _configurable);
            Set("off",          "Hide off",     "off",          r => !r.Enabled,                _hideOff);
        }

        private string FilterSummary()
        {
            var parts = new List<string>();
            if (_worth) parts.Add("worth a look");
            if (_dir != null) parts.Add(_dir.ToLowerInvariant());
            if (_action == "Allow") parts.Add("permits");
            if (_action == "Block") parts.Add("blocks");
            if (_configurable) parts.Add("Configurable store");
            if (_hideOff) parts.Add("switched-off rules hidden");
            if (_filter.Text.Trim().Length > 0) parts.Add($"containing \"{_filter.Text.Trim()}\"");
            return string.Join(", ", parts);
        }

        private void ShowRules()
        {
            _shown = _rules.Where(r => Passes(r)).ToList();
            _grid.ItemsSource = _shown;
            RefreshChips();
            RefreshPurge();
            ShowSummary();
        }

        // ── Purge obsolete ───────────────────────────────────────────────────
        // Counts every obsolete rule, not just those in view: the filters decide what is shown,
        // not what is tidied.

        private void RefreshPurge()
        {
            var n = _rules.Count(r => r.Obsolete);
            IconText.SetText(_purge, n > 0 ? $"Purge obsolete ({n})" : "Purge obsolete");
            _purge.IsEnabled = n > 0 && !_busy;
        }

        private async Task PurgeAsync()
        {
            if (_busy) return;
            var obsolete = _rules.Where(r => r.Obsolete).ToList();
            if (obsolete.Count == 0) return;

            const int Listed = 30;
            var list = string.Join("\n", obsolete.Take(Listed).Select(r => $"• {r.ServiceShown} · {r.DirShort} {r.Action} · {r.ProgramShown}"));
            if (obsolete.Count > Listed) list += $"\n… and {obsolete.Count - Listed} more";
            var message =
                $"These {obsolete.Count} Configurable rules are for program files no longer on this machine:\n\n{list}\n\n" +
                $"They are saved first to a .reg file in {AppFolder.FolderPath}, then removed " +
                "through the firewall service, so they are gone at once. One the service won't remove is deleted from " +
                "the registry instead, which takes effect at the next restart. Static rules are never touched.\n\n" +
                "To undo, double-click the .reg file (as administrator): the rules come back in the registry and apply again " +
                "after the next restart.";
            if (!ThemedDialog.Confirm(this, "Purge obsolete service rules?", message, "Purge", danger: true)) return;

            _purging = true;
            _purges++;
            // Reset whatever happens, or the window (and the app) could never close again.
            try
            {
                SetBusy(true, "Purging…");
                ServiceHardening.PurgeResult result;
                try { result = await Task.Run(() => ServiceHardening.Purge(obsolete)); }
                catch (Exception ex) { result = new ServiceHardening.PurgeResult(0, 0, new List<string> { ex.Message }, new List<string>(), null); }

                var report = new StringBuilder();
                report.AppendLine($"Removed at once: {result.ByService}");
                if (result.ByRegistry > 0) report.AppendLine($"Removed from the registry, gone after the next restart: {result.ByRegistry}");
                if (result.Backup != null) report.AppendLine($"Backup: {result.Backup}");
                if (result.Failed.Count > 0)
                {
                    report.AppendLine().AppendLine($"Not removed ({result.Failed.Count}):");
                    foreach (var f in result.Failed.Take(Listed)) report.AppendLine($"• {f}");
                    if (result.Failed.Count > Listed) report.AppendLine($"… and {result.Failed.Count - Listed} more");
                }
                if (result.Notes.Count > 0)
                {
                    report.AppendLine().AppendLine("Notes:");
                    foreach (var n in result.Notes.Take(Listed)) report.AppendLine($"• {n}");
                    if (result.Notes.Count > Listed) report.AppendLine($"… and {result.Notes.Count - Listed} more");
                }
                ThemedDialog.Info(this, "Purge obsolete service rules", report.ToString().TrimEnd(), danger: result.Failed.Count > 0);
            }
            finally
            {
                _purging = false;
                _purges--;
                SetBusy(false);
            }
            await LoadAsync();
        }

        // A passing message (a copy) stands in the summary line for a few seconds, then the
        // summary comes back: it holds the hard-permit answer.
        private readonly System.Windows.Threading.DispatcherTimer _messageTimer = new() { Interval = TimeSpan.FromSeconds(4) };

        private void ShowMessage(string message)
        {
            _count.Text = message;
            _messageTimer.Stop();
            _messageTimer.Tick -= OnMessageDone;
            _messageTimer.Tick += OnMessageDone;
            _messageTimer.Start();
        }

        private void OnMessageDone(object? sender, EventArgs e)
        {
            _messageTimer.Stop();
            if (!_busy) ShowSummary();
        }

        private void ShowSummary()
        {
            _messageTimer.Stop();
            var services = _rules.Select(r => r.Service).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var missing  = _rules.Count(r => r.ProgramMissing);
            _count.Text = $"{_shown.Count} of {_rules.Count} rules · {services} services" +
                          (missing > 0 ? $" · {missing} with the program missing" : "") +
                          $" · {HardSummary()}" +
                          (_problems.Count > 0 ? $" · not read: {string.Join("; ", _problems)}" : "");
        }

        // Every hard permit on the machine, from any provider: the count that answers "can
        // anything get past my rules", whether or not it belongs to a rule listed here.
        private string HardSummary()
        {
            if (_hardPermits == null) return "hard permits: unknown (filtering engine not read)";
            if (_hardPermits.Count == 0) return "no hard permit anywhere on this machine";
            var ranks = _hardPermits.Select(f => ServiceHardening.Outranks(f, _firewall)).ToList();
            var above = ranks.Count(x => x == ServiceHardening.HardRank.Above);
            var other = ranks.Count(x => x == ServiceHardening.HardRank.OtherLayer);
            var unknown = ranks.Count(x => x == ServiceHardening.HardRank.Unknown);
            return $"{_hardPermits.Count} hard permit{(_hardPermits.Count == 1 ? "" : "s")} on this machine (all providers): " +
                   $"{above} above your rules' sublayer, {other} in other layers" + (unknown > 0 ? $", {unknown} not comparable" : "");
        }

        // ── Copy for AI ──────────────────────────────────────────────────────
        // The rules in view by service, with the facts a reader can't get from the names alone:
        // how these rules combine with the firewall's, which are hard, which programs are gone,
        // and who may run each program.
        private void CopyForAi()
        {
            if (_shown.Count == 0) { ShowMessage("No rules in view to copy."); return; }

            var os = OsInfo.Describe();
            var hard = HardSummary();
            var sb = new StringBuilder();
            sb.AppendLine($"# Windows service hardening rules — {DateTime.Now:yyyy-MM-dd HH:mm}");
            sb.AppendLine();
            sb.AppendLine("Context for the reader:");
            sb.AppendLine($"- Read with: Firewall Rule Manager {BuildInfo.AppVersion}, from Get-NetFirewallRule -PolicyStore StaticServiceStore and ConfigurableServiceStore, and the live filters in Windows' filtering engine (WFP).");
            sb.AppendLine($"- Machine: {os.Title}, {os.Detail}.");
            sb.AppendLine("- These rules are separate from the firewall policy and local rules. Static ones ship with Windows; Configurable ones are added by services such as Defender. Merge off, purging local rules and this app's lock-down don't change them.");
            sb.AppendLine("- How they combine: they sit in their own WFP sublayer. A block from any sublayer wins, unless a hard permit in a higher-weight sublayer comes first (see Hard). So unless one of these rules is hard and outranks the firewall's rules, a service gets out only where these rules AND the firewall's rules both allow it.");
            sb.AppendLine("- Hard: within one WFP layer, sublayers are asked in order of weight and a block from any of them normally wins. A permit with the \"clear action right\" flag is hard: blocks from lower-weight sublayers of the same layer can't override it. " +
                          "\"HARD, above yours\" = a hard permit in a sublayer that outranks the one holding the firewall's rules, in a layer where those rules have filters, so it could get through where they block; \"HARD, not above\" = hard, but the firewall's blocks still win; " +
                          "\"HARD, other layer\" = a hard permit, but in a layer where the firewall's rules have no filters, so it neither competes with them nor gets past them. " +
                          "\"HARD\" = hard, but the firewall rules' sublayer couldn't be found or ranked against it; \"soft\" = a normal permit; \"block\" = a block, which can stop the service even where the firewall's rules allow it; \"no own filter\" = an enabled block with no live filter under its name; Windows may carry it out through filters not named after it (for services it typically does), which the app doesn't try to identify; a block can't let anything past the firewall's rules either way; \"no filter\" = nothing live under that name and action; \"?\" = the rule has no name, so its filters can't be found, or the filtering engine couldn't be read; \"not parsed\" = Windows' own tools return the rule without name or conditions because of a non-standard spelling, so its fields were read from its registry string (given below the rule); if no live filter carries its name, Windows likely doesn't apply it; \"*\" = several rules share the name, so the verdict covers all of them. Filters are matched to rules by name and action. " +
                          "No hard permit has turned up in normal use on Windows 10, 11 or Server 2019. The verdicts were checked against test filters on Windows 10 22H2.");
            sb.AppendLine(_firewall != null
                ? $"- The firewall's rules sit in sublayer {_firewall.Name} (weight {_firewall.Weight})."
                : "- The firewall rules' sublayer couldn't be found, so hard permits can't be ranked against it.");
            sb.AppendLine($"- {char.ToUpperInvariant(hard[0])}{hard[1..]}.");
            if (_hardPermits is { Count: > 0 })
            {
                foreach (var g in _hardPermits.GroupBy(f => (f.Provider, f.SubLayerName, f.SubLayerWeight, Rank: ServiceHardening.Outranks(f, _firewall)))
                                              .OrderByDescending(g => g.Key.SubLayerWeight).ThenBy(g => g.Key.Rank))
                {
                    sb.AppendLine($"  - {g.Count()}× provider {(g.Key.Provider.Length > 0 ? g.Key.Provider : "none")}, sublayer {g.Key.SubLayerName} (weight {g.Key.SubLayerWeight})" +
                                  g.Key.Rank switch
                                  {
                                      ServiceHardening.HardRank.Above      => ", ABOVE the firewall's rules",
                                      ServiceHardening.HardRank.NotAbove   => ", not above the firewall's rules",
                                      ServiceHardening.HardRank.OtherLayer => ", in a layer where the firewall's rules have no filters",
                                      _                                    => "",
                                  } +
                                  ": " + string.Join("; ", g.Take(10).Select(f => { var n = ForAi(f.Name); return $"\"{n.Shown}\"{n.Note} ({f.Id})"; })) +
                                  (g.Count() > 10 ? $"; … {g.Count() - 10} more" : ""));
                }
            }
            sb.AppendLine("- A rule shown off (Enabled False) has no live filter after a restart.");
            sb.AppendLine("- \"Program missing\" = the rule's program file isn't on this machine: left over from an old install or a moved path.");
            sb.AppendLine("- \"Can run the file\" = the accounts whose file permissions allow executing the program; \"denied\" = execute denied. It says who can start the file, not who a rule applies to: a rule for a service matches that service's identity only. svchost.exe hosts many services, so taking away its execute rights would stop all of them; a single service is stopped by disabling that service.");
            if (_problems.Count > 0) sb.AppendLine($"- Not read: {string.Join("; ", _problems)}.");
            if (FilterSummary() is { Length: > 0 } filters) sb.AppendLine($"- Filtered: {_shown.Count} of {_rules.Count} rules ({filters}).");
            sb.AppendLine();
            sb.AppendLine("Please explain what each service is, whether its rules matter on a machine locked down like this, which rules look stale, " +
                          "whether any hard permit deserves a closer look, and for programs that are not svchost.exe, whether who can run the file deserves a closer look.");
            sb.AppendLine();

            // Each program file once: svchost.exe alone appears under dozens of services.
            sb.AppendLine("## Program files");
            foreach (var file in _shown.Where(r => r.Program != "Any")
                                       .GroupBy(r => Environment.ExpandEnvironmentVariables(r.Program), StringComparer.OrdinalIgnoreCase))
            {
                var first = file.First();
                var path = ForAi(file.Key);
                sb.AppendLine($"- {path.Shown}{path.Note}" + (first.ProgramMissing ? " (program missing)"
                    : first.CanRun == "?" ? $" · can run the file: unknown ({first.UnusualWhat})"
                    : first.CanRun.Length > 0 ? $" · can run the file: {first.CanRun}" + (first.UnusualWhat.Length > 0 ? $" ({first.UnusualWhat})" : "") : ""));
            }
            sb.AppendLine();

            foreach (var service in _shown.GroupBy(r => r.Service, StringComparer.OrdinalIgnoreCase))
            {
                sb.AppendLine(service.Key.Equals("Any", StringComparison.OrdinalIgnoreCase)
                    ? "## No service (rules for a program)" : $"## {service.Key}");
                foreach (var program in service.GroupBy(r => r.Program, StringComparer.OrdinalIgnoreCase))
                {
                    var path = ForAi(program.Key);
                    sb.AppendLine($"- Program: {path.Shown}{path.Note}" + (program.First().ProgramMissing ? " (program missing)" : ""));
                    foreach (var r in program)
                    {
                        var name = r.Name.Length > 0 ? ForAi(r.Name) : (Shown: "(no name)", Note: "");
                        var ports = (r.RemotePorts == "Any" ? "" : $" port {r.RemotePorts}") + (r.LocalPorts == "Any" ? "" : $", local port {r.LocalPorts}");
                        sb.AppendLine($"  - {r.Direction} · {r.Action} · {(r.Enabled ? "on" : "off")} · hard: {r.Hard}{(r.HardNote.Length > 0 ? $" — {r.HardNote}" : "")} · {r.Protocol}{ports} · remote {r.Remote} · {r.Store} · \"{name.Shown}\"{name.Note}");
                        if (r.Unparsed) sb.AppendLine($"    registry ({r.Store}, value {r.Id}): {r.RawRule}");
                    }
                }
                sb.AppendLine();
            }

            try
            {
                Clipboard.SetText(sb.ToString());
                ShowMessage($"Copied {_shown.Count} rules for pasting into an AI chat.");
            }
            catch (Exception ex) { ShowMessage($"Couldn't copy: {ex.Message} Try again."); }
        }

        // A name or path as shown, and what a reader can't see in it, for the copy's reader:
        // " (hidden characters: ZWSP (U+200B), …)", any look-alike letters after them; "" when clean.
        private static (string Shown, string Note) ForAi(string text)
        {
            var (shown, findings) = TextHygiene.Reveal(text);
            if (findings.Count == 0) return (text, "");
            var hidden = text.EnumerateRunes().Select(TextHygiene.Hidden).OfType<string>().Distinct().ToList();
            var parts = findings.Where(f => !hidden.Contains(f)).ToList();
            if (hidden.Count > 0) parts.Insert(0, $"hidden characters: {string.Join(", ", hidden)}");
            return (shown, $" ({string.Join("; ", parts)})");
        }
    }
}
