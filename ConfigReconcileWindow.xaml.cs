using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FirewallManager
{
    public partial class ConfigReconcileWindow : Window
    {
        public Dictionary<ConfigService.Section, bool> Decisions { get; } = new();

        private readonly Dictionary<ConfigService.Section, RadioButton> _useJsonRadios = new();

        private static readonly Brush Cyan  = new SolidColorBrush(Color.FromRgb(0x22, 0xd3, 0xee));
        private static readonly Brush Amber = new SolidColorBrush(Color.FromRgb(0xfb, 0xbf, 0x24));
        private static readonly Brush Text  = new SolidColorBrush(Color.FromRgb(0xe5, 0xe7, 0xeb));
        private static readonly Brush Dim   = new SolidColorBrush(Color.FromRgb(0x9c, 0xa3, 0xaf));

        public ConfigReconcileWindow(List<ConfigService.Section> differing,
                                     Dictionary<ConfigService.Section, bool> current)
        {
            InitializeComponent();

            foreach (var s in differing)
            {
                bool defaultUseJson = current.TryGetValue(s, out var v) && v;
                Decisions[s] = defaultUseJson;
                SectionsPanel.Children.Add(BuildRow(s, defaultUseJson));
            }
        }

        private UIElement BuildRow(ConfigService.Section s, bool defaultUseJson)
        {
            var border = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x11, 0x18, 0x22)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x1f, 0x29, 0x37)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(14, 10, 14, 10),
                Margin = new Thickness(0, 0, 0, 8)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var label = new StackPanel();
            label.Children.Add(new TextBlock
            {
                Text = SectionTitle(s),
                Foreground = Text, FontWeight = FontWeights.SemiBold, FontSize = 14
            });

            // Prominent: name exactly what changed in this section.
            var changed = ConfigService.ChangedEntries(s);
            if (changed.Count > 0)
            {
                label.Children.Add(new TextBlock
                {
                    Text = "changed:  " + string.Join(",  ", changed),
                    Foreground = Cyan, FontSize = 13, FontWeight = FontWeights.SemiBold,
                    TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 12, 0)
                });
            }

            label.Children.Add(new TextBlock
            {
                Text = SectionHint(s),
                Foreground = Dim, FontSize = 12, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 3, 12, 0)
            });
            Grid.SetColumn(label, 0);
            grid.Children.Add(label);

            var choices = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            string group = "grp_" + s;

            var useJson = new RadioButton
            {
                Content = "Use JSON", GroupName = group, Foreground = Cyan,
                IsChecked = defaultUseJson, Margin = new Thickness(0, 0, 12, 0),
                VerticalAlignment = VerticalAlignment.Center, Cursor = System.Windows.Input.Cursors.Hand
            };
            var keepHard = new RadioButton
            {
                Content = "Keep built-in", GroupName = group, Foreground = Amber,
                IsChecked = !defaultUseJson,
                VerticalAlignment = VerticalAlignment.Center, Cursor = System.Windows.Input.Cursors.Hand
            };

            useJson.Checked  += (_, __) => Decisions[s] = true;
            keepHard.Checked += (_, __) => Decisions[s] = false;

            _useJsonRadios[s] = useJson;

            choices.Children.Add(useJson);
            choices.Children.Add(keepHard);
            Grid.SetColumn(choices, 1);
            grid.Children.Add(choices);

            border.Child = grid;
            return border;
        }

        private static string SectionTitle(ConfigService.Section s) => s switch
        {
            ConfigService.Section.Noise      => "Noise suppression",
            ConfigService.Section.DnsPresets => "DNS presets",
            ConfigService.Section.Services   => "Service IP ranges",
            ConfigService.Section.OrgTags    => "Org-tags (log resolver)",
            _ => s.ToString()
        };

        private static string SectionHint(ConfigService.Section s) => s switch
        {
            ConfigService.Section.Noise      => "What the log viewer treats as background noise.",
            ConfigService.Section.DnsPresets => "The resolver list in the Setup dropdowns.",
            ConfigService.Section.Services   => "Public CIDR ranges written into firewall rules (GitHub, updates). Security-relevant.",
            ConfigService.Section.OrgTags    => "IP-prefix → owner labels shown in the log.",
            _ => ""
        };

        private void BtnKeepAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (var key in new List<ConfigService.Section>(Decisions.Keys))
            {
                Decisions[key] = false;
                if (_useJsonRadios.TryGetValue(key, out var rb)) rb.IsChecked = false;
            }
            Close();
        }

        private void BtnOk_Click(object sender, RoutedEventArgs e) => Close();
    }
}
