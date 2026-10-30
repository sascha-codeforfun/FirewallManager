using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

using HueThemeKit;

namespace FirewallManager
{
    public partial class ConfigReconcileWindow : Window
    {
        public Dictionary<ConfigService.Section, bool> Decisions { get; } = new();

        private readonly Dictionary<ConfigService.Section, RadioButton> _useJsonRadios = new();

        public ConfigReconcileWindow(List<ConfigService.Section> differing,
                                     Dictionary<ConfigService.Section, bool> current)
        {
            InitializeComponent();
            HueTitleBar.Attach(this);

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
                Padding = new Thickness(16, 12, 16, 12),
                Margin = new Thickness(0, 0, 0, 8)
            }.Styled("Hue.Card");

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var label = new StackPanel();
            label.Children.Add(new TextBlock { Text = SectionTitle(s) }.Styled("Text.Heading"));

            // Prominent: name exactly what changed in this section.
            var changed = ConfigService.ChangedEntries(s);
            if (changed.Count > 0)
            {
                label.Children.Add(new TextBlock
                {
                    Text = "changed:  " + string.Join(",  ", changed),
                    FontSize = 13, FontWeight = FontWeights.SemiBold,
                    TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 12, 0)
                }.Ref(TextBlock.ForegroundProperty, "Brush.AccentText"));
            }

            label.Children.Add(new TextBlock
            {
                Text = SectionHint(s), TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 3, 12, 0)
            }.Styled("Text.Caption"));
            Grid.SetColumn(label, 0);
            grid.Children.Add(label);

            var choices = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            string group = "grp_" + s;

            var useJson = new RadioButton
            {
                Content = "Use JSON", GroupName = group,
                IsChecked = defaultUseJson, Margin = new Thickness(0, 0, 12, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            var keepHard = new RadioButton
            {
                Content = "Keep built-in", GroupName = group,
                IsChecked = !defaultUseJson,
                VerticalAlignment = VerticalAlignment.Center
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
            ConfigService.Section.EncryptedDns => "Encrypted-DNS servers",
            _ => s.ToString()
        };

        private static string SectionHint(ConfigService.Section s) => s switch
        {
            ConfigService.Section.Noise      => "What the log viewer treats as background noise.",
            ConfigService.Section.DnsPresets => "The resolvers the rule editor's DNS preset offers.",
            ConfigService.Section.Services   => "Public CIDR ranges written into firewall rules (GitHub). Security-relevant.",
            ConfigService.Section.OrgTags    => "IP-prefix → owner labels shown in the log.",
            ConfigService.Section.EncryptedDns => "Known DNS-over-HTTPS/TLS servers: connections and lookups to them are flagged in the log.",
            _ => ""
        };

        private void BtnKeepAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (var key in new List<ConfigService.Section>(Decisions.Keys))
            {
                Decisions[key] = false;
                if (_useJsonRadios.TryGetValue(key, out var rb)) rb.IsChecked = false;
            }
            DialogResult = true;   // an explicit choice; closing any other way leaves the file unapproved
        }

        private void BtnOk_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    }
}
