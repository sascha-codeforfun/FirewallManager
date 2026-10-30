using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using Path = System.Windows.Shapes.Path;

namespace FirewallManager
{
    /// <summary>
    /// Icon + text content for buttons: a Hue.Icon path, a 6 px gap and the label, built the
    /// same way for every button. XAML sets both attached properties; code calls Set or
    /// SetText. The icon's stroke follows the button's Foreground, so it greys out with the
    /// text when the button is disabled.
    /// </summary>
    public static class IconText
    {
        /// <summary>An Icon.* resource key (AppIcons.xaml or the theme kit).</summary>
        public static readonly DependencyProperty IconProperty = DependencyProperty.RegisterAttached(
            "Icon", typeof(string), typeof(IconText), new PropertyMetadata(null, Changed));

        public static readonly DependencyProperty TextProperty = DependencyProperty.RegisterAttached(
            "Text", typeof(string), typeof(IconText), new PropertyMetadata(null, Changed));

        public static string? GetIcon(DependencyObject d) => (string?)d.GetValue(IconProperty);
        public static void SetIcon(DependencyObject d, string? value) => d.SetValue(IconProperty, value);
        public static string? GetText(DependencyObject d) => (string?)d.GetValue(TextProperty);
        public static void SetText(DependencyObject d, string? value) => d.SetValue(TextProperty, value);

        public static void Set(ContentControl control, string icon, string text)
        {
            SetIcon(control, icon);
            SetText(control, text);
        }

        /// <summary>A 16 px Hue.Icon path for a geometry key.</summary>
        public static Path Glyph(string key)
        {
            var path = new Path().Styled("Hue.Icon");
            path.SetResourceReference(Path.DataProperty, key);
            return path;
        }

        /// <summary>
        /// The same icon at another size. Scaled as a whole, stroke included, so it keeps the
        /// 16 px drawing's proportions.
        /// </summary>
        public static FrameworkElement Glyph(string key, double size) =>
            new Viewbox { Width = size, Height = size, Child = Glyph(key), VerticalAlignment = VerticalAlignment.Center };

        private sealed class Row : StackPanel
        {
            public readonly Path Icon = new Path().Styled("Hue.Icon");
            public readonly TextBlock Label = new() { VerticalAlignment = VerticalAlignment.Center };

            public Row()
            {
                Orientation = Orientation.Horizontal;
                Icon.Margin = new Thickness(0, 0, 6, 0);
                Children.Add(Icon);
                Children.Add(Label);
            }
        }

        // Updates the row in place, so a label that changes often (counts, ✓/✗) doesn't
        // rebuild it. A panel has no text of its own for screen readers: the label names the
        // button unless the button sets its own AutomationProperties.Name.
        private static void Changed(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is not ContentControl control) return;
            if (control.Content is not Row row)
            {
                row = new Row();
                control.Content = row;
                if (AutomationProperties.GetLabeledBy(control) == null)
                    AutomationProperties.SetLabeledBy(control, row.Label);
            }
            var icon = GetIcon(control);
            if (string.IsNullOrEmpty(icon))
            {
                row.Icon.ClearValue(Path.DataProperty);
                row.Icon.Visibility = Visibility.Collapsed;
            }
            else
            {
                row.Icon.SetResourceReference(Path.DataProperty, icon);
                row.Icon.Visibility = Visibility.Visible;
            }
            row.Label.Text = GetText(control) ?? "";
        }
    }
}
