using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FirewallManager
{
    // A small app-styled confirm dialog — dark theme, used instead of the harsh
    // default Windows MessageBox for the "you're opening a firewall default" prompts.
    public class ThemedDialog : Window
    {
        private bool _result;

        private ThemedDialog(Window owner, string title, string message, string confirmText, bool danger)
        {
            Owner = owner;
            Title = title;
            Width = 460;
            SizeToContent = SizeToContent.Height;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ResizeMode = ResizeMode.NoResize;
            Background = new SolidColorBrush(Color.FromRgb(0x0a, 0x0e, 0x14));
            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;

            var outer = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x0a, 0x0e, 0x14)),
                BorderBrush = new SolidColorBrush(danger ? Color.FromRgb(0x7f,0x1d,0x1d)
                                                         : Color.FromRgb(0x37,0x41,0x51)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(22, 18, 22, 18)
            };
            var stack = new StackPanel();

            stack.Children.Add(new TextBlock
            {
                Text = title,
                Foreground = new SolidColorBrush(danger ? Color.FromRgb(0xf8,0x71,0x71)
                                                        : Color.FromRgb(0xf9,0xfa,0xfb)),
                FontSize = 15, FontWeight = FontWeights.Bold, Margin = new Thickness(0,0,0,8)
            });
            stack.Children.Add(new TextBlock
            {
                Text = message,
                Foreground = new SolidColorBrush(Color.FromRgb(0xcb,0xd5,0xe1)),
                FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,18)
            });

            var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var cancel = new Button
            {
                Content = "Cancel", Padding = new Thickness(14,7,14,7), Margin = new Thickness(0,0,8,0),
                Background = new SolidColorBrush(Color.FromRgb(0x37,0x41,0x51)),
                Foreground = new SolidColorBrush(Color.FromRgb(0xe5,0xe7,0xeb)),
                BorderThickness = new Thickness(0), Cursor = System.Windows.Input.Cursors.Hand
            };
            var ok = new Button
            {
                Content = confirmText, Padding = new Thickness(14,7,14,7),
                Background = new SolidColorBrush(danger ? Color.FromRgb(0xb9,0x1c,0x1c)
                                                        : Color.FromRgb(0x1d,0x4e,0xd8)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0), Cursor = System.Windows.Input.Cursors.Hand
            };
            cancel.Click += (_, __) => { _result = false; Close(); };
            ok.Click     += (_, __) => { _result = true;  Close(); };

            row.Children.Add(cancel);
            row.Children.Add(ok);
            stack.Children.Add(row);

            outer.Child = stack;
            Content = outer;
        }

        public static bool Confirm(Window owner, string title, string message,
                                   string confirmText = "Continue", bool danger = false)
        {
            var d = new ThemedDialog(owner, title, message, confirmText, danger);
            d.ShowDialog();
            return d._result;
        }
    }
}
