using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using HueThemeKit;

namespace FirewallManager
{
    // In-app message dialog, used instead of the system MessageBox, which ignores the theme.
    // Confirm delegates to the kit's HueConfirm.Ask; Info, YesNoCancel, TwoWay, Gate, CreateOnOrOff
    // and UnexpectedError, which the kit lacks, are a small Hue.Window built here. Esc gives the cancel-side answer. Monospace messages
    // (command output) show in a read-only text box so they can be selected and copied.
    public class ThemedDialog : Window
    {
        private enum Kind { Neutral, Primary, Danger }

        private readonly record struct Choice(string Text, int Id, Kind Kind, bool IsCancel);

        private int _result;

        private ThemedDialog(Window? owner, string title, string message, bool danger,
                             bool monospace, int cancelResult, params Choice[] choices)
        {
            SetResourceReference(StyleProperty, "Hue.Window");
            HueTitleBar.Attach(this);

            _result = cancelResult;   // closing any other way counts as cancel

            if (owner != null)
            {
                Owner = owner;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;
                ShowInTaskbar = false;
            }
            else
            {
                WindowStartupLocation = WindowStartupLocation.CenterScreen;
            }

            Title = title;
            Width = monospace ? 620 : 460;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;

            var stack = new StackPanel { Margin = new Thickness(22, 18, 22, 18) };

            var heading = new TextBlock
            {
                Text = title, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8)
            }.Styled("Text.Heading");
            // Danger prompts say so in words (the button reads "Delete", "Replace"...);
            // the heading takes the error text colour on top of that.
            if (danger) heading.Ref(TextBlock.ForegroundProperty, "Brush.ErrorText");
            stack.Children.Add(heading);

            // A long message scrolls inside a capped area, so the buttons never leave the screen.
            var cap = HueConfirm.MessageMaxHeight(owner);
            if (monospace)
            {
                var box = new TextBox
                {
                    Text = message,
                    IsReadOnly = true,
                    TextWrapping = TextWrapping.Wrap,
                    MaxHeight = cap,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    Margin = new Thickness(0, 0, 0, 18)
                }.Ref(TextBox.FontFamilyProperty, "Font.Mono");
                stack.Children.Add(box);
            }
            else
            {
                // A tab stop only while there is something to scroll.
                var scroll = new ScrollViewer
                {
                    Content = new TextBlock { Text = message }.Styled("Text.Body"),
                    MaxHeight = cap,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                    IsTabStop = false,
                    Margin = new Thickness(0, 0, 0, 18)
                };
                scroll.ScrollChanged += (_, _) => scroll.IsTabStop = scroll.ScrollableHeight > 0;
                stack.Children.Add(scroll);
            }

            var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            for (int i = 0; i < choices.Length; i++)
            {
                var c = choices[i];
                var btn = new Button
                {
                    Content = c.Text,
                    Margin = new Thickness(i == 0 ? 0 : 8, 0, 0, 0),
                    IsCancel = c.IsCancel,
                    // Enter confirms only on non-destructive prompts.
                    IsDefault = c.Kind == Kind.Primary && !danger
                };
                if (c.Kind == Kind.Primary)
                    btn.Styled(danger ? "Hue.Button.Danger" : "Hue.Button.Primary");
                else if (c.Kind == Kind.Danger)
                    btn.Styled("Hue.Button.Danger");
                int id = c.Id;
                btn.Click += (_, __) => { _result = id; Close(); };
                row.Children.Add(btn);
            }
            stack.Children.Add(row);

            Content = stack;
        }

        private int Run()
        {
            ShowDialog();
            return _result;
        }

        /// <summary>Two-button confirm, via the kit's HueConfirm: Cancel has the focus and answers
        /// Enter and Escape. True only if the confirm button was clicked.</summary>
        public static bool Confirm(Window? owner, string title, string message,
                                   string confirmText = "Continue", bool danger = false)
            => HueConfirm.Ask(owner, title, message, confirmText, destructive: danger);

        /// <summary>Three-way choice. True = yes, false = no, null = cancelled.</summary>
        public static bool? YesNoCancel(Window? owner, string title, string message,
                                        string yesText = "Yes", string noText = "No",
                                        bool danger = false)
        {
            var d = new ThemedDialog(owner, title, message, danger, monospace: false, cancelResult: -1,
                new Choice("Cancel", -1, Kind.Neutral, IsCancel: true),
                new Choice(noText, 0, Kind.Neutral, IsCancel: false),
                new Choice(yesText, 1, Kind.Primary, IsCancel: false));
            return d.Run() switch { 1 => true, 0 => false, _ => null };
        }

        /// <summary>
        /// Two plain choices, neither preferred: true = first, false = second, null = closed
        /// (X or Esc). Both look alike and neither answers Enter, so the answer is a deliberate click.
        /// </summary>
        public static bool? TwoWay(Window? owner, string title, string message, string firstText, string secondText)
        {
            var d = new ThemedDialog(owner, title, message, danger: false, monospace: false, cancelResult: -1,
                new Choice(firstText, 1, Kind.Neutral, IsCancel: false),
                new Choice(secondText, 0, Kind.Neutral, IsCancel: false));
            // Neither button is the cancel side, so Esc closes the window itself.
            d.PreviewKeyDown += (_, e) =>
            {
                if (e.Key != Key.Escape) return;
                e.Handled = true;
                d.Close();
            };
            return d.Run() switch { 1 => true, 0 => false, _ => null };
        }

        /// <summary>
        /// A gate: agree to go on, or close the app. Wider than the other dialogs (the text
        /// explains what will be written and why); neither button answers Enter, so it takes a
        /// deliberate click. Closing the window counts as closing the app.
        /// </summary>
        public static bool Gate(Window? owner, string title, string message,
                                string agreeText = "AGREE", string closeText = "CLOSE APP")
        {
            var d = new ThemedDialog(owner, title, message, danger: false, monospace: false, cancelResult: 0,
                new Choice(closeText, 0, Kind.Neutral, IsCancel: true),
                new Choice(agreeText, 1, Kind.Primary, IsCancel: false));
            d.Width = 640;
            if (d.Content is StackPanel s && s.Children[s.Children.Count - 1] is StackPanel row)
                foreach (var b in row.Children.OfType<Button>()) b.IsDefault = false;
            return d.Run() == 1;
        }

        /// <summary>
        /// A gate with only one way out: the app can't run, so the one button closes it. No Enter
        /// default; Esc and the window's close button count the same.
        /// </summary>
        public static void Stop(Window? owner, string title, string message, string closeText = "CLOSE APP")
        {
            var d = new ThemedDialog(owner, title, message, danger: false, monospace: false, cancelResult: 0,
                new Choice(closeText, 0, Kind.Neutral, IsCancel: true));
            d.Width = 640;
            d.Run();
        }

        /// <summary>
        /// Create a missing rule switched on or off. True = on, false = off, null = cancelled.
        /// Off is the default (Enter), being the safe side; on is red when it opens something up.
        /// </summary>
        public static bool? CreateOnOrOff(Window? owner, string title, string message, bool onIsRisky)
        {
            var d = new ThemedDialog(owner, title, message, danger: false, monospace: false, cancelResult: -1,
                new Choice("Cancel", -1, Kind.Neutral, IsCancel: true),
                new Choice("Create on", 1, onIsRisky ? Kind.Danger : Kind.Neutral, IsCancel: false),
                new Choice("Create off", 0, Kind.Primary, IsCancel: false));
            return d.Run() switch { 1 => true, 0 => false, _ => null };
        }

        /// <summary>An error nobody foresaw, its details selectable. True = continue, false = close the app.</summary>
        public static bool UnexpectedError(Window? owner, string message)
        {
            var d = new ThemedDialog(owner, "Unexpected error", message, danger: false, monospace: true, cancelResult: 1,
                new Choice("Close app", 0, Kind.Neutral, IsCancel: false),
                new Choice("Continue", 1, Kind.Primary, IsCancel: true));
            d.MarkError();
            return d.Run() == 1;
        }

        /// <summary>An error nobody foresaw before the main window showed: there is nothing to continue in.</summary>
        public static void UnexpectedErrorAtStart(string message)
        {
            var d = new ThemedDialog(null, "Unexpected error", message, danger: false, monospace: true, cancelResult: 0,
                new Choice("Close app", 0, Kind.Primary, IsCancel: true));
            d.MarkError();
            d.Run();
        }

        /// <summary>Single-button notice. Use monospace for tabular command output.</summary>
        public static void Info(Window? owner, string title, string message,
                                bool danger = false, bool monospace = false)
        {
            // A notice has nothing destructive to confirm: its OK is always a plain primary.
            var d = new ThemedDialog(owner, title, message, danger: false, monospace, cancelResult: 0,
                new Choice("OK", 0, Kind.Primary, IsCancel: true));
            if (danger) d.MarkError();
            d.Run();
        }

        // Error notices keep the red heading without turning OK into a Danger button.
        private void MarkError()
        {
            if (Content is StackPanel { Children.Count: > 0 } s && s.Children[0] is TextBlock h)
                h.Ref(TextBlock.ForegroundProperty, "Brush.ErrorText");
        }
    }
}
