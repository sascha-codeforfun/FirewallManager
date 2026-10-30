using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using HueThemeKit;

namespace FirewallManager
{
    /// <summary>
    /// After a change made over Remote Desktop with a failsafe (Lock down, a Remote Desktop rule
    /// in Setup, or a change the session guard stands in front of, with a Remote Desktop rule
    /// written first: merge off, inbound block, firewall on, the start-up move):
    /// the user reconnects to prove the new rule works, then keeps the change. Without Keep in
    /// time, the caller restores.
    /// Closing the window is not an answer; only Keep, Restore now or the timeout end it.
    /// </summary>
    public sealed class LockdownCountdownWindow : Window
    {
        public bool Kept { get; private set; }

        private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
        // Measured, not read off the clock: a time sync or a clock set by hand during the
        // countdown would otherwise end it early, or stretch it.
        private readonly Stopwatch _elapsed = Stopwatch.StartNew();
        private readonly TimeSpan _length;
        private readonly TextBlock _count;
        private bool _decided;

        /// <param name="heading">The question, as title and heading.</param>
        /// <param name="closing">A last sentence after the failsafe's explanation; null for none.</param>
        public LockdownCountdownWindow(Window owner, string situation, int seconds, DateTime backstopAt,
                                       string heading = "Keep the lock-down?",
                                       string? closing = "The logging stays on either way.")
        {
            SetResourceReference(StyleProperty, "Hue.Window");
            HueTitleBar.Attach(this);
            Owner = owner;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ShowInTaskbar = false;
            Title = heading;
            Width = 560;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            _length = TimeSpan.FromSeconds(seconds);

            var stack = new StackPanel { Margin = new Thickness(22, 18, 22, 18) };
            stack.Children.Add(new TextBlock { Text = heading, Margin = new Thickness(0, 0, 0, 8) }.Styled("Text.Heading"));
            stack.Children.Add(new TextBlock
            {
                Text =
                    situation + "\n\n" +
                    "Without Keep, this window puts the firewall back as it was when the time runs out. " +
                    $"Should this app be gone by then, a one-time scheduled task (\"{Lockdown.BackstopTask}\") " +
                    $"does it at {backstopAt:HH:mm:ss}. Keep removes that task." +
                    (closing != null ? " " + closing : ""),
                Margin = new Thickness(0, 0, 0, 14)
            }.Styled("Text.Body"));

            _count = new TextBlock { Margin = new Thickness(0, 0, 0, 18) }.Styled("Text.Heading");
            stack.Children.Add(_count);

            var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var restore = new Button { Content = "Restore now", Margin = new Thickness(0, 0, 8, 0) };
            var keep = new Button { Content = "Keep" }.Styled("Hue.Button.Primary");
            restore.Click += (_, _) => Decide(false);
            keep.Click += (_, _) => Decide(true);
            row.Children.Add(restore);
            row.Children.Add(keep);
            stack.Children.Add(row);
            Content = stack;

            _timer.Tick += (_, _) => Tick();
            Loaded += (_, _) => { Tick(); _timer.Start(); };
            Closing += (_, e) => { if (!_decided) e.Cancel = true; };
        }

        private void Tick()
        {
            var left = (int)Math.Ceiling((_length - _elapsed.Elapsed).TotalSeconds);
            if (left <= 0) { Decide(false); return; }
            _count.Text = $"{left} s left";
        }

        private void Decide(bool keep)
        {
            if (_decided) return;
            _decided = true;
            _timer.Stop();
            Kept = keep;
            Close();
        }
    }
}
