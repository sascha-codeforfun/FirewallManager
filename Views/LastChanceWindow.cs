using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Threading;
using HueThemeKit;

namespace FirewallManager
{
    /// <summary>
    /// The last question before a change cuts the operator's Remote Desktop session with no
    /// rule for it (see MergeOffGuard). It is the only question where no rule can be offered (a
    /// tunnel, a VPN adapter, the operator's own rule going); otherwise the operator has clicked
    /// past one warning already, and a second that looks like it gets clicked past the same
    /// way. So this one looks like no other dialog: wide, a red frame, large text, the facts
    /// one per line, the answers stacked and spelled out with the safe
    /// one on top. Esc and closing the window are the safe answer, nothing answers Enter, and
    /// PROCEED arms only after a few seconds, so a click already on its way lands on nothing.
    /// </summary>
    internal sealed class LastChanceWindow : Window
    {
        private const int ArmSeconds = 3;

        /// <summary>True only when PROCEED was clicked.</summary>
        public bool Proceed { get; private set; }

        private readonly DispatcherTimer _arm = new() { Interval = TimeSpan.FromSeconds(ArmSeconds) };

        /// <summary>
        /// Shows the window; true only for PROCEED. Call on the UI thread. <paramref name="clients"/>
        /// (with the ports they are connected on), <paramref name="tunnel"/> (the ports a tunnel
        /// arrives on), <paramref name="vpnAdapters"/> (the VPN or tunnel adapters the session comes
        /// in on) and, for RuleRemoved, <paramref name="rules"/> (the rules that let the clients in
        /// now): any may be empty. Without network clients the heading says "can cut", since the
        /// cut can't be told from here, only that it can happen. <paramref name="failsafe"/>: the
        /// change runs with the failsafe after PROCEED (Lock down), so "No failsafe" isn't said.
        /// For RuleRemoved: <paramref name="removal"/> says what happens to the rules ("RDP-51-IN is
        /// switched off"); <paramref name="others"/>: other sessions stay connected, so the cut one
        /// may not be this one, and the window names it by its address instead. <paramref name="note"/>:
        /// one more fact line, e.g. what the safe answer does when there is no question to go back to.
        /// </summary>
        public static bool Ask(Window owner, GuardChange change, IReadOnlyList<string> clients, IReadOnlyList<int> ports,
                               IReadOnlyList<int> tunnel, IReadOnlyList<string>? vpnAdapters = null, IReadOnlyList<string>? rules = null,
                               bool failsafe = false, string? removal = null, bool others = false, string? note = null)
        {
            var w = new LastChanceWindow(owner, change, clients, ports, tunnel, vpnAdapters, rules, failsafe, removal, others, note);
            w.ShowDialog();
            return w.Proceed;
        }

        public LastChanceWindow(Window owner, GuardChange change, IReadOnlyList<string> clients, IReadOnlyList<int> ports,
                                IReadOnlyList<int> tunnel, IReadOnlyList<string>? vpnAdapters = null, IReadOnlyList<string>? rules = null,
                                bool failsafe = false, string? removal = null, bool others = false, string? note = null)
        {
            vpnAdapters ??= Array.Empty<string>();
            rules ??= Array.Empty<string>();
            var words = GuardWords.Of(change);
            var many = clients.Count > 1;
            var from = MergeOffGuard.JoinWords(clients);
            // Several of the app's rules going: the heading names them so.
            var what = change == GuardChange.RuleRemoved && rules.Count > 1 ? "Removing these rules" : words.Change;
            // With other sessions staying, the one cut is named by its address, not called this one.
            var notOurs = change == GuardChange.RuleRemoved && others && clients.Count > 0;
            var heading = notOurs ? $"{what} cuts the Remote Desktop {(many ? "sessions" : "session")} from {from}"
                        : clients.Count > 0 ? $"{what} cuts this session" : $"{what} can cut this session";
            SetResourceReference(StyleProperty, "Hue.Window");
            HueTitleBar.Attach(this);
            Owner = owner;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ShowInTaskbar = false;
            // The changes that offer a rule first keep "without a rule"; the others offer none.
            Title = change is GuardChange.LockDown or GuardChange.RuleRemoved or GuardChange.OutboundBlock
                ? heading : $"{words.Change} without a rule";
            Width = 720;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;

            var stack = new StackPanel();

            var band = new Border { Padding = new Thickness(26, 20, 26, 18) }.Ref(Border.BackgroundProperty, "Brush.ErrorSoft");
            band.Child = new TextBlock
            {
                Text = heading,
                FontSize = 28, FontWeight = FontWeights.Bold, TextWrapping = TextWrapping.Wrap
            }.Ref(TextBlock.ForegroundProperty, "Brush.ErrorText");
            stack.Children.Add(band);

            var body = new StackPanel { Margin = new Thickness(26, 20, 26, 22) };
            if (clients.Count > 0)
            {
                var connected = Fact();
                connected.Inlines.Add(new Run(notOurs ? (many ? "Remote Desktop sessions from " : "A Remote Desktop session from ")
                                                      : "You are connected over Remote Desktop from "));
                connected.Inlines.Add(new Run(from) { FontWeight = FontWeights.Bold });
                connected.Inlines.Add(new Run(notOurs ? (many ? " are connected, on TCP " : " is connected, on TCP ") : ", on TCP "));
                connected.Inlines.Add(new Run(MergeOffGuard.JoinWords(ports.Select(p => p.ToString()).ToList())) { FontWeight = FontWeights.Bold });
                connected.Inlines.Add(new Run("."));
                body.Children.Add(connected);
                if (change == GuardChange.RuleRemoved && !string.IsNullOrEmpty(removal))
                    body.Children.Add(Fact($"Nothing of yours created in this app lets {(many ? "these addresses" : "this address")} in once {removal}."));
                else
                    body.Children.Add(Fact(many ? "Nothing of yours created in this app lets these addresses in." : "Nothing of yours created in this app lets this address in."));
            }
            if (tunnel.Count > 0)
            {
                body.Children.Add(Fact(MergeOffGuard.TunnelFact(tunnel)));
                body.Children.Add(Fact(MergeOffGuard.TunnelNoRule));
            }
            if (vpnAdapters.Count > 0)
                body.Children.Add(Fact(MergeOffGuard.VpnFact(vpnAdapters, change)));
            if (LocalConsole.NoneAttached() == true)
                body.Children.Add(Fact("No screen, keyboard or mouse is attached to this machine."));
            // The owner's drop line speaks of this session; a session that may be someone else's is "that" one.
            body.Children.Add(Fact(notOurs
                ? $"Count on {(many ? "those sessions" : "that session")} dropping the moment the {(rules.Count > 1 ? "rules go" : "rule goes")}."
                : words.Drop));
            if (!failsafe) body.Children.Add(Fact("No failsafe: nothing puts the firewall back."));
            if (note != null) body.Children.Add(Fact(note));

            // The safe answer on top; Esc clicks it.
            var stay = Answer(new TextBlock { Text = "I RECONSIDERED AND DO NOT WANT TO LOCK MYSELF OUT" }, "Hue.Button.Primary");
            stay.IsCancel = true;
            stay.Margin = new Thickness(0, 14, 0, 10);
            stay.Click += (_, _) => Close();
            body.Children.Add(stay);

            // Taking down one's own way in when done is a legitimate end, not only a risk taken.
            var statement = new Run(change == GuardChange.RuleRemoved ? "I AM DONE HERE AND CUT MYSELF OUT" : "I CAN DIRECTLY ACCESS THE MACHINE");
            var proceedText = new TextBlock();
            proceedText.Inlines.Add(new Run("THAT IS FINE "));
            proceedText.Inlines.Add(statement);
            proceedText.Inlines.Add(new Run(" PROCEED"));
            var proceed = Answer(proceedText, "Hue.Button");
            proceed.IsEnabled = false;
            // Amber only once it can be clicked: while greyed it reads as greyed.
            proceed.IsEnabledChanged += (_, _) =>
            {
                if (proceed.IsEnabled) statement.SetResourceReference(TextElement.ForegroundProperty, "Brush.WarnText");
                else statement.ClearValue(TextElement.ForegroundProperty);
            };
            proceed.Click += (_, _) => { Proceed = true; Close(); };
            body.Children.Add(proceed);
            stack.Children.Add(body);

            var frame = new Border { BorderThickness = new Thickness(3), Child = stack }.Ref(Border.BorderBrushProperty, "Brush.ErrorEdge");
            Content = frame;

            // Counted from when the window is on screen, not from when it was built.
            _arm.Tick += (_, _) => { _arm.Stop(); proceed.IsEnabled = true; };
            ContentRendered += (_, _) => _arm.Start();
            Closed += (_, _) => _arm.Stop();
        }

        private static TextBlock Fact(string? text = null)
        {
            var line = new TextBlock { FontSize = 17, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) }
                .Ref(TextBlock.ForegroundProperty, "Brush.Text");
            if (text != null) line.Text = text;
            return line;
        }

        // Full width, one sentence, no Enter default.
        private static Button Answer(TextBlock text, string style)
        {
            text.TextWrapping = TextWrapping.Wrap;
            text.TextAlignment = TextAlignment.Center;
            return new Button
            {
                Content = text,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                MinHeight = 54,
                Padding = new Thickness(16, 10, 16, 10),
                FontSize = 16,
                FontWeight = FontWeights.SemiBold,
            }.Styled(style);
        }
    }
}
