using System;
using System.Windows;
using Microsoft.Win32;

namespace FirewallManager
{
    public partial class ConsentWindow : Window
    {
        // Bump this if the warning text materially changes — forces re-acknowledgment.
        private const int ConsentVersion = 1;
        private const string RegPath = @"Software\GeekFirewallManager";

        public ConsentWindow()
        {
            InitializeComponent();
        }

        /// <summary>The bouncer, re-summoned because config.json contained values
        /// that cannot represent any real address (impossible, not merely risky).
        /// Names the offending entries and refuses them. Read-only, just Close.</summary>
        public ConsentWindow(System.Collections.Generic.List<string> impossible) : this(reviewMode: true)
        {
            Title = "ἸΔΙΩΤΗΣ — impossible values rejected";
            RejectBanner.Visibility = Visibility.Visible;
            RejectText.Text = string.Join("\n", impossible);
        }

        /// <summary>
        /// Review mode: re-show the consent read-only — the terms plus the two oaths
        /// shown locked-and-checked (what you swore). For reference / for showing a
        /// complainer what they accepted. No metadata recorded or displayed.
        /// </summary>
        public ConsentWindow(bool reviewMode) : this()
        {
            if (!reviewMode) return;

            _reviewMode = true;
            Title = "ἸΔΙΩΤΗΣ — the terms you accepted";

            // Show the oaths locked-checked: the "you swore this" receipt.
            ChkNotIdiotes.IsChecked = true;      ChkNotIdiotes.IsEnabled = false;
            ChkResponsibility.IsChecked = true;  ChkResponsibility.IsEnabled = false;

            // Just a Close — no re-accepting, nothing recorded.
            BtnDecline.Visibility = Visibility.Collapsed;
            BtnProceed.Content = "Close";
            BtnProceed.IsEnabled = true;
        }

        private bool _reviewMode;

        /// <summary>
        /// Returns true if the user has already accepted the current consent version.
        /// </summary>
        public static bool AlreadyAccepted()
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(RegPath);
                var v = k?.GetValue("ConsentVersion");
                return v is int iv && iv >= ConsentVersion;
            }
            catch { return false; }
        }

        private void Chk_Changed(object sender, RoutedEventArgs e)
        {
            if (_reviewMode) return;
            BtnProceed.IsEnabled =
                ChkNotIdiotes.IsChecked == true &&
                ChkResponsibility.IsChecked == true;
        }

        private void BtnProceed_Click(object sender, RoutedEventArgs e)
        {
            if (_reviewMode) { Close(); return; }   // review: just close, don't re-record

            try
            {
                using var k = Registry.CurrentUser.CreateSubKey(RegPath);
                k?.SetValue("ConsentVersion", ConsentVersion, RegistryValueKind.DWord);
            }
            catch { /* if we can't persist, they'll just see it again next launch — harmless */ }

            DialogResult = true;
            Close();
        }

        private void BtnDecline_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
