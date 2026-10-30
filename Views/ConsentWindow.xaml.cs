using System;
using System.Windows;
using Microsoft.Win32;

using HueThemeKit;

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
            HueTitleBar.Attach(this);
        }

        /// <summary>Read-only notice for config.json values that cannot represent any real
        /// address (impossible, not merely risky): names the rejected entries.</summary>
        public ConsentWindow(System.Collections.Generic.List<string> impossible) : this(reviewMode: true)
        {
            Title = "ἸΔΙΩΤΗΣ — impossible values rejected";
            RejectBanner.Visibility = Visibility.Visible;
            RejectText.Text = string.Join("\n", impossible);
        }

        /// <summary>
        /// Review mode: the terms read-only, with both oaths checked and locked.
        /// Nothing is recorded.
        /// </summary>
        public ConsentWindow(bool reviewMode) : this()
        {
            if (!reviewMode) return;

            _reviewMode = true;
            Title = "ἸΔΙΩΤΗΣ — the terms you accepted";

            ChkNotIdiotes.IsChecked = true;      ChkNotIdiotes.IsEnabled = false;
            ChkResponsibility.IsChecked = true;  ChkResponsibility.IsEnabled = false;

            BtnDecline.Visibility = Visibility.Collapsed;
            BtnProceed.Content = "Close";
            BtnProceed.IsEnabled = true;
        }

        private bool _reviewMode;

        /// <summary>True when the stored consent is for the current version or later.</summary>
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
            if (_reviewMode) { Close(); return; }   // review mode records nothing

            try
            {
                using var k = Registry.CurrentUser.CreateSubKey(RegPath);
                k?.SetValue("ConsentVersion", ConsentVersion, RegistryValueKind.DWord);
            }
            catch { /* not persisted: the consent is shown again next launch */ }

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
