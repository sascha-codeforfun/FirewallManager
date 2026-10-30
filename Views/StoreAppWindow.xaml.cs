using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;

using HueThemeKit;

namespace FirewallManager
{
    /// <summary>The rule editor's Store app list (see StoreApps): picks the exe a Store app starts.</summary>
    public partial class StoreAppWindow : Window
    {
        public string? SelectedPath { get; private set; }

        public StoreAppWindow()
        {
            InitializeComponent();
            HueTitleBar.Attach(this);
            Loaded += async (_, _) => await FillAsync();
        }

        // Every package's manifest is read: off the window's thread.
        private async Task FillAsync()
        {
            List<StoreApps.App> apps;
            try { apps = await Task.Run(() => StoreApps.List()); }
            catch (Exception ex)
            {
                Reading.Text = $"The installed Store apps couldn't be read: {ex.Message.TrimEnd('.')}.";
                return;
            }
            if (apps.Count == 0)
            {
                Reading.Text = "No Store app that a rule by path can match is installed for this user.";
                return;
            }
            Reading.Visibility = Visibility.Collapsed;
            AppList.ItemsSource = apps;
            AppList.SelectedIndex = 0;
            BtnSelect.IsEnabled = true;
            AppList.Focus();
        }

        private void Choose()
        {
            if (AppList.SelectedItem is not StoreApps.App app) return;
            SelectedPath = app.Exe;
            DialogResult = true;
        }

        private void BtnSelect_Click(object sender, RoutedEventArgs e) => Choose();
        private void AppList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e) => Choose();
        private void BtnCancel_Click(object sender, RoutedEventArgs e) => Close();
    }
}
