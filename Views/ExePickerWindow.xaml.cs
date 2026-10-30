using System.Collections.Generic;
using System.Linq;
using System.Windows;

using HueThemeKit;

namespace FirewallManager
{
    public partial class ExePickerWindow : Window
    {
        public string? SelectedPath { get; private set; }

        private class PickerItem
        {
            public string Path    { get; set; } = "";
            public string Display { get; set; } = "";
            public string Weight  { get; set; } = "Normal";
            public bool   IsBest  { get; set; }
        }

        public ExePickerWindow(List<string> paths, string currentPath)
        {
            InitializeComponent();
            HueTitleBar.Attach(this);

            // The likely match keeps the exe's folder and name (e.g. \app\Claude.exe). An exe directly
            // in its package folder has the version in that folder's name, so there the folder is
            // known by its package name (Microsoft.WindowsTerminal_1.21… and _1.22… are one).
            var exeName = System.IO.Path.GetFileName(currentPath);
            var subDir  = System.IO.Path.GetDirectoryName(currentPath);
            var subName = subDir != null ? System.IO.Path.GetFileName(subDir) : "";
            var package = subDir != null ? RuleEditWindow.PackageName(subDir) : null;

            var items = new List<PickerItem>();
            foreach (var p in paths)
            {
                var hasSubPathMatch = package != null
                    ? System.IO.Path.GetFileName(p).Equals(exeName, System.StringComparison.OrdinalIgnoreCase) &&
                      System.IO.Path.GetDirectoryName(p) is { } dir &&
                      RuleEditWindow.PackageName(dir) is { } name &&
                      name.Equals(package, System.StringComparison.OrdinalIgnoreCase)
                    : p.Contains($@"\{subName}\{exeName}", System.StringComparison.OrdinalIgnoreCase);

                items.Add(new PickerItem
                {
                    Path    = p,
                    Display = hasSubPathMatch ? $"★  {System.IO.Path.GetFileName(p)}" : System.IO.Path.GetFileName(p),
                    Weight  = hasSubPathMatch ? "SemiBold" : "Normal",
                    IsBest  = hasSubPathMatch
                });
            }

            // Likely matches first, as the window text promises; otherwise the callers' order.
            PathList.ItemsSource = items.OrderByDescending(i => i.IsBest).ToList();
            if (items.Count > 0) PathList.SelectedIndex = 0;
        }

        private void BtnSelect_Click(object sender, RoutedEventArgs e)
        {
            if (PathList.SelectedItem is PickerItem item)
            {
                SelectedPath = item.Path;
                DialogResult = true;
                Close();
            }
        }

        private void PathList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (PathList.SelectedItem is PickerItem item)
            {
                SelectedPath = item.Path;
                DialogResult = true;
                Close();
            }
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e) => Close();
    }
}
