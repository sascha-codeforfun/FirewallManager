using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;

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
            public Brush  Color   { get; set; } = Brushes.White;
        }

        public ExePickerWindow(List<string> paths, string currentPath)
        {
            InitializeComponent();

            var items = new List<PickerItem>();
            foreach (var p in paths)
            {
                var isSubMatch = p.Equals(currentPath, System.StringComparison.OrdinalIgnoreCase)
                    || p.Contains(System.IO.Path.GetDirectoryName(currentPath) ?? "@@@@");

                // Check if the sub-path portion matches (e.g. \app\Claude.exe)
                var exeName = System.IO.Path.GetFileName(currentPath);
                var subDir  = System.IO.Path.GetDirectoryName(currentPath);
                var subName = subDir != null ? System.IO.Path.GetFileName(subDir) : "";
                var hasSubPathMatch = p.Contains($@"\{subName}\{exeName}",
                    System.StringComparison.OrdinalIgnoreCase);

                items.Add(new PickerItem
                {
                    Path    = p,
                    Display = hasSubPathMatch ? $"★  {System.IO.Path.GetFileName(p)}" : System.IO.Path.GetFileName(p),
                    Weight  = hasSubPathMatch ? "SemiBold" : "Normal",
                    Color   = hasSubPathMatch
                        ? new SolidColorBrush(Color.FromRgb(0x34, 0xd3, 0x99))
                        : new SolidColorBrush(Color.FromRgb(0xe5, 0xe7, 0xeb))
                });
            }

            PathList.ItemsSource = items;
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
