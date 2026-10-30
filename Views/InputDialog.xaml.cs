using System.Windows;
using System.Windows.Input;

using HueThemeKit;

namespace FirewallManager
{
    public partial class InputDialog : Window
    {
        public string Value => InputBox.Text;

        public InputDialog(string title, string prompt, string initial = "")
        {
            InitializeComponent();
            HueTitleBar.Attach(this);
            Title        = title;
            Prompt.Text  = prompt;
            InputBox.Text = initial;
            InputBox.SelectAll();
            InputBox.Focus();
        }

        private void BtnOK_Click    (object s, RoutedEventArgs e) { DialogResult = true;  Close(); }
        private void BtnCancel_Click(object s, RoutedEventArgs e) { DialogResult = false; Close(); }
        private void InputBox_KeyDown(object s, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)  { DialogResult = true;  Close(); }
            if (e.Key == Key.Escape) { DialogResult = false; Close(); }
        }
    }
}
