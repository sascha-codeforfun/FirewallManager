using System.Windows;
using System.Windows.Input;

namespace FirewallManager
{
    public partial class InputDialog : Window
    {
        public string Value => InputBox.Text;

        public InputDialog(string title, string prompt)
        {
            InitializeComponent();
            Title        = title;
            Prompt.Text  = prompt;
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
