using System.Windows;

namespace FirewallManager
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Hold the app open across the consent dialog. Without this, the consent
            // window is the *only* window, so closing it (even via Proceed) trips
            // ShutdownMode.OnLastWindowClose and the app shuts down before MainWindow
            // ever shows — looks like "won't start", especially under the debugger.
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            // The whole app is a power tool — gate it once, forever, at the door.
            // Looking is free; this consent covers everything inside (Setup, Purge,
            // toggles, DNS disable, rule edits — all of which can do harm).
            if (!ConsentWindow.AlreadyAccepted())
            {
                var consent = new ConsentWindow();
                if (consent.ShowDialog() != true)
                {
                    Shutdown();           // declined → the idiōtēs departs
                    return;
                }
            }

            var main = new MainWindow();
            MainWindow = main;
            ShutdownMode = ShutdownMode.OnMainWindowClose;   // now normal lifetime applies
            main.Show();
        }
    }
}
