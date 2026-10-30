using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using HueThemeKit;

namespace FirewallManager
{
    public partial class App : Application
    {
        // Held for the app's lifetime: one copy per machine, since every copy writes the same
        // machine-wide policy, failsafe task and backups. Global, so a second Remote Desktop
        // session can't start a lock-down alongside the first.
        private const string InstanceName = @"Global\GeekFirewallManager.Running";
        private static Mutex? _instance;

        // True once the main window is on screen; until then an unexpected error can only close
        // the app, since there is nothing to continue in.
        private bool _mainShown;
        // Set once an error at start has closed the app: what was still running stops there.
        private bool _closingAtStart;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            if (!TakeInstance())
            {
                Shutdown();
                return;
            }

            HueContrast.Follow(this);   // hands colours back to Windows under a contrast theme

            // An error nobody foresaw would otherwise close the app without a word, and during a
            // lock-down that would take the countdown with it.
            DispatcherUnhandledException += OnUnexpectedError;

            // The consent window is the only window at this point, so closing it (even via
            // Proceed) would trip OnLastWindowClose and end the app before MainWindow shows.
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            try
            {
                StartUp();
            }
            catch (Exception ex)
            {
                // Before the main window shows there is nothing to continue in, and the app would
                // otherwise stay running with no window.
                CloseAtStart(ex);
            }
        }

        private void StartUp()
        {
            // One consent, given once, covers everything inside (Setup, Purge, toggles,
            // DNS disable, rule edits), since all of it can do harm.
            if (!ConsentWindow.AlreadyAccepted())
            {
                var consent = new ConsentWindow();
                if (consent.ShowDialog() != true)
                {
                    Shutdown();
                    return;
                }
            }

            // Two conditions make the app show settings Windows doesn't apply. Nothing changes
            // until every question is agreed; declining closes the app, since running on would
            // mean green tiles that aren't true.
            if (!StartupChecks(out var pending))
            {
                Shutdown();
                return;
            }

            // Held-back start-up writes are settled by the main window first, locked, under the
            // session guard (see StartupWrites).
            if (_closingAtStart) return;   // an error during the checks already closed the app
            var main = new MainWindow(pending);
            MainWindow = main;
            ShutdownMode = ShutdownMode.OnMainWindowClose;   // now normal lifetime applies
            main.Show();
            _mainShown = true;
        }

        private void CloseAtStart(Exception ex)
        {
            if (_closingAtStart) return;   // said once
            _closingAtStart = true;
            try
            {
                ThemedDialog.UnexpectedErrorAtStart(
                    "Something went wrong while the app was starting, so it closes. Nothing that wasn't " +
                    "already confirmed has been changed.\n\n" + ex);
            }
            catch { /* the dialog itself failed: close anyway */ }
            Shutdown();
        }

        // ── one copy at a time ───────────────────────────────────────────────

        /// <summary>
        /// True when this is the only copy. Otherwise the running copy's window comes to the front
        /// and this one ends; a copy in another Windows session can't be brought forward, so that
        /// case says where it runs.
        /// </summary>
        private static bool TakeInstance()
        {
            try
            {
                _instance = new Mutex(true, InstanceName, out var createdNew);
                if (createdNew) return true;
            }
            catch (UnauthorizedAccessException) { /* held by another session's copy */ }
            catch (Exception) { return true; }   // no guard available: don't refuse to start

            if (!BringOtherToFront())
                ThemedDialog.Info(null, "Already running",
                    "FirewallManager is already running in another Windows session on this machine " +
                    "(another user, or a Remote Desktop session). Only one copy runs at a time, since " +
                    "every copy changes the same machine-wide firewall policy.");
            return false;
        }

        private static bool BringOtherToFront()
        {
            try
            {
                using var self = Process.GetCurrentProcess();
                foreach (var p in Process.GetProcessesByName(self.ProcessName))
                {
                    using (p)
                    {
                        if (p.Id == self.Id || p.SessionId != self.SessionId) continue;
                        var hwnd = p.MainWindowHandle;
                        if (hwnd == IntPtr.Zero) continue;
                        if (IsIconic(hwnd)) ShowWindow(hwnd, SW_RESTORE);
                        SetForegroundWindow(hwnd);
                        return true;
                    }
                }
            }
            catch { }
            // Same session but no window yet (still starting, or a dialog before the main
            // window): nothing to bring forward, and nothing worth saying either.
            return SameSessionCopyExists();
        }

        private static bool SameSessionCopyExists()
        {
            try
            {
                using var self = Process.GetCurrentProcess();
                return Process.GetProcessesByName(self.ProcessName)
                              .Any(p => { using (p) return p.Id != self.Id && p.SessionId == self.SessionId; });
            }
            catch { return true; }
        }

        private const int SW_RESTORE = 9;
        [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr hWnd);
        [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);

        private bool _showingError;

        private void OnUnexpectedError(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            // Errors while the dialog is open (a timer that throws every tick, say) are not shown
            // again: one dialog at a time, and the app stays up until it is answered.
            e.Handled = true;
            if (_showingError) return;
            _showingError = true;
            try
            {
                if (!_mainShown)
                {
                    CloseAtStart(e.Exception);
                    return;
                }

                // Only a window on screen can own a dialog; before the main window shows, none can.
                var owner = MainWindow is { IsVisible: true } shown ? shown : null;
                var keepGoing = ThemedDialog.UnexpectedError(owner,
                    "Something went wrong that the app didn't expect. What you were doing may not have finished.\n\n" +
                    "Continue keeps the app open, and a running lock-down countdown with it. Close app ends it.\n\n" +
                    e.Exception);
                if (!keepGoing) Shutdown();
            }
            finally { _showingError = false; }
        }

        private static bool StartupChecks(out StartupWrites.Pending? pending)
        {
            pending = null;
            // An unreadable config.json would otherwise be ignored without a word.
            ConfigService.EnsureLoaded();
            if (ConfigService.Status == AppConfig.LoadStatus.UsedBaselineParseError && !AskCorruptConfig()) return false;

            var strays   = LocalGroupPolicy.FindStrays();
            var needSeed = !LocalGroupPolicy.HasFirewallSetting();
            var seedKb   = LocalGroupPolicy.SeedLogSizeKb();

            // Without these tools a change would be written but not applied, not checked or not
            // undoable; netsh too when the start-up setting is still needed. The app can't do its
            // job then, so the gate has one way out.
            var missing = WindowsTools.Missing(WindowsTools.NeededForChanges);
            if (needSeed && !WindowsTools.Exists(WindowsTools.Tool.Netsh)) missing.Add(WindowsTools.Tool.Netsh);
            if (missing.Count > 0)
            {
                ShowMissingTools(missing);
                return false;
            }

            // Ask everything before acting, so a refusal leaves nothing changed.
            if (strays.Count > 0 && !AskStrays(strays)) return false;
            if (needSeed && !AskSeed(seedKb)) return false;

            var work = new StartupWrites.Pending(needSeed, seedKb, strays);
            if (!needSeed && strays.Count == 0) return true;

            // A move that can cut a Remote Desktop session is written only once the main window's
            // guard has judged the facts; nothing is written before.
            if (StartupWrites.CouldCut(strays))
            {
                pending = work;
                return true;
            }

            if (StartupWrites.WriteWithDialogs(null, work) is not { } done) return false;
            if (done.Length > 0) PolicyApply.PendingAtStart = done;
            return true;
        }

        // Profile values under StandardProfile, which Windows does not reliably apply.
        private static bool AskStrays(List<LocalGroupPolicy.Stray> strays)
        {
            string Target(string profile, int? own, LocalGroupPolicy.Stray s) =>
                own == null
                    ? $"{profile}: set to {LocalGroupPolicy.Words(s.Name, s.Value)}"
                    : $"{profile}: keeps its own {LocalGroupPolicy.Words(s.Name, own.Value)}";

            var lines = strays.Select(s =>
                $"  •  {s.Label} = {LocalGroupPolicy.Words(s.Name, s.Value)}   →   " +
                $"{Target("Private", s.PrivateValue, s)};  {Target("Public", s.PublicValue, s)}");

            var message =
                "Profile settings were found under StandardProfile, the key's name from before Windows Vista. " +
                "Windows reads these firewall settings from PrivateProfile and PublicProfile and doesn't reliably " +
                "apply them from StandardProfile; the tiles showed them as if it did.\n\n" +
                "Found under HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile:\n" +
                string.Join("\n", lines) + "\n\n" +
                "AGREE copies each value to PrivateProfile and PublicProfile where that profile has no value of its " +
                "own (a profile's own value is what Windows uses, so it stays), then removes them from StandardProfile, " +
                "and the key too once it is empty. From the next policy refresh they take effect, and the tiles show " +
                "what Windows applies. Check the Private and Public tiles afterwards. Values set by Group Policy " +
                "(gpedit.msc or a domain) are not touched.\n\n" +
                "CLOSE APP changes nothing.";

            return ThemedDialog.Gate(null, "Profile settings are in the wrong place", message);
        }

        private static void ShowMissingTools(List<WindowsTools.Tool> missing)
        {
            string Role(WindowsTools.Tool t) => t switch
            {
                WindowsTools.Tool.Gpupdate   => "applies the firewall policy after a change",
                WindowsTools.Tool.PowerShell => "checks that a change is in force",
                WindowsTools.Tool.Reg        => "puts the firewall back after a lock-down",
                WindowsTools.Tool.Schtasks   => "sets up the lock-down's failsafe",
                WindowsTools.Tool.Netsh      => "adds the local Group Policy setting the firewall needs to re-read its policy",
                _                            => "",
            };
            var message =
                $"These Windows tools are not in {System.Environment.SystemDirectory}:\n" +
                string.Join("\n", missing.Select(t => $"  •  {WindowsTools.Name(t)}: {Role(t)}")) + "\n\n" +
                "Without them, a change would be written but not applied, not checked, or not undoable. " +
                "This app doesn't run without them. Nothing was changed.";
            ThemedDialog.Stop(null, "Windows tools are missing", message);
        }

        private static bool AskCorruptConfig()
        {
            var message =
                $"The configuration file next to the app can't be read:\n  {AppConfig.ConfigPath}\n\n" +
                $"{ConfigService.LoadError}\n\n" +
                "USE BUILT-IN runs the app with its built-in settings for this session. The file is left as it is, " +
                "and this question comes back at every start until it is fixed or removed.\n\n" +
                "CLOSE APP changes nothing.";
            return ThemedDialog.Gate(null, "config.json can't be read", message, agreeText: "USE BUILT-IN");
        }

        // The firewall only re-reads its policy when Group Policy hands it a change, which needs
        // at least one firewall setting in the local Group Policy.
        private static bool AskSeed(int kb)
        {
            var message =
                "On this computer, Windows applies the firewall policy only when it starts.\n\n" +
                "Why: the firewall re-reads its policy only when Group Policy hands it a change. This computer's " +
                "local Group Policy has no firewall setting in it, so it never hands one over, and the rules and " +
                "settings this app writes wait for the next restart. Until then the app would show them as set " +
                "while the firewall still does the old thing.\n\n" +
                "What AGREE adds: one setting in the local Group Policy, written with Windows' own tool (netsh):\n" +
                $"  •  {LocalGroupPolicy.SeedDescription(kb)}\n" +
                "That is the size the log already has, so the firewall behaves exactly as before. From then on, " +
                "every change this app makes takes effect within seconds.\n\n" +
                $"Where it is kept: {LocalGroupPolicy.PolFile}\n" +
                "It shows in gpedit.msc under Windows Defender Firewall with Advanced Security.\n\n" +
                "To remove it later, run netsh and type:\n" +
                $"  advfirewall set store gpo={System.Environment.MachineName}\n" +
                "  advfirewall set publicprofile logging maxfilesize notconfigured\n\n" +
                "CLOSE APP changes nothing.";

            return ThemedDialog.Gate(null, "Firewall changes won't take effect until a restart", message);
        }
    }

    /// <summary>
    /// The start-up writes agreed to at the gates: the seed setting and the StandardProfile move.
    /// Written by App, or, when the move could cut a Remote Desktop session, by the main window
    /// after the session guard (GuardChange.StartupMove).
    /// </summary>
    internal static class StartupWrites
    {
        public sealed record Pending(bool NeedSeed, int SeedKb, List<LocalGroupPolicy.Stray> Strays);

        // The values that, moved into a profile, can cut a Remote Desktop session: firewall on,
        // inbound block and merge off (only the operator's own rules let it in), outbound block
        // (the program carrying a session over a VPN). As the guard reads them: any value but 0 is
        // on / block, only 0 is merge off.
        private static bool Cutting(LocalGroupPolicy.Stray s) => s.Name switch
        {
            "EnableFirewall" or "DefaultInboundAction" or "DefaultOutboundAction" => s.Value != 0,
            "AllowLocalPolicyMerge"                                               => s.Value == 0,
            _                                                                     => false,
        };

        /// <summary>
        /// Cheap, before any window: a remote session and a cutting value that the move writes into
        /// Private or Public. The guard then judges the facts (and finds NotNeeded if none hold).
        /// </summary>
        public static bool CouldCut(List<LocalGroupPolicy.Stray> strays) =>
            strays.Any(s => Cutting(s) && (s.PrivateValue == null || s.PublicValue == null)) && Lockdown.IsRemoteSession();

        /// <summary>What MoveStrays writes into Private and Public (null where it writes nothing), for the guard.</summary>
        public static List<ProfileAfter> After(List<LocalGroupPolicy.Stray> strays)
        {
            int? Moved(string name, bool toPrivate) =>
                strays.FirstOrDefault(s => s.Name == name && (toPrivate ? s.PrivateValue : s.PublicValue) == null)?.Value;
            return new List<ProfileAfter>
            {
                new("Private", Moved("EnableFirewall", true),  Moved("DefaultInboundAction", true),  Moved("AllowLocalPolicyMerge", true),
                    Moved("DefaultOutboundAction", true)),
                new("Public",  Moved("EnableFirewall", false), Moved("DefaultInboundAction", false), Moved("AllowLocalPolicyMerge", false),
                    Moved("DefaultOutboundAction", false)),
            };
        }

        /// <summary>
        /// The guard's write: seed first (the step Windows can refuse), then the move. Touches no
        /// control; throws on failure.
        /// </summary>
        public static void Write(Pending p)
        {
            if (p.NeedSeed)
            {
                var (ok, output) = LocalGroupPolicy.AddSeed(p.SeedKb);
                if (!ok) throw new System.InvalidOperationException(
                    $"Windows refused or failed to add the setting to the local Group Policy ({output.Trim()})");
            }
            if (p.Strays.Count > 0) LocalGroupPolicy.MoveStrays(p.Strays);
        }

        /// <summary>What the start-up writes did: Done for the status line ("" for nothing), or the failure to show.</summary>
        public sealed record Outcome(string? Done, string? FailTitle = null, string? FailText = null, bool Monospace = false);

        /// <summary>
        /// Writes as the start-up always has: the step that can be refused by Windows first, so a
        /// failure there leaves nothing half done. Touches no control (netsh can take a while, so
        /// the main window runs this on a worker); the failure is shown by <see cref="ShowFailure"/>.
        /// </summary>
        public static Outcome Collect(Pending p)
        {
            var done = new List<string>();
            if (p.NeedSeed)
            {
                var (ok, output) = LocalGroupPolicy.AddSeed(p.SeedKb);
                if (!ok)
                    return new Outcome(null, "Could not add the setting",
                        "Windows refused or failed to add the setting to the local Group Policy, so changes made in " +
                        "this app would still wait for a restart. Nothing was changed. The app closes.\n\n" + output, Monospace: true);
                done.Add("local Group Policy setting added");
            }
            if (p.Strays.Count > 0)
            {
                var moved = new List<string>();
                try
                {
                    LocalGroupPolicy.MoveStrays(p.Strays, moved);
                    done.Add("profile settings moved out of StandardProfile");
                }
                catch (System.Exception ex)
                {
                    var seed = p.NeedSeed ? "The local Group Policy setting was added. " : "";
                    return new Outcome(null, "Could not move the settings",
                        $"{ex.Message}\n\n" +
                        (moved.Count == 0
                            ? (p.NeedSeed ? "The local Group Policy setting was added; the StandardProfile values were not moved. " : "Nothing was changed. ")
                            : $"{seed}The move stopped part way; already written: {string.Join(", ", moved)}. ") +
                        "The app closes.");
                }
            }
            return new Outcome(done.Count > 0 ? "Start-up: " + string.Join("; ", done) : "");
        }

        /// <summary>Shows a failed write (the app then closes); false when there was one.</summary>
        public static bool ShowFailure(Window? owner, Outcome o)
        {
            if (o.Done != null) return true;
            ThemedDialog.Info(owner, o.FailTitle!, o.FailText!, danger: true, monospace: o.Monospace);
            return false;
        }

        /// <summary>Collect and ShowFailure on this thread: null when it failed (the app closes).</summary>
        public static string? WriteWithDialogs(Window? owner, Pending p)
        {
            var o = Collect(p);
            return ShowFailure(owner, o) ? o.Done : null;
        }
    }
}
