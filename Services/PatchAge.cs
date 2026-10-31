using System;
using Microsoft.Win32;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  PatchAge — how long since this Windows last took a cumulative update, read
    //  locally: nothing is asked online (the app never phones home, and on a
    //  deny-by-default machine couldn't). Windows' servicing store records each
    //  monthly cumulative update ("RollupFix") with the time it was installed,
    //  whether it came from Windows Update or an .msu installed by hand.
    //
    //  Measured against Patch Tuesday (the second Tuesday of each month, when they
    //  come out), with a week's grace: a release not taken a week later counts as
    //  missed. It says how long since the last update, not whether a newer one exists:
    //  for a normal Windows 10/11 machine the same thing, for LTSC, Server or a managed
    //  machine on another cadence a heuristic.
    //
    //  Windows 10 (Home, Pro, Enterprise, Education) reached end of support on
    //  14 October 2025; its LTSC editions are supported for longer and don't count.
    // ─────────────────────────────────────────────────────────────────────────
    internal static class PatchAge
    {
        /// <param name="LastUpdate">When the last cumulative update was installed; null if not known.</param>
        /// <param name="Missed">Patch Tuesdays passed (a week's grace each) since then; 0 when unknown.</param>
        /// <param name="DaysSinceEndOfSupport">For Windows 10 past its end of support, the days since; else null.</param>
        public sealed record State(DateTime? LastUpdate, int Missed, int? DaysSinceEndOfSupport)
        {
            /// <summary>0 current, 1 one plaster, 2 three plasters, 3 three plasters and stitches.</summary>
            public int Level => DaysSinceEndOfSupport != null ? Math.Max(2, Missed >= 4 ? 3 : 2)
                              : Missed <= 0 ? 0 : Missed == 1 ? 1 : Missed <= 3 ? 2 : 3;

            public bool Behind => Level > 0;
        }

        public static readonly DateTime Windows10EndOfSupport = new(2025, 10, 14);

        /// <summary>
        /// Flick's default when the settings file doesn't say: on for Home, Pro and the education
        /// editions, off where it would be out of place, Enterprise (LTSC and IoT too) and Server.
        /// </summary>
        public static bool FlickByDefault()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (k == null) return true;
                var type    = k.GetValue("InstallationType")?.ToString() ?? "";
                var edition = k.GetValue("EditionID")?.ToString() ?? "";
                if (type.StartsWith("Server", StringComparison.OrdinalIgnoreCase)) return false;
                // EnterpriseS, IoTEnterprise(S), EnterpriseG…; ServerRdsh is Enterprise multi-session.
                if (edition.Contains("Enterprise", StringComparison.OrdinalIgnoreCase)) return false;
                if (edition.StartsWith("Server", StringComparison.OrdinalIgnoreCase)) return false;
                return true;
            }
            catch { return true; }
        }
        private static readonly TimeSpan Grace = TimeSpan.FromDays(7);

        public static State Read()
        {
            var last = LastCumulativeUpdate();
            var missed = last is { } installed ? MissedSince(installed, DateTime.Now) : 0;
            return new State(last, missed, DaysSinceWindows10EndOfSupport());
        }

        /// <summary>Patch Tuesdays after the install, each counted a week after its release.</summary>
        public static int MissedSince(DateTime installed, DateTime now)
        {
            var count = 0;
            var month = new DateTime(installed.Year, installed.Month, 1);
            for (var i = 0; i < 240; i++, month = month.AddMonths(1))
            {
                var tuesday = SecondTuesday(month.Year, month.Month);
                if (tuesday <= installed.Date) continue;
                if (tuesday + Grace > now) break;
                count++;
            }
            return count;
        }

        private static DateTime SecondTuesday(int year, int month)
        {
            var first = new DateTime(year, month, 1);
            var offset = ((int)DayOfWeek.Tuesday - (int)first.DayOfWeek + 7) % 7;
            return first.AddDays(offset + 7);
        }

        // The newest installed RollupFix package in Windows' servicing store (CurrentState 0x70 =
        // installed), by its recorded install time.
        private static DateTime? LastCumulativeUpdate()
        {
            try
            {
                using var packages = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");
                if (packages == null) return null;
                DateTime? newest = null;
                foreach (var name in packages.GetSubKeyNames())
                {
                    if (!name.StartsWith("Package_for_RollupFix", StringComparison.OrdinalIgnoreCase)) continue;
                    using var k = packages.OpenSubKey(name);
                    if (k?.GetValue("CurrentState") is not int state || state != 0x70) continue;
                    if (k.GetValue("InstallTimeHigh") is not int high || k.GetValue("InstallTimeLow") is not int low) continue;
                    var fileTime = ((long)(uint)high << 32) | (uint)low;
                    // Out of DateTime's range would throw, and the catch below would drop every package.
                    if (fileTime <= 0 || fileTime > DateTime.MaxValue.ToFileTimeUtc()) continue;
                    var when = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();
                    if (newest == null || when > newest) newest = when;
                }
                return newest;
            }
            catch { return null; }
        }

        // Windows 10 by build (below 22000) on a client, not one of the LTSC editions.
        private static int? DaysSinceWindows10EndOfSupport()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (k == null) return null;
                string Str(string n) => k.GetValue(n)?.ToString()?.Trim() ?? "";
                if (Str("InstallationType").StartsWith("Server", StringComparison.OrdinalIgnoreCase)) return null;
                if (!int.TryParse(Str("CurrentBuildNumber"), out var build) || build >= 22000 || build < 10240) return null;
                var edition = Str("EditionID");
                // EnterpriseS, IoTEnterpriseS (and their N variants) are the LTSC editions.
                if (edition.Contains("EnterpriseS", StringComparison.OrdinalIgnoreCase)) return null;
                var days = (DateTime.Today - Windows10EndOfSupport).Days;
                return days > 0 ? days : null;
            }
            catch { return null; }
        }
    }
}
