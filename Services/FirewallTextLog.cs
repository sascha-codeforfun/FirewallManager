using System.Diagnostics;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// Windows Firewall's own text log (pfirewall.log), kept for the viewer's
    /// File source. No program names, and written in batches, so Live (the Security-log
    /// audit) is the everyday view; this is mainly useful where a policy keeps auditing off.
    ///
    /// State is read from the registry: a Group Policy value if one is set (it wins), else the
    /// machine's own. Numbers, not words, so it reads the same in every Windows language
    /// (netsh's printed output is translated). Switched with netsh for all three profiles.
    /// </summary>
    internal static class FirewallTextLog
    {
        private const string LocalRoot  = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        private const string PolicyRoot = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";
        // The Private profile has different key names: "PrivateProfile" in the policy,
        // "StandardProfile" in Windows' own local settings.
        private static readonly (string Policy, string Local)[] Profiles =
        {
            ("DomainProfile", "DomainProfile"), ("PrivateProfile", "StandardProfile"), ("PublicProfile", "PublicProfile"),
        };

        /// <summary>Is blocked / allowed logging on in any profile? Null where it can't be read.</summary>
        public static (bool? Blocked, bool? Allowed) State()
        {
            try { return (AnyProfile("LogDroppedPackets"), AnyProfile("LogSuccessfulConnections")); }
            catch { return (null, null); }
        }

        private static bool AnyProfile(string value)
        {
            foreach (var (policy, local) in Profiles)
            {
                var v = Read(PolicyRoot, policy, value) ?? Read(LocalRoot, local, value);
                if (v == 1) return true;
            }
            return false;
        }

        private static int? Read(string root, string profile, string value)
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{root}\{profile}\Logging");
            return key?.GetValue(value) is int i ? i : null;
        }

        /// <summary>"droppedconnections" or "allowedconnections", on or off, all profiles. Null, or why it couldn't run.</summary>
        public static string? Set(string setting, bool on)
        {
            if (WindowsTools.NotFound(WindowsTools.Tool.Netsh, "the text log was not switched") is { } missing) return missing;
            Netsh($"advfirewall set allprofiles logging {setting} {(on ? "enable" : "disable")}");
            if (on)   // make sure it writes where the viewer reads
                Netsh(@"advfirewall set allprofiles logging filename ""%systemroot%\system32\LogFiles\Firewall\pfirewall.log""");
            return null;
        }

        private static void Netsh(string args)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.Netsh), Arguments = args,
                    CreateNoWindow = true, UseShellExecute = false
                })?.WaitForExit(10000);
            }
            catch { /* the state read afterwards shows whether it took */ }
        }
    }
}
