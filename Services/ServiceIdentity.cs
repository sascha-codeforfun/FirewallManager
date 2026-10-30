using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// Whether a firewall rule can match one service by name (Svc=). Windows tells the services
    /// inside one svchost.exe apart by each one's own security identity (its service SID), and
    /// only a service set to have one (ServiceSidType 1, unrestricted, or 3, restricted) can be
    /// matched. Without it, or with the service not installed at all (uninstalled, or trimmed out
    /// of the image), a rule for it never matches and does nothing. Read from the registry: a
    /// change of SID type counts from the service's next start, so for that short while the
    /// answer may be ahead of what Windows applies.
    /// </summary>
    internal static class ServiceIdentity
    {
        public enum State { Matchable, NoSid, NotInstalled, Unknown }

        public static State Of(string service)
        {
            if (string.IsNullOrWhiteSpace(service) || service.Trim() == "*") return State.Unknown;
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{service.Trim()}");
                if (k == null) return State.NotInstalled;
                return k.GetValue("ServiceSidType") is int v && (v == 1 || v == 3) ? State.Matchable : State.NoSid;
            }
            catch { return State.Unknown; }
        }

        /// <summary>Why a rule for this service does nothing, or null when it can match (or that isn't known).</summary>
        public static string? WhyNotMatched(string service) => Of(service) switch
        {
            State.NoSid        => $"{service.Trim()} has no service identity on this machine, so this rule can't match it and doesn't take effect.",
            State.NotInstalled => $"Service {service.Trim()} isn't installed on this machine, so this rule doesn't take effect.",
            _                  => null,
        };
    }

    /// <summary>
    /// The time-sync rule: UDP 123 out to one time server, for the Windows Time service (W32Time)
    /// only, as the rule editor's Time preset and Setup's Time sync tile both write it. W32Time
    /// is the one that sets the clock, so the scope takes nothing from it; anything else that
    /// wants to reach a time server needs a rule of its own. Where W32Time has no service
    /// identity the rule can't be tied to it, and is written for any program instead.
    /// </summary>
    internal static class NtpRule
    {
        public const string Program = @"%SystemRoot%\system32\svchost.exe";
        public const string Service = "W32Time";
        public const string Port    = "123";

        /// <summary>True when a rule can be tied to W32Time on this machine.</summary>
        public static bool CanBind => ServiceIdentity.Of(Service) == ServiceIdentity.State.Matchable;

        /// <summary>Why the rule isn't tied to W32Time here; any program may use it then.</summary>
        public static string UnboundNote =>
            (ServiceIdentity.Of(Service) == ServiceIdentity.State.NotInstalled
                ? "W32Time isn't installed on this machine"
                : "W32Time has no service identity on this machine") +
            ", so the rule can't be tied to it: any program may use it.";
    }
}
