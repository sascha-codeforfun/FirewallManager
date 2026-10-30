using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

namespace FirewallManager
{
    /// <summary>
    /// When the firewall dropped and re-read all its rules, from its own event log. At each such
    /// reload Windows renumbers the filters behind the rules, so the filter ID in a connection
    /// event names a rule only among the events after the same reload.
    ///
    /// 2033 (Windows 10) and 2059 (Windows 11): all rules deleted, the reload itself.
    /// 2008: Group Policy firewall settings applied, which caused the reload when it is close by.
    /// </summary>
    internal static class FirewallReloads
    {
        internal const string LogName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";
        private const int MaxEvents = 500;

        public sealed record Reload(DateTime Time, bool AfterGroupPolicy);

        /// <summary>Newest first; empty if the log can't be read.</summary>
        public static List<Reload> Read(DateTime? since)
        {
            var events = new List<(DateTime Time, int Id)>();
            try
            {
                var ids = "(EventID=2008 or EventID=2033 or EventID=2059)";
                var xpath = since.HasValue
                    ? $"*[System[{ids} and TimeCreated[timediff(@SystemTime) <= {Math.Max(1000, (long)(DateTime.Now - since.Value).TotalMilliseconds)}]]]"
                    : $"*[System[{ids}]]";
                using var reader = new EventLogReader(new EventLogQuery(LogName, PathType.LogName, xpath) { ReverseDirection = true });
                for (var ev = reader.ReadEvent(); ev != null && events.Count < MaxEvents; ev = reader.ReadEvent())
                {
                    using (ev)
                    {
                        var t = ev.TimeCreated ?? DateTime.Now;
                        if (t.Kind == DateTimeKind.Utc) t = t.ToLocalTime();
                        events.Add((t, ev.Id));
                    }
                }
            }
            catch { return new(); }

            // The Group Policy event and the reload it causes come within seconds of each other,
            // in either order.
            var policy = events.Where(e => e.Id == 2008).Select(e => e.Time).ToList();
            return events.Where(e => e.Id != 2008)
                .Select(e => new Reload(e.Time, policy.Any(p => Math.Abs((p - e.Time).TotalSeconds) <= 30)))
                .ToList();
        }

        public static string Text(Reload r) => r.AfterGroupPolicy
            ? "Firewall reloaded all rules (Group Policy change)"
            : "Firewall reloaded all rules";
    }
}
