using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;

namespace FirewallManager
{
    /// <summary>
    /// When the network came and went, from Windows' network list log (NetworkProfile
    /// Operational: 10000 connected, 10001 disconnected). Context for the log only: Windows
    /// writes no event when it renumbers its filters, and a network change doesn't always
    /// renumber them (measured on 26300), so these lines say nothing about filter IDs.
    /// </summary>
    internal static class NetworkChanges
    {
        internal const string LogName = "Microsoft-Windows-NetworkProfile/Operational";
        private const int MaxEvents = 500;

        public sealed record Change(DateTime Time, bool Connected);

        /// <summary>Newest first; one per second per kind (Windows writes them in pairs); empty if the log can't be read.</summary>
        public static List<Change> Read(DateTime? since)
        {
            var list = new List<Change>();
            try
            {
                var ids = "(EventID=10000 or EventID=10001)";
                var xpath = since.HasValue
                    ? $"*[System[{ids} and TimeCreated[timediff(@SystemTime) <= {Math.Max(1000, (long)(DateTime.Now - since.Value).TotalMilliseconds)}]]]"
                    : $"*[System[{ids}]]";
                using var reader = new EventLogReader(new EventLogQuery(LogName, PathType.LogName, xpath) { ReverseDirection = true });
                for (var ev = reader.ReadEvent(); ev != null && list.Count < MaxEvents; ev = reader.ReadEvent())
                {
                    using (ev)
                    {
                        var t = ev.TimeCreated ?? DateTime.Now;
                        if (t.Kind == DateTimeKind.Utc) t = t.ToLocalTime();
                        list.Add(new Change(t, ev.Id == 10000));
                    }
                }
            }
            catch { return new(); }

            return list
                .GroupBy(c => (Second: new DateTime(c.Time.Ticks - c.Time.Ticks % TimeSpan.TicksPerSecond), c.Connected))
                .Select(g => g.First())
                .OrderByDescending(c => c.Time)
                .ToList();
        }

        public static string Text(bool connected) => connected ? "network connected" : "network disconnected";
    }

    /// <summary>
    /// When the system clock was set by more than a minute (Security 4616), so rows that look
    /// out of order have a visible reason. Time sync's small steps are left out.
    /// </summary>
    internal static class ClockChanges
    {
        private const int MaxEvents = 200;
        private static readonly TimeSpan Threshold = TimeSpan.FromMinutes(1);

        public sealed record Change(DateTime Time, DateTime Before, DateTime After);

        /// <summary>Newest first; empty if the log can't be read.</summary>
        public static List<Change> Read(DateTime? since)
        {
            var list = new List<Change>();
            try
            {
                var xpath = since.HasValue
                    ? $"*[System[EventID=4616 and TimeCreated[timediff(@SystemTime) <= {Math.Max(1000, (long)(DateTime.Now - since.Value).TotalMilliseconds)}]]]"
                    : "*[System[EventID=4616]]";
                using var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, xpath) { ReverseDirection = true });
                for (var ev = reader.ReadEvent(); ev != null && list.Count < MaxEvents; ev = reader.ReadEvent())
                {
                    using (ev)
                    {
                        var data = EventFields.Of(ev);
                        if (!Utc(data, "PreviousTime", out var before) || !Utc(data, "NewTime", out var after)) continue;
                        if ((after - before).Duration() < Threshold) continue;
                        var t = ev.TimeCreated ?? DateTime.Now;
                        if (t.Kind == DateTimeKind.Utc) t = t.ToLocalTime();
                        list.Add(new Change(t, before.ToLocalTime(), after.ToLocalTime()));
                    }
                }
            }
            catch { return new(); }
            return list;
        }

        // The event writes both times in UTC, ISO 8601 ("2026-10-09T19:43:56.1234567Z").
        private static bool Utc(Dictionary<string, string> data, string key, out DateTime value)
        {
            value = default;
            return data.TryGetValue(key, out var text) &&
                   DateTime.TryParse(text, CultureInfo.InvariantCulture,
                                     DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out value);
        }

        public static string Text(Change c) => $"clock changed: {c.Before:HH:mm:ss} → {c.After:HH:mm:ss}";
    }
}
