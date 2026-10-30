using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

namespace FirewallManager
{
    /// <summary>
    /// Windows' DNS client log ("Microsoft-Windows-DNS-Client/Operational"): one event (3008)
    /// per name lookup, with the name, the answers and the program that asked. Off by default.
    ///
    /// Switched the same way as connection auditing: on when you ask for it, and offered off
    /// on every close, so it can also stay on for a long observation. Like the audit, it is a
    /// Windows setting and keeps recording after this app closes. Read and changed through
    /// the event log's own configuration: the same in every Windows language, no command-line
    /// tool, nothing written by this app itself.
    /// </summary>
    internal static class DnsClientLog
    {
        public const string Channel = "Microsoft-Windows-DNS-Client/Operational";

        /// <summary>True if lookups are being recorded; null if the setting can't be read.</summary>
        public static bool? IsOn()
        {
            try
            {
                using var cfg = new EventLogConfiguration(Channel);
                return cfg.IsEnabled;
            }
            catch { return null; }
        }

        /// <summary>Switches recording on or off. False if Windows refused.</summary>
        public static bool Set(bool on)
        {
            try
            {
                using var cfg = new EventLogConfiguration(Channel);
                if (cfg.IsEnabled == on) return true;
                cfg.IsEnabled = on;
                cfg.SaveChanges();
                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// How much the log keeps before it overwrites its oldest lookups ("1 MB"), or "" if
        /// unknown. Said when switching on, since it decides how far back a long observation
        /// reaches.
        /// </summary>
        public static string SizeText()
        {
            try
            {
                using var cfg = new EventLogConfiguration(Channel);
                var bytes = cfg.MaximumSizeInBytes;
                return bytes >= 1024 * 1024 ? $"{bytes / (1024.0 * 1024.0):0.#} MB" : $"{bytes / 1024} KB";
            }
            catch { return ""; }
        }

        // ── Reading lookups ───────────────────────────────────────────────────

        /// <summary>
        /// The oldest and newest lookup in the log, whatever the scope: how far back it reaches
        /// (it only holds what was recorded while on, and overwrites its oldest when full).
        /// </summary>
        public static (DateTime? Oldest, DateTime? Newest) Coverage()
        {
            DateTime? End(bool newest)
            {
                try
                {
                    var q = new EventLogQuery(Channel, PathType.LogName, "*[System[EventID=3008]]") { ReverseDirection = newest };
                    using var reader = new EventLogReader(q);
                    using var ev = reader.ReadEvent();
                    var t = ev?.TimeCreated;
                    return t is { Kind: DateTimeKind.Utc } ? t.Value.ToLocalTime() : t;
                }
                catch { return null; }
            }
            return (End(false), End(true));
        }

        public const int MaxEntries = 5000;

        /// <summary>True when the last read stopped at <see cref="MaxEntries"/> with older lookups left.</summary>
        public static bool LastReadTruncated { get; private set; }

        /// <summary>One completed lookup (event 3008).</summary>
        public sealed record Lookup(
            DateTime Time, string Name, int Type, int Status,
            IReadOnlyList<string> Aliases, IReadOnlyList<string> Addresses,
            int ProcessId, string Program, string Services, string ServicesLong, string Account)
        {
            /// <summary>The event's number in the log, for reading on from it.</summary>
            public long RecordId { get; init; }
        }

        /// <summary>A cursor at the newest lookup now, for <see cref="ReadOn"/>.</summary>
        public static LogCursor Cursor() => new(Channel);

        /// <summary>
        /// Lookups written after the cursor's mark, newest first, at most <see cref="MaxEntries"/>,
        /// left out and named as in <see cref="Read"/>. Leaves <see cref="LastReadTruncated"/>
        /// alone: that describes the full read.
        /// </summary>
        public static List<Lookup> ReadOn(LogCursor cursor)
        {
            var raw = new List<Raw>();
            // Newest first, and only as far back as is kept (see LiveDropSource.ReadOn).
            try
            {
                cursor.ReadNewestOn("*[System[EventID=3008]]", ev =>
                {
                    if (Parse(ev) is { } parsed) raw.Add(parsed);
                    return raw.Count < MaxEntries;
                });
            }
            catch (EventLogNotFoundException) { return new List<Lookup>(); }
            return Named(raw);
        }

        private readonly record struct Raw(DateTime Time, string Name, int Type, int Status, string Results, int Pid, string Sid, long RecordId);

        /// <summary>
        /// Lookups newest first, at most <see cref="MaxEntries"/>, optionally only since a time.
        /// Left out: Windows asking about itself (its own name, "..localmachine", localhost), and
        /// the empty status-87 entries that come paired with a real query and carry nothing.
        /// newestRecordId: the newest event read, left out or not; 0 if none was read.
        /// </summary>
        public static List<Lookup> Read(DateTime? since) => Read(since, out _);

        public static List<Lookup> Read(DateTime? since, out long newestRecordId)
        {
            newestRecordId = 0;
            var xpath = "*[System[EventID=3008]]";
            if (since.HasValue)
            {
                var ms = Math.Max(1000, (long)(DateTime.Now - since.Value).TotalMilliseconds);
                xpath = $"*[System[EventID=3008 and TimeCreated[timediff(@SystemTime) <= {ms}]]]";
            }

            var raw = new List<Raw>();
            LastReadTruncated = false;
            try
            {
                var query = new EventLogQuery(Channel, PathType.LogName, xpath) { ReverseDirection = true };
                using var reader = new EventLogReader(query);
                for (var ev = reader.ReadEvent(); ev != null; ev = reader.ReadEvent())
                {
                    using (ev)
                    {
                        if (raw.Count >= MaxEntries) { LastReadTruncated = true; break; }
                        newestRecordId = Math.Max(newestRecordId, ev.RecordId ?? 0);
                        var parsed = Parse(ev);
                        if (parsed != null) raw.Add(parsed.Value);
                    }
                }
            }
            catch (EventLogNotFoundException) { return new List<Lookup>(); }
            return Named(raw);
        }

        private static List<Lookup> Named(List<Raw> raw)
        {
            // Which program asked: the process ID, named while that same process still runs
            // (started before the lookup), and for a service host the services seen in it.
            LiveDropSource.ObserveServices();
            var procs = new Dictionary<int, (DateTime Start, string Name)?>();
            (DateTime Start, string Name)? Proc(int pid)
            {
                if (procs.TryGetValue(pid, out var known)) return known;
                (DateTime, string)? found = null;
                try { using var p = Process.GetProcessById(pid); found = (p.StartTime, p.ProcessName); }
                catch { /* ended, or not accessible */ }
                procs[pid] = found;
                return found;
            }

            var self = Environment.MachineName;
            return raw
                .Where(r => r.Status != 87 || r.Results.Length > 0)
                .Where(r => !r.Name.StartsWith("..", StringComparison.Ordinal)
                            && !r.Name.Equals(self, StringComparison.OrdinalIgnoreCase)
                            && !r.Name.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                .Select(r =>
                {
                    var (aliases, addresses) = SplitResults(r.Results);
                    var program = "";
                    string svc = "", svcLong = "";
                    if (r.Pid > 0 && Proc(r.Pid) is { } p && p.Start <= r.Time.AddSeconds(1))
                    {
                        program = p.Name + ".exe";
                        (svc, svcLong) = LiveDropSource.ServicesAt(r.Pid, p.Name, r.Time);
                    }
                    return new Lookup(r.Time, r.Name.TrimEnd('.'), r.Type, r.Status, aliases, addresses,
                                      r.Pid, program, svc, svcLong, AccountName(r.Sid)) { RecordId = r.RecordId };
                })
                .ToList();
        }

        // Fast path: the event's values in their fixed order (QueryName, QueryType, QueryOptions,
        // QueryStatus, QueryResults), no XML. The XML with its field names is the fallback if a
        // Windows version ever lays them out differently.
        private static Raw? Parse(EventRecord ev)
        {
            try
            {
                var time0 = ev.TimeCreated ?? DateTime.Now;
                if (time0.Kind == DateTimeKind.Utc) time0 = time0.ToLocalTime();
                var props = ev.Properties;
                if (props.Count >= 5 && props[0].Value is string qn && props[4].Value is string qr)
                {
                    var t  = Convert.ToInt32(props[1].Value);
                    var st = Convert.ToInt32(props[3].Value);
                    return new Raw(time0, qn, t, st, qr, ev.ProcessId ?? 0, ev.UserId?.Value ?? "", ev.RecordId ?? 0);
                }

                var data = EventFields.Of(ev);
                string Get(string k) => data.TryGetValue(k, out var v) ? v : "";
                int.TryParse(Get("QueryType"),   out var type);
                int.TryParse(Get("QueryStatus"), out var status);

                var time = ev.TimeCreated ?? DateTime.Now;
                if (time.Kind == DateTimeKind.Utc) time = time.ToLocalTime();
                return new Raw(time, Get("QueryName"), type, status, Get("QueryResults"),
                               ev.ProcessId ?? 0, ev.UserId?.Value ?? "", ev.RecordId ?? 0);
            }
            catch { return null; }
        }

        // "type:  5 alias.example.net;type:  5 edge.example.net;::ffff:150.171.28.12;::1;"
        // → aliases (the CNAME chain, in order) and addresses (IPv4 written plainly).
        private static (List<string> Aliases, List<string> Addresses) SplitResults(string results)
        {
            var aliases = new List<string>();
            var addresses = new List<string>();
            foreach (var part in results.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (part.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
                {
                    var name = part.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
                    if (name.Length > 0 && !name.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
                        aliases.Add(name.TrimEnd('.'));
                }
                else
                {
                    var a = part.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) ? part[7..] : part;
                    if (!addresses.Contains(a, StringComparer.OrdinalIgnoreCase)) addresses.Add(a);
                }
            }
            return (aliases, addresses);
        }

        private static string AccountName(string sid) => sid switch
        {
            "S-1-5-18" => "SYSTEM",
            "S-1-5-19" => "Local Service",
            "S-1-5-20" => "Network Service",
            ""         => "",
            _          => "user",
        };

        /// <summary>The query status in words: the common DNS results, else the number.</summary>
        public static string StatusText(int status) => status switch
        {
            0    => "answered",
            9003 => "no such name",
            9501 => "no records",
            9002 => "server failure",
            9005 => "refused",
            1460 => "timed out",
            1214 => "invalid name",
            123  => "invalid name",
            11001 => "host not found",
            _    => $"error {status}",
        };
    }
}
