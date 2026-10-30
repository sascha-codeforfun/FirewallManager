using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// Process starts from the Security log (event 4688, "Process Creation" audit), with their
    /// command lines. They name what the connection log can't: a service host that has ended
    /// ("svchost.exe -k netsvcs -p -s wuauserv"), what rundll32 or dllhost ran, and which
    /// program started it. The record stays after the process is gone — also across a reboot,
    /// which is the moment nothing else can catch it.
    ///
    /// Two Windows settings, both switched here and nowhere else: the audit (by its ID, any
    /// language) and the policy value that adds the command line. On = both, off = both. Like
    /// the other recording, it keeps going after the app closes; closing asks.
    /// </summary>
    internal static class ProcessStartLog
    {
        private const string ProcessCreationAudit = "{0CCE922B-69AE-11D9-BED3-505054503030}";
        private const string CmdLineKey   = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
        private const string CmdLineValue = "ProcessCreationIncludeCmdLine_Enabled";

        // ── Switch ────────────────────────────────────────────────────────────

        /// <summary>True if process starts are recorded; null if the audit can't be read.</summary>
        public static bool? IsOn() => LiveDropSource.QueryAuditPolicy(ProcessCreationAudit)?.Success;

        public static bool Enable()
        {
            // The command-line value is only worth writing when the audit can follow.
            if (LiveDropSource.AuditpolMissing != null) return false;
            try
            {
                using (var k = Registry.LocalMachine.CreateSubKey(CmdLineKey))
                    k?.SetValue(CmdLineValue, 1, RegistryValueKind.DWord);
            }
            catch { return false; }
            return LiveDropSource.SetAuditSuccess(ProcessCreationAudit, true);
        }

        public static void Disable()
        {
            LiveDropSource.SetAuditSuccess(ProcessCreationAudit, false);
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(CmdLineKey, writable: true);
                k?.DeleteValue(CmdLineValue, throwOnMissingValue: false);
            }
            catch { }
        }

        // ── Will service names be exact on this machine? ──────────────────────

        /// <summary>
        /// Windows gives each service its own host (so the command line carries "-s Service")
        /// when the installed memory exceeds SvcHostSplitThresholdInKB (default 3.5 GB);
        /// below it, services share hosts and only the group ("-k netsvcs") can be named.
        /// </summary>
        public static (double MemoryGb, double ThresholdGb, bool Split) SplitInfo()
        {
            ulong thresholdKb = 3670016;   // 3.5 GB, Windows' default
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control");
                if (k?.GetValue("SvcHostSplitThresholdInKB") is int v) thresholdKb = unchecked((uint)v);
            }
            catch { }
            var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
            var totalKb = GlobalMemoryStatusEx(ref status) ? status.TotalPhys / 1024 : 0;
            return (totalKb / 1048576.0, thresholdKb / 1048576.0, totalKb > thresholdKb);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryStatusEx
        {
            public uint Length, MemoryLoad;
            public ulong TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);

        // ── Reading starts ────────────────────────────────────────────────────

        public sealed record Start(DateTime Time, int ProcessId, string Image, string CommandLine, string Parent)
        {
            /// <summary>The event's number in the Security log, for reading on from it.</summary>
            public long RecordId { get; init; }
            /// <summary>When it started, in UTC: what boot and process start times are compared in.</summary>
            public DateTime TimeUtc { get; init; }
            /// <summary>The service a service host was started for ("-s Name"), or "".</summary>
            public string Service => ArgAfter("-s");
            /// <summary>The service group ("-k netsvcs"), or "".</summary>
            public string Group => ArgAfter("-k");

            private string ArgAfter(string flag)
            {
                var parts = CommandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var i = Array.FindIndex(parts, p => p.Equals(flag, StringComparison.OrdinalIgnoreCase));
                return i >= 0 && i + 1 < parts.Length ? parts[i + 1].Trim('"') : "";
            }
        }

        public const int MaxEntries = 20000;

        /// <summary>When this machine last started, in UTC (local time would be an hour off across a clock change).</summary>
        public static DateTime BootUtc() => DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

        /// <summary>
        /// Starts since the current boot, indexed by process ID, newest first. Read in full up to
        /// <see cref="MaxEntries"/>, since a service host may have started at boot, hours ago.
        /// Earlier boots are left out: Windows hands out the same process IDs again after a
        /// restart. cursor: marks where this read began, for <see cref="ReadOn"/>.
        /// </summary>
        public static Dictionary<int, List<Start>> ReadIndex(out LogCursor cursor)
        {
            cursor = new LogCursor("Security");
            var index = new Dictionary<int, List<Start>>();
            try
            {
                var uptimeMs = Math.Max(1000, Environment.TickCount64);
                var query = new EventLogQuery("Security", PathType.LogName,
                    $"*[System[EventID=4688 and TimeCreated[timediff(@SystemTime) <= {uptimeMs}]]]") { ReverseDirection = true };
                using var reader = new EventLogReader(query);
                var n = 0;
                for (var ev = reader.ReadEvent(); ev != null && n < MaxEntries; ev = reader.ReadEvent(), n++)
                {
                    using (ev)
                    {
                        if (Parse(ev) is not { } s) continue;
                        if (!index.TryGetValue(s.ProcessId, out var list)) index[s.ProcessId] = list = new();
                        list.Add(s);
                    }
                }
            }
            catch { /* no access or no events: nothing to name from */ }
            return index;
        }

        /// <summary>The starts written after the cursor's mark, since the current boot, oldest first.</summary>
        public static List<Start> ReadOn(LogCursor cursor)
        {
            var boot = BootUtc();
            var found = new List<Start>();
            // Newest first and no further back than the index keeps, then turned oldest first.
            try
            {
                cursor.ReadNewestOn("*[System[EventID=4688]]", ev =>
                {
                    if (Parse(ev) is { } s && s.TimeUtc >= boot) found.Add(s);
                    return found.Count < MaxEntries;
                });
            }
            catch { /* no access: nothing new to name from */ }
            found.Reverse();
            return found;
        }

        /// <summary>
        /// Adds starts (oldest first) to an index, keeping it newest first per ID; ones already in
        /// it are skipped. The index stays at about <see cref="MaxEntries"/> starts, as a full
        /// read leaves it: the oldest go first.
        /// </summary>
        public static void AddTo(Dictionary<int, List<Start>> index, List<Start> starts)
        {
            foreach (var s in starts)
            {
                if (!index.TryGetValue(s.ProcessId, out var list)) index[s.ProcessId] = list = new();
                if (list.Any(x => x.RecordId == s.RecordId)) continue;
                list.Insert(0, s);
            }

            // Trimmed only once it is a tenth over, so a following log doesn't sort every tick.
            var total = index.Values.Sum(l => l.Count);
            if (total <= MaxEntries + MaxEntries / 10) return;
            var cut = index.Values.SelectMany(l => l).Select(x => x.RecordId)
                           .OrderBy(id => id).ElementAt(total - MaxEntries - 1);
            foreach (var pid in index.Keys.ToList())
            {
                var list = index[pid];
                list.RemoveAll(x => x.RecordId <= cut);
                if (list.Count == 0) index.Remove(pid);
            }
        }

        /// <summary>
        /// The recorded start of the process that had this ID at this moment, or null when there
        /// is none to rely on: the moment is from before the current boot, nothing was recorded,
        /// or the process still running under this ID started at another time than the record
        /// says (its own start wasn't recorded).
        /// </summary>
        public static Start? At(Dictionary<int, List<Start>> index, int pid, DateTime time)
        {
            var t = time.ToUniversalTime();
            if (pid <= 0 || t < BootUtc() || !index.TryGetValue(pid, out var list)) return null;
            var s = list.FirstOrDefault(x => x.TimeUtc <= t.AddSeconds(1));      // newest first
            if (s == null) return null;

            var (running, started) = RunningStart(pid);
            if (!running) return s;
            if (started is not { } real) return null;                              // running, start unreadable
            if (Math.Abs((real - s.TimeUtc).TotalSeconds) <= 2) return s;          // the very process
            // A process started after this moment took the ID later; it says nothing about then.
            return real > t.AddSeconds(1) ? s : null;
        }

        // Whether a process with this ID runs now, and when it started in UTC (null if unreadable).
        // Remembered a few seconds: a read asks for the same few IDs on many rows.
        private static readonly Dictionary<int, (DateTime Asked, bool Running, DateTime? Start)> _running = new();
        private static readonly object _runningGate = new();

        private static (bool Running, DateTime? Start) RunningStart(int pid)
        {
            lock (_runningGate)
                if (_running.TryGetValue(pid, out var known) && (DateTime.Now - known.Asked).TotalSeconds < 5)
                    return (known.Running, known.Start);

            bool running;
            DateTime? start = null;
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                running = true;
                try { start = p.StartTime.ToUniversalTime(); } catch { /* running, but its start can't be read */ }
            }
            catch { running = false; }   // no process with this ID now

            lock (_runningGate)
            {
                if (_running.Count > 4096) _running.Clear();
                _running[pid] = (DateTime.Now, running, start);
            }
            return (running, start);
        }

        // Fast path: the values by position (event version 2: NewProcessId 4, NewProcessName 5,
        // CommandLine 8, ParentProcessName 13) — reading thousands of starts through XML is slow
        // on a small machine. The XML with field names is the fallback for other versions.
        private static Start? Parse(EventRecord ev)
        {
            try
            {
                var time0 = ev.TimeCreated ?? DateTime.Now;
                var utc = time0.ToUniversalTime();
                if (time0.Kind == DateTimeKind.Utc) time0 = time0.ToLocalTime();
                var props = ev.Properties;
                if (ev.Version >= 2 && props.Count >= 14 && props[5].Value is string image)
                {
                    var raw = props[4].Value;
                    long id = raw is string s0
                        ? long.Parse(s0.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s0[2..] : s0, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                        : Convert.ToInt64(raw, CultureInfo.InvariantCulture);
                    return new Start(time0, (int)id, image, (props[8].Value as string ?? "").Trim(), props[13].Value as string ?? "")
                        { RecordId = ev.RecordId ?? 0, TimeUtc = utc };
                }

                var data = EventFields.Of(ev);
                string Get(string k) => data.TryGetValue(k, out var v) ? v : "";

                // NewProcessId is written in hex ("0x1f34").
                var hex = Get("NewProcessId");
                if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
                if (!int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var pid)) return null;

                return new Start(time0, pid, Get("NewProcessName"), Get("CommandLine").Trim(), Get("ParentProcessName"))
                    { RecordId = ev.RecordId ?? 0, TimeUtc = utc };
            }
            catch { return null; }
        }
    }
}
