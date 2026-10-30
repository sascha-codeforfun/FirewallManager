using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace FirewallManager
{
    /// <summary>
    /// The viewer's "Live" source: connections read from the Security log — blocked (event 5157)
    /// and, only while their audit is switched on, allowed (event 5156). Unlike pfirewall.log, these are
    /// written the moment the firewall decides, and they name the program.
    ///
    /// Windows records these only while their audit is on, a system-wide setting. This class
    /// reads and changes three of them, each by GUID so it works in every Windows language:
    /// connection failures (5157) and connection successes (5156) of "Filtering Platform
    /// Connection", and process creation (<see cref="SetAuditSuccess"/>, for ProcessStartLog).
    /// Allowed connections have their own switch: they fire for every connection the machine
    /// makes and fill the Security log quickly.
    /// </summary>
    internal static class LiveDropSource
    {
        // Audit subcategory "Filtering Platform Connection" (same GUID on every Windows language).
        private const string WfpConnectionAudit = "{0CCE9226-69AE-11D9-BED3-505054503030}";
        public  const int    MaxEntries         = 2000;

        /// <summary>
        /// True when the last read stopped at <see cref="MaxEntries"/> with older events still in
        /// the log: counts are then low, and the viewer says so.
        /// </summary>
        public static bool LastReadTruncated { get; private set; }

        public sealed record LiveEvent(
            string Action, DateTime Time, string Direction, string Protocol,
            string SrcIP, string SrcPort, string DstIP, string DstPort, string Program,
            int ProcessId)
        {
            /// <summary>Services hosted by the process (short names, e.g. "MapsBroker"); empty if none.</summary>
            public string Services { get; init; } = "";
            /// <summary>The same with display names, for the tooltip.</summary>
            public string ServicesLong { get; init; } = "";
            /// <summary>The filter that decided (FilterRTID); renumbered at every firewall reload.</summary>
            public long FilterId { get; init; }
            /// <summary>The event's number in the Security log, for reading on from it.</summary>
            public long RecordId { get; init; }
        }

        // ── Audit setting ─────────────────────────────────────────────────────

        /// <summary>True if blocked connections (5157, the "failure" audit) are recorded.</summary>
        public static bool? DropAuditingOn() => AuditState().Failure;

        /// <summary>True if allowed connections (5156, the "success" audit) are recorded.</summary>
        public static bool? AllowAuditingOn() => AuditState().Success;

        /// <summary>Both halves of the audit, read now. Null where the state can't be read.</summary>
        public static (bool? Success, bool? Failure) AuditState() => QueryAuditPolicy() ?? ParseAuditpol();

        // Asked of Windows directly (the call auditpol itself makes): plain flags, the same in
        // every Windows language. Needs the "manage auditing and security log" privilege, which
        // an administrator holds but has switched off until a program switches it on.
        private static (bool? Success, bool? Failure)? QueryAuditPolicy() => QueryAuditPolicy(WfpConnectionAudit);

        /// <summary>Any audit subcategory by its ID: (success, failure), or null if unreadable.</summary>
        internal static (bool? Success, bool? Failure)? QueryAuditPolicy(string subcategoryGuid)
        {
            try
            {
                EnableSecurityPrivilege();
                var ids = new[] { new Guid(subcategoryGuid) };
                if (!AuditQuerySystemPolicy(ids, 1, out var buffer) || buffer == IntPtr.Zero) return null;
                try
                {
                    var info = Marshal.PtrToStructure<AuditPolicyInformation>(buffer);
                    return ((info.AuditingInformation & PolicyAuditEventSuccess) != 0,
                            (info.AuditingInformation & PolicyAuditEventFailure) != 0);
                }
                finally { AuditFree(buffer); }
            }
            catch { return null; }
        }

        // Fallback: auditpol's own words. Column 5 of its CSV is the setting, written in the
        // Windows language; English and German are known here, anything else stays unknown.
        private static (bool? Success, bool? Failure) ParseAuditpol()
        {
            var output = RunAuditpol($"/get /subcategory:{WfpConnectionAudit} /r", out var exit);
            if (exit != 0 || string.IsNullOrWhiteSpace(output)) return (null, null);

            var rows = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (rows.Length < 2) return (null, null);
            var cols = rows[1].Split(',');
            if (cols.Length < 5) return (null, null);

            var setting = cols[4].Trim();
            if (setting.Equals("No Auditing", StringComparison.OrdinalIgnoreCase) ||
                setting.Equals("Keine Überwachung", StringComparison.OrdinalIgnoreCase)) return (false, false);
            var success = setting.Contains("Success", StringComparison.OrdinalIgnoreCase)
                       || setting.Contains("Erfolg",  StringComparison.OrdinalIgnoreCase);
            var failure = setting.Contains("Failure", StringComparison.OrdinalIgnoreCase)
                       || setting.Contains("Fehler",  StringComparison.OrdinalIgnoreCase);
            return success || failure ? (success, failure) : (null, null);
        }

        private const uint PolicyAuditEventSuccess = 0x1;
        private const uint PolicyAuditEventFailure = 0x2;

        [StructLayout(LayoutKind.Sequential)]
        private struct AuditPolicyInformation
        {
            public Guid AuditSubCategoryGuid;
            public uint AuditingInformation;
            public Guid AuditCategoryGuid;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AuditQuerySystemPolicy([In] Guid[] subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);

        // SeSecurityPrivilege: held by administrators, off until switched on for this process.
        private static bool _securityPrivilegeOn;

        private static void EnableSecurityPrivilege()
        {
            if (_securityPrivilegeOn) return;
            if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token)) return;
            try
            {
                if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out var luid)) return;
                var tp = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = SePrivilegeEnabled };
                if (AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)
                    && Marshal.GetLastWin32Error() == 0)
                    _securityPrivilegeOn = true;
            }
            finally { CloseHandle(token); }
        }

        private const uint TokenAdjustPrivileges = 0x0020;
        private const uint TokenQuery            = 0x0008;
        private const uint SePrivilegeEnabled    = 0x0002;

        [StructLayout(LayoutKind.Sequential)]
        private struct Luid { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct TokenPrivileges
        {
            public uint PrivilegeCount;
            public Luid Luid;
            public uint Attributes;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges newState,
                                                         uint bufferLength, IntPtr previousState, IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        /// <summary>Why the audit settings can't be changed here, or null.</summary>
        public static string? AuditpolMissing => WindowsTools.NotFound(WindowsTools.Tool.Auditpol, "audit settings can't be changed") is { } m ? m + "." : null;

        /// <summary>Switches recording of allowed connections on or off. Leaves "failure" as it is.</summary>
        public static bool SetAllowAuditing(bool on)
        {
            RunAuditpol($"/set /subcategory:{WfpConnectionAudit} /success:{(on ? "enable" : "disable")}", out var exit);
            return exit == 0;
        }

        /// <summary>Switches auditing of blocked connections on or off. Leaves "success" as it is.</summary>
        public static bool SetDropAuditing(bool on)
        {
            RunAuditpol($"/set /subcategory:{WfpConnectionAudit} /failure:{(on ? "enable" : "disable")}", out var exit);
            return exit == 0;
        }

        /// <summary>Switches the success half of any audit subcategory (by ID) on or off.</summary>
        internal static bool SetAuditSuccess(string subcategoryGuid, bool on)
        {
            RunAuditpol($"/set /subcategory:{subcategoryGuid} /success:{(on ? "enable" : "disable")}", out var exit);
            return exit == 0;
        }

        private static string? RunAuditpol(string args, out int exitCode)
        {
            exitCode = -1;
            if (!WindowsTools.Exists(WindowsTools.Tool.Auditpol)) return null;   // read as "unknown", like a failed run
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.Auditpol), Arguments = args,
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true
                });
                if (p == null) return null;
                var output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);
                exitCode = p.HasExited ? p.ExitCode : -1;
                return output;
            }
            catch { return null; }
        }

        // ── Reading events ────────────────────────────────────────────────────

        /// <summary>
        /// Newest first, at most 2000, optionally only those since <paramref name="since"/>.
        /// Blocked (5157) always; allowed (5156) are there only while their audit is on.
        /// newestRecordId: the newest event read, parsed or not; 0 if none was read.
        /// </summary>
        public static List<LiveEvent> Read(DateTime? since, out long newestRecordId)
        {
            newestRecordId = 0;
            var xpath = ConnectionEvents;
            if (since.HasValue)
            {
                var ms = Math.Max(1000, (long)(DateTime.Now - since.Value).TotalMilliseconds);
                xpath = $"*[System[(EventID=5157 or EventID=5156) and TimeCreated[timediff(@SystemTime) <= {ms}]]]";
            }

            var query = new EventLogQuery("Security", PathType.LogName, xpath) { ReverseDirection = true };
            var list  = new List<LiveEvent>();
            using (var reader = new EventLogReader(query))
            {
                for (var ev = reader.ReadEvent(); ev != null && list.Count < MaxEntries; ev = reader.ReadEvent())
                {
                    using (ev)
                    {
                        newestRecordId = Math.Max(newestRecordId, ev.RecordId ?? 0);
                        var parsed = Parse(ev);
                        if (parsed != null) list.Add(parsed);
                    }
                }
                // Full? Then see whether anything older was left behind.
                if (list.Count >= MaxEntries)
                {
                    using var more = reader.ReadEvent();
                    LastReadTruncated = more != null;
                }
                else LastReadTruncated = false;
            }
            return NameServices(list);
        }

        private const string ConnectionEvents = "*[System[(EventID=5157 or EventID=5156)]]";

        /// <summary>Connections written after the cursor's mark, newest first, at most <see cref="MaxEntries"/>.</summary>
        public static List<LiveEvent> ReadOn(LogCursor cursor)
        {
            // Newest first, and only as far back as is kept: after a long gap with allowed
            // connections recorded, every event since the mark could be hundreds of thousands.
            var list = new List<LiveEvent>();
            cursor.ReadNewestOn(ConnectionEvents, ev =>
            {
                if (Parse(ev) is { } parsed) list.Add(parsed);
                return list.Count < MaxEntries;
            });
            return NameServices(list);
        }

        /// <summary>
        /// Pushes each new connection event as Windows writes it (on a pool thread), or null if
        /// the subscription can't be made. onFailed: the subscription broke; read on instead.
        /// Dispose the watcher to stop it.
        /// </summary>
        public static EventLogWatcher? Watch(Action<LiveEvent> onEvent, Action onFailed)
        {
            EventLogWatcher? watcher = null;
            try
            {
                watcher = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, ConnectionEvents));
                watcher.EventRecordWritten += (_, a) =>
                {
                    if (a.EventException != null) { onFailed(); return; }
                    using var ev = a.EventRecord;
                    if (ev != null && Parse(ev) is { } parsed) onEvent(parsed);
                };
                watcher.Enabled = true;
                return watcher;
            }
            catch
            {
                try { watcher?.Dispose(); } catch { }
                return null;
            }
        }

        // Source/Destination in event 5157 follow the packet (sender → receiver) in both
        // directions, like the file log: an inbound IGMP query shows the router as Source and
        // the multicast group as Destination. No swapping. Protocols without ports (ICMP, IGMP,
        // GRE…) report port 0, shown as blank like the file log's "-".
        private static LiveEvent? Parse(EventRecord ev)
        {
            try
            {
                var data = EventFields.Of(ev);

                string Get(string k) => data.TryGetValue(k, out var v) ? v : "";

                var inbound  = Get("Direction").Contains("14592");   // %%14592 = Inbound, %%14593 = Outbound
                var protocol = ProtocolName(Get("Protocol"));
                var ported   = protocol is "TCP" or "UDP";
                string Port(string p) => ported && p != "0" ? p : "";

                int.TryParse(Get("ProcessID"), out var pid);
                long.TryParse(Get("FilterRTID"), out var filter);

                var time = ev.TimeCreated ?? DateTime.Now;
                if (time.Kind == DateTimeKind.Utc) time = time.ToLocalTime();

                return new LiveEvent(
                    ev.Id == 5156 ? "ALLOW" : "DROP",
                    time,
                    inbound ? "RECEIVE" : "SEND",
                    protocol,
                    Get("SourceAddress"), Port(Get("SourcePort")),
                    Get("DestAddress"),   Port(Get("DestPort")),
                    RealSpelling(ToDosPath(Get("Application"))),
                    pid) { FilterId = filter, RecordId = ev.RecordId ?? 0 };
            }
            catch { return null; }
        }

        // The shared table, so the log names a protocol as the rule list and the editor do. A
        // packet always has a protocol: a missing field stays blank, not "Any".
        private static string ProtocolName(string number) =>
            number.Trim().Length == 0 ? "" : Protocols.Name(number);

        // ── \device\harddiskvolumeN\… → C:\… ─────────────────────────────────

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

        // A volume mounted after the map was built (a USB stick, a VHD) isn't in it, so a path it
        // can't place rebuilds it. At most every 5 s: paths no drive letter covers (network
        // shares) would otherwise rebuild it on every event. The watcher and the readers parse
        // on their own threads: each build is a new map swapped in whole and never changed after.
        private static volatile Dictionary<string, string>? _deviceMap;
        private static long _deviceMapBuilt;                            // Environment.TickCount64, under the gate
        private static readonly object _deviceMapGate = new();
        private const long DeviceMapRebuildMs = 5000;

        private static string ToDosPath(string path)
        {
            if (!path.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase)) return path;
            var map = _deviceMap ?? DeviceMap(null);
            if (OnDrive(map, path) is { } dos) return dos;
            var fresh = DeviceMap(map);
            return ReferenceEquals(fresh, map) ? path : OnDrive(fresh, path) ?? path;
        }

        private static string? OnDrive(Dictionary<string, string> map, string path)
        {
            foreach (var (device, drive) in map)
                if (path.StartsWith(device + @"\", StringComparison.OrdinalIgnoreCase))
                    return drive + path[device.Length..];
            return null;
        }

        // A new map, unless another thread swapped one in since `seen` was read (that one is
        // as new) or the last build is under 5 s old (the same map comes back).
        private static Dictionary<string, string> DeviceMap(Dictionary<string, string>? seen)
        {
            lock (_deviceMapGate)
            {
                var current = _deviceMap;
                if (current != null && (!ReferenceEquals(current, seen)
                                        || Environment.TickCount64 - _deviceMapBuilt < DeviceMapRebuildMs))
                    return current;
                var built = BuildDeviceMap();
                _deviceMapBuilt = Environment.TickCount64;
                _deviceMap = built;
                return built;
            }
        }

        private static Dictionary<string, string> BuildDeviceMap()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] roots;
            try { roots = Environment.GetLogicalDrives(); }
            catch { return map; }                                       // raw paths until the next build
            foreach (var root in roots)                                 // "C:\"
            {
                var drive = root.TrimEnd('\\');                         // "C:"
                var sb = new StringBuilder(512);
                if (QueryDosDevice(drive, sb, (uint)sb.Capacity) != 0)
                    map[sb.ToString()] = drive;                         // "\Device\HarddiskVolume3" → "C:"
            }
            return map;
        }

        // ── The spelling on the disk ──────────────────────────────────────────
        //
        // The Security log hands paths over in lower case. Windows matches them either way, and
        // so does every comparison here; the real spelling is for reading. Looked up on the
        // thread that parses the event (never the window's), once per path while the app runs.

        private static readonly ConcurrentDictionary<string, string> _spelling = new(StringComparer.OrdinalIgnoreCase);
        // Program paths repeat; a bound only for a machine that runs endless one-off programs.
        private const int MaxSpellings = 4000;

        /// <summary>
        /// The path as the disk spells it; as given where it isn't there (any more), can't be
        /// read, or isn't a full path ("System").
        /// </summary>
        public static string RealSpelling(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            if (_spelling.TryGetValue(path, out var known)) return known;
            // Full: as given, rather than a walk over the disk for every event.
            if (_spelling.Count >= MaxSpellings) return path;
            return _spelling.GetOrAdd(path, SpellingOnDisk(path));
        }

        // One directory listing per part, matched by name (no wildcards in a real path). A
        // folder that can't be listed keeps what was spelled before it; the rest stays as given.
        private static string SpellingOnDisk(string path)
        {
            try
            {
                if (!Path.IsPathFullyQualified(path) || path.IndexOfAny(new[] { '*', '?' }) >= 0) return path;
                var root = Path.GetPathRoot(path) ?? "";
                if (root.Length == 0) return path;
                var parts = path[root.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Any(p => p is "." or "..")) return path;
                // "c:\" → "C:\"; a share's name stays as written.
                var result = root.Length >= 2 && root[1] == ':' ? char.ToUpperInvariant(root[0]) + root[1..] : root;
                for (var i = 0; i < parts.Length; i++)
                {
                    string? found;
                    try { found = Directory.EnumerateFileSystemEntries(result, parts[i]).FirstOrDefault(); }
                    catch { return Path.Combine(new[] { result }.Concat(parts[i..]).ToArray()); }
                    if (found == null) return path;                   // not there (any more)
                    result = Path.Combine(result, Path.GetFileName(found));
                }
                return result;
            }
            catch { return path; }
        }

        // ── Which services a process hosts (svchost.exe says nothing on its own) ──
        //
        // The event carries only the process ID, and the service control manager can name the
        // services only while that process runs. Short-lived hosts (update scans, time sync)
        // are often gone by the time the log is read, so every host seen running is remembered
        // in memory while the app is open. An event is named only if it falls within that very
        // process's lifetime (start ≤ event ≤ last seen), so a reused process ID never lends
        // its services to an earlier event; anything else stays unnamed.

        private sealed class HostSeen
        {
            public DateTime Start;
            public string   Image = "";
            public DateTime LastSeen;
            public readonly SortedDictionary<string, string> Services = new(StringComparer.OrdinalIgnoreCase);
        }

        private static readonly Dictionary<int, List<HostSeen>> _hostsSeen = new();
        private static readonly object _hostsGate = new();
        private const int MaxHostsRemembered = 4000;

        /// <summary>Notes every process that hosts a running service right now.</summary>
        public static void ObserveServices()
        {
            var now = DateTime.Now;
            foreach (var (pid, services) in ServicesByProcess())
            {
                DateTime start; string image;
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    start = proc.StartTime;
                    image = proc.ProcessName;
                }
                catch { continue; }   // gone meanwhile, or not accessible

                lock (_hostsGate)
                {
                    if (!_hostsSeen.TryGetValue(pid, out var list)) _hostsSeen[pid] = list = new List<HostSeen>();
                    var host = list.FirstOrDefault(h => h.Start == start);
                    if (host == null)
                        list.Add(host = new HostSeen { Start = start, Image = image });
                    foreach (var (name, display) in services) host.Services[name] = display;   // services can join a host later
                    host.LastSeen = now;
                }
            }

            lock (_hostsGate)
            {
                // Bounded: drop the longest-unseen hosts if a long session collects too many.
                var all = _hostsSeen.SelectMany(kv => kv.Value.Select(h => (kv.Key, h))).ToList();
                if (all.Count <= MaxHostsRemembered) return;
                foreach (var (pid, h) in all.OrderBy(x => x.h.LastSeen).Take(all.Count - MaxHostsRemembered))
                {
                    _hostsSeen[pid].Remove(h);
                    if (_hostsSeen[pid].Count == 0) _hostsSeen.Remove(pid);
                }
            }
        }

        /// <summary>
        /// The services a process hosted at a given moment, from what has been seen running
        /// (see above): "" if unknown. For other readers of process IDs (the DNS log).
        /// </summary>
        public static (string Short, string Long) ServicesAt(int pid, string image, DateTime time)
        {
            lock (_hostsGate)
            {
                if (pid <= 0 || !_hostsSeen.TryGetValue(pid, out var list)) return ("", "");
                var host = list
                    .Where(h => h.Image.Equals(image, StringComparison.OrdinalIgnoreCase)
                                && h.Start <= time.AddSeconds(1) && time <= h.LastSeen)
                    .OrderByDescending(h => h.Start)
                    .FirstOrDefault();
                if (host == null || host.Services.Count == 0) return ("", "");
                return (string.Join(", ", host.Services.Keys),
                        string.Join("\n", host.Services.Select(s => $"{s.Key} — {s.Value}")));
            }
        }

        /// <summary>The events with the services of their process, where known (see above).</summary>
        public static List<LiveEvent> NameServices(List<LiveEvent> events)
        {
            ObserveServices();
            lock (_hostsGate)
            {
                return events.Select(ev =>
                {
                    if (ev.ProcessId <= 0 || !_hostsSeen.TryGetValue(ev.ProcessId, out var list)) return ev;
                    var image = Path.GetFileNameWithoutExtension(ev.Program);
                    var host = list
                        .Where(h => h.Image.Equals(image, StringComparison.OrdinalIgnoreCase)
                                    && h.Start <= ev.Time.AddSeconds(1)          // clocks round differently
                                    && ev.Time <= h.LastSeen)
                        .OrderByDescending(h => h.Start)
                        .FirstOrDefault();
                    if (host == null || host.Services.Count == 0) return ev;

                    return ev with
                    {
                        Services     = string.Join(", ", host.Services.Keys),
                        ServicesLong = string.Join("\n", host.Services.Select(s => $"{s.Key} — {s.Value}")),
                    };
                }).ToList();
            }
        }

        private const uint ScManagerEnumerateService = 0x0004;
        private const int  ScEnumProcessInfo         = 0;
        private const uint ServiceWin32              = 0x00000030;
        private const uint ServiceActive             = 0x00000001;
        private const int  ErrorMoreData             = 234;

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatusProcess
        {
            public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
                        ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EnumServiceStatusProcess
        {
            public IntPtr ServiceName;
            public IntPtr DisplayName;
            public ServiceStatusProcess Status;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool EnumServicesStatusEx(IntPtr hSCManager, int infoLevel, uint serviceType,
            uint serviceState, IntPtr services, uint bufSize, out uint bytesNeeded, out uint servicesReturned,
            ref uint resumeHandle, string? groupName);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        private static Dictionary<int, List<(string Name, string Display)>> ServicesByProcess()
        {
            var map = new Dictionary<int, List<(string, string)>>();
            foreach (var (name, display, pid) in EnumServices(ServiceWin32, ServiceActive))
            {
                if (pid == 0) continue;
                if (!map.TryGetValue(pid, out var list)) map[pid] = list = new List<(string, string)>();
                list.Add((name, display));
            }
            return map;
        }

        public sealed record ServiceChoice(string Name, string Display);

        /// <summary>
        /// Every service that runs inside a shared svchost.exe process, running or not, sorted by
        /// name: the choices for scoping a firewall rule to one service (Svc=…).
        /// </summary>
        public static List<ServiceChoice> SharedProcessServices() =>
            EnumServices(ServiceWin32ShareProcess, ServiceStateAll)
                .Select(s => new ServiceChoice(s.Name, s.Display))
                .GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase).Select(g => g.First())
                .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

        private const uint ServiceWin32ShareProcess = 0x00000020;
        private const uint ServiceStateAll          = 0x00000003;

        private static List<(string Name, string Display, int Pid)> EnumServices(uint type, uint state)
        {
            var result = new List<(string, string, int)>();
            var scm = OpenSCManager(null, null, ScManagerEnumerateService);
            if (scm == IntPtr.Zero) return result;
            try
            {
                uint resume = 0;
                var size = 64 * 1024;
                while (true)
                {
                    var buffer = Marshal.AllocHGlobal(size);
                    try
                    {
                        var done = EnumServicesStatusEx(scm, ScEnumProcessInfo, type, state,
                            buffer, (uint)size, out var needed, out var count, ref resume, null);
                        var error = done ? 0 : Marshal.GetLastWin32Error();
                        if (!done && error != ErrorMoreData) return result;

                        var itemSize = Marshal.SizeOf<EnumServiceStatusProcess>();
                        for (var i = 0; i < count; i++)
                        {
                            var item = Marshal.PtrToStructure<EnumServiceStatusProcess>(buffer + i * itemSize);
                            var name    = Marshal.PtrToStringUni(item.ServiceName) ?? "";
                            var display = Marshal.PtrToStringUni(item.DisplayName) ?? name;
                            result.Add((name, display, (int)item.Status.ProcessId));
                        }

                        if (done) return result;
                        if (count == 0) size = (int)Math.Max(needed, (uint)size * 2);   // buffer too small for even one
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
            }
            finally { CloseServiceHandle(scm); }
        }

        /// <summary>File name for the grid ("firefox.exe"); the full path goes in the tooltip.</summary>
        public static string ShortProgram(string path) =>
            string.IsNullOrEmpty(path) ? "" :
            path.Contains('\\') ? Path.GetFileName(path) : path;
    }

    /// <summary>
    /// Where a reader of one event log left off, so the next read takes only what was written
    /// since. The mark is the log's newest event of any kind: a filtered read that stops at the
    /// last match would scan back over everything that didn't match, every time.
    /// </summary>
    internal sealed class LogCursor
    {
        private readonly string _log;
        private EventBookmark? _mark;     // null: start of the log
        private long _markId;
        // Unset while the log couldn't be read: the first read that works only sets the mark,
        // rather than take the whole log for new.
        private bool _set;

        /// <summary>Marks the log's newest event now: whatever is written after it is new.</summary>
        public LogCursor(string log)
        {
            _log = log;
            var (mark, id) = Newest(log);
            if (id >= 0) (_mark, _markId, _set) = (mark, id, true);
        }

        /// <summary>
        /// Calls each for every event matching the XPath written since the last read, oldest
        /// first, then moves the mark to the end of what was read.
        /// </summary>
        public void ReadOn(string xpath, Action<EventRecord> each)
        {
            var (end, endId) = Newest(_log);
            if (endId < 0) return;                                // unreadable: try again next time
            if (!_set) { (_mark, _markId, _set) = (end, endId, true); return; }
            if (endId == _markId) return;                         // nothing new
            if (endId < _markId) (_mark, _markId) = (null, 0);    // cleared: read it from its start

            var after = _markId;
            try { Read(new EventLogReader(new EventLogQuery(_log, PathType.LogName, xpath), _mark), ref after, endId, each); }
            catch (EventLogException) when (_mark != null)
            {
                // The marked event is gone (the log wrapped): ask by number instead.
                var byId = xpath.Replace("*[System[", $"*[System[EventRecordID > {after} and ");
                Read(new EventLogReader(new EventLogQuery(_log, PathType.LogName, byId)), ref after, endId, each);
            }
            (_mark, _markId) = (end, endId);
        }

        /// <summary>
        /// Like <see cref="ReadOn"/>, but newest first, stopping as soon as each returns false:
        /// a catch-up after a long gap reads only as far back as it keeps, rather than every
        /// event since the mark. The mark still moves to the end of the log.
        /// </summary>
        public void ReadNewestOn(string xpath, Func<EventRecord, bool> each)
        {
            var (end, endId) = Newest(_log);
            if (endId < 0) return;                                // unreadable: try again next time
            if (!_set) { (_mark, _markId, _set) = (end, endId, true); return; }
            if (endId == _markId) return;                         // nothing new
            if (endId < _markId) (_mark, _markId) = (null, 0);    // cleared: read it from its start

            // Backwards from the end, stopping at the first match at or before the mark. The
            // range is checked here, not in the filter: the log has no index on record numbers,
            // so a filtered range would be tested against every older event, back to the start.
            using (var reader = new EventLogReader(new EventLogQuery(_log, PathType.LogName, xpath) { ReverseDirection = true }))
                for (var ev = reader.ReadEvent(); ev != null; ev = reader.ReadEvent())
                    using (ev)
                    {
                        var id = ev.RecordId ?? 0;
                        if (id > endId) continue;                // written meanwhile: next time
                        if (id <= _markId) break;                // read before
                        if (!each(ev)) break;
                    }
            (_mark, _markId) = (end, endId);
        }

        // Hands on the events numbered after "after" up to endId; "after" follows what was handed on.
        private static void Read(EventLogReader reader, ref long after, long endId, Action<EventRecord> each)
        {
            using (reader)
                for (var ev = reader.ReadEvent(); ev != null; ev = reader.ReadEvent())
                    using (ev)
                    {
                        var id = ev.RecordId ?? 0;
                        if (id <= after) continue;
                        if (id > endId) break;                   // written meanwhile: next time
                        each(ev);
                        after = id;
                    }
        }

        /// <summary>
        /// The number of the log's newest event: 0 for an empty log, -1 if it can't be read. One
        /// event read, so a reader can ask every few seconds whether anything was written.
        /// </summary>
        public static long NewestId(string log) => Newest(log).Id;

        // The newest event and its number: (null, 0) for an empty log, -1 if it can't be read.
        private static (EventBookmark? Mark, long Id) Newest(string log)
        {
            try
            {
                using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName) { ReverseDirection = true });
                using var ev = reader.ReadEvent();
                return ev == null ? (null, 0) : (ev.Bookmark, ev.RecordId ?? 0);
            }
            catch { return (null, -1); }
        }
    }
}
