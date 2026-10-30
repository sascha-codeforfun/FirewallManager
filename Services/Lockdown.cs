using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// One-click lock-down for a fresh machine: all profiles block in and out with merge off,
    /// Windows' local rules purged, recording switched on, and, when the session arrived over
    /// Remote Desktop, a rule for exactly that client so the lock-down can't cut it off.
    ///
    /// Before anything is written, the firewall state is saved twice: a .reg file that first
    /// deletes the policy key and then recreates it as it was (plus the local rules), and the
    /// firewall's own export of the local store (.wfw). Restoring is `reg import` of the one and
    /// `netsh advfirewall import` of the other, so the app and the scheduled backstop restore
    /// the same way, and the running firewall has Windows' local rules back at once: the
    /// lock-down removes them through the firewall, which a .reg import alone can't undo.
    ///
    /// The local rules go only once the lock-down's policy is in force, so there is no moment
    /// in which a Remote Desktop session is allowed by neither the old rules nor the new ones.
    ///
    /// Windows' service-hardening rules are left as they are, on purpose: see "Purging obsolete
    /// rules" in ServiceHardening before adding them here.
    /// </summary>
    internal static class Lockdown
    {
        private const string PolicyRoot = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";
        private const string LocalRulesKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        private const string RdpTcp     = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
        public  const string BackstopTask = "FirewallManager lock-down failsafe";

        private static readonly string[] ProfileKeys = { "DomainProfile", "PrivateProfile", "PublicProfile" };
        private static readonly string[] ProfileValues = { "EnableFirewall", "DefaultInboundAction", "DefaultOutboundAction", "AllowLocalPolicyMerge" };

        // ── What is there now ──────────────────────────────────────────────────

        public sealed record Existing(int PolicyRules, int ProfileSettings, int LocalRuleCount)
        {
            /// <summary>Nothing configured in the policy yet: lock down without asking.</summary>
            public bool Fresh => PolicyRules == 0 && ProfileSettings == 0;
        }

        public static Existing Inspect()
        {
            int rules = 0, settings = 0, local = 0;
            using (var k = Registry.LocalMachine.OpenSubKey($@"{PolicyRoot}\FirewallRules"))
                rules = k?.ValueCount ?? 0;
            foreach (var p in ProfileKeys)
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"{PolicyRoot}\{p}");
                if (k != null) settings += ProfileValues.Count(v => k.GetValue(v) != null);
            }
            using (var k = Registry.LocalMachine.OpenSubKey(LocalRulesKey))
                local = k?.ValueCount ?? 0;
            return new Existing(rules, settings, local);
        }

        // ── Remote Desktop ─────────────────────────────────────────────────────

        public static int RdpPort()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(RdpTcp);
                if (k?.GetValue("PortNumber") is int p && p is > 0 and < 65536) return p;
            }
            catch { }
            return 3389;
        }

        /// <summary>The port setting; false (and 3389) when it can't be read, so the caller can say it assumed one.</summary>
        public static bool TryRdpPort(out int port)
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(RdpTcp);
                if (k?.GetValue("PortNumber") is int p && p is > 0 and < 65536) { port = p; return true; }
            }
            catch { }
            port = 3389;
            return false;
        }

        /// <summary>
        /// The TCP ports the Remote Desktop service listens on right now: a changed port setting
        /// takes effect only when the service restarts, so until then the setting and the port
        /// in use differ. Empty when the service isn't running; null if it can't be read.
        /// </summary>
        public static List<int>? RdpListeningPorts()
        {
            try
            {
                var pid = TermServicePid();
                if (pid == null) return null;
                if (pid == 0) return new List<int>();
                var v4 = ServiceListeners(AF_INET, pid.Value);
                if (v4 == null) return null;
                // The service listens on the same port in both families, so an unreadable IPv6
                // table loses nothing the IPv4 one doesn't show.
                var v6 = ServiceListeners(AF_INET6, pid.Value) ?? new List<int>();
                return v4.Concat(v6).Distinct().OrderBy(p => p).ToList();
            }
            catch { return null; }
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, byte[] buffer, int size, out int needed);
        [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
        private const uint SC_MANAGER_CONNECT = 0x0001, SERVICE_QUERY_STATUS = 0x0004;
        private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;

        // The process the service runs in; 0 when it isn't running (or doesn't exist), null if unreadable.
        private static int? TermServicePid()
        {
            var manager = OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (manager == IntPtr.Zero) return null;
            try
            {
                var service = OpenService(manager, "TermService", SERVICE_QUERY_STATUS);
                if (service == IntPtr.Zero) return Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST ? 0 : null;
                try
                {
                    // SERVICE_STATUS_PROCESS: nine DWORDs, the process ID is the eighth.
                    var status = new byte[36];
                    if (!QueryServiceStatusEx(service, 0, status, status.Length, out _)) return null;
                    return BitConverter.ToInt32(status, 28);
                }
                finally { CloseServiceHandle(service); }
            }
            finally { CloseServiceHandle(manager); }
        }

        [DllImport("iphlpapi.dll")]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, int reserved);
        [DllImport("iphlpapi.dll")]
        private static extern uint GetOwnerModuleFromTcpEntry(IntPtr row, int infoClass, IntPtr buffer, ref int size);
        [DllImport("iphlpapi.dll")]
        private static extern uint GetOwnerModuleFromTcp6Entry(IntPtr row, int infoClass, IntPtr buffer, ref int size);
        private const int AF_INET = 2, AF_INET6 = 23, TCP_TABLE_OWNER_MODULE_LISTENER = 6;
        private const uint ERROR_INSUFFICIENT_BUFFER = 122;

        // MIB_TCPROW_OWNER_MODULE / MIB_TCP6ROW_OWNER_MODULE: size, and where the port and the process ID sit.
        private static (int Size, int Port, int Pid) RowLayout(int family) => family == AF_INET ? (160, 8, 20) : (192, 20, 52);

        /// <summary>
        /// Listening ports of that process. When the process hosts other services too (a shared
        /// svchost), a row another service owns is left out; a row whose owner can't be named
        /// stays, as it is in the service's process.
        /// </summary>
        private static List<int>? ServiceListeners(int family, int pid)
        {
            var (rowSize, portAt, pidAt) = RowLayout(family);
            var size = 0;
            var code = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_MODULE_LISTENER, 0);
            if (code != 0 && code != ERROR_INSUFFICIENT_BUFFER) return null;
            // The table can grow between the size query and the read.
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var table = Marshal.AllocHGlobal(Math.Max(size, 8));
                try
                {
                    code = GetExtendedTcpTable(table, ref size, false, family, TCP_TABLE_OWNER_MODULE_LISTENER, 0);
                    if (code == ERROR_INSUFFICIENT_BUFFER) continue;
                    if (code != 0) return null;
                    var ports = new List<int>();
                    var count = Marshal.ReadInt32(table);
                    for (var i = 0; i < count; i++)
                    {
                        var row = table + 8 + i * rowSize;   // the rows hold 8-byte members, so they start at 8
                        if (Marshal.ReadInt32(row, pidAt) != pid) continue;
                        if (OwnerModule(row, family) is { } owner &&
                            !owner.Equals("TermService", StringComparison.OrdinalIgnoreCase) &&
                            !owner.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            continue;
                        var raw = Marshal.ReadInt32(row, portAt);
                        ports.Add(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));   // network byte order
                    }
                    return ports;
                }
                finally { Marshal.FreeHGlobal(table); }
            }
            return null;
        }

        // The service (or program) a listening row belongs to, as Windows names it; null if unknown.
        private static string? OwnerModule(IntPtr row, int family)
        {
            var size = 0;
            var code = family == AF_INET ? GetOwnerModuleFromTcpEntry(row, 0, IntPtr.Zero, ref size)
                                         : GetOwnerModuleFromTcp6Entry(row, 0, IntPtr.Zero, ref size);
            if (code != ERROR_INSUFFICIENT_BUFFER || size <= 0) return null;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                code = family == AF_INET ? GetOwnerModuleFromTcpEntry(row, 0, buffer, ref size)
                                         : GetOwnerModuleFromTcp6Entry(row, 0, buffer, ref size);
                if (code != 0) return null;
                var name = Marshal.ReadIntPtr(buffer);   // TCPIP_OWNER_MODULE_BASIC_INFO.pModuleName
                return name == IntPtr.Zero ? null : Marshal.PtrToStringUni(name);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        /// <summary>
        /// Addresses with an established connection to this machine's RDP port, other than this
        /// machine's own (those are a tunnel, see RdpTunnelPorts). Decided by the
        /// network connection, not the session type: a Hyper-V enhanced session is RDP over the
        /// VM bus, which the firewall never sees, so it needs no rule and no failsafe.
        /// Null if the connection table can't be read: then nothing can be assumed.
        /// </summary>
        public static List<string>? RdpClients(int port)
        {
            try
            {
                var self = ThisMachine();
                return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                    .Where(c => c.State == TcpState.Established && c.LocalEndPoint.Port == port)
                    .Select(c => Plain(c.RemoteEndPoint.Address))   // no %zone in a rule
                    .Where(a => !self(a))
                    .Select(a => a.ToString())
                    .Distinct()
                    .ToList();
            }
            catch { return null; }
        }

        /// <summary>
        /// The ports among these with an established connection from this machine itself
        /// (127.0.0.0/8, ::1, or one of its own addresses): Remote Desktop arriving through a tunnel (SSH, a VPN client's local
        /// forward). The firewall doesn't filter that loopback leg; what a change can cut is the
        /// tunnel's own connection from the network, which isn't seen from here. Null if the
        /// connection table can't be read.
        /// </summary>
        public static List<int>? RdpTunnelPorts(IEnumerable<int> ports)
        {
            try
            {
                var wanted = ports.ToHashSet();
                var self = ThisMachine();
                return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                    .Where(c => c.State == TcpState.Established && wanted.Contains(c.LocalEndPoint.Port))
                    .Where(c => self(Plain(c.RemoteEndPoint.Address)))
                    .Select(c => c.LocalEndPoint.Port)
                    .Distinct()
                    .OrderBy(p => p)
                    .ToList();
            }
            catch { return null; }
        }

        // Names by which VPN and tunnel adapters can be recognised in an adapter's name or
        // description. Recognisable names, not proof: an adapter can be named anything, and one
        // not named here counts only by its type (Ppp or Tunnel).
        private static readonly string[] VpnAdapterNames =
        {
            "Wintun", "WireGuard", "Tailscale", "OpenVPN", "TAP-Windows", "ZeroTier",
            "Fortinet", "Cisco AnyConnect", "GlobalProtect", "PANGP",
        };

        /// <summary>
        /// The VPN or tunnel adapters that network Remote Desktop clients come in on: for each
        /// established connection on these ports from another machine, the adapter its local
        /// address belongs to, when that adapter is of type Tunnel, is a connection Windows dialled
        /// as a VPN, or carries one of the recognisable names. As shown to the operator ("Tailscale", "Ethernet 3: TAP-Windows
        /// Adapter V9"); empty when none; null when the connections or adapters can't be read.
        /// Outbound block ends the program that carries such a connection unless a rule lets it out.
        /// </summary>
        public static List<string>? RdpVpnAdapters(IEnumerable<int> ports)
        {
            try
            {
                var wanted = ports.ToHashSet();
                var self = ThisMachine();
                var locals = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                    .Where(c => c.State == TcpState.Established && wanted.Contains(c.LocalEndPoint.Port))
                    .Where(c => !self(Plain(c.RemoteEndPoint.Address)))
                    .Select(c => Plain(c.LocalEndPoint.Address))
                    .ToHashSet();
                if (locals.Count == 0) return new List<string>();
                var found = new List<string>();
                HashSet<string>? rasVpn = null;   // read only when a PPP adapter carries a session
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (!nic.GetIPProperties().UnicastAddresses.Any(u => locals.Contains(Plain(u.Address)))) continue;
                    // PPP is also PPPoE broadband and the dial-in server's interface: only one
                    // Windows dials as a VPN counts by type (its adapter bears the entry's name).
                    var vpn = nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel ||
                              nic.NetworkInterfaceType == NetworkInterfaceType.Ppp && (rasVpn ??= RasVpnEntries()).Contains(nic.Name) ||
                              VpnAdapterNames.Any(n => nic.Name.Contains(n, StringComparison.OrdinalIgnoreCase) ||
                                                       nic.Description.Contains(n, StringComparison.OrdinalIgnoreCase));
                    if (!vpn) continue;
                    // The name the operator gave it, and what it is when the name doesn't say.
                    found.Add(nic.Description.Length == 0 ? nic.Name
                              : nic.Description.Contains(nic.Name, StringComparison.OrdinalIgnoreCase) ? nic.Description
                              : $"{nic.Name}: {nic.Description}");
                }
                return found.Distinct().ToList();
            }
            catch { return null; }
        }

        // The entry names of the connections Windows has dialled as a VPN (device type "vpn", not
        // "PPPoE", "modem", …). Empty when there are none or they can't be read: then a PPP
        // adapter counts only by a recognisable name.
        private static HashSet<string> RasVpnEntries()
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                // The record as declared; should Windows refuse its size, the unpacked one once.
                foreach (var entrySize in new[] { Marshal.SizeOf<RASCONN>(), 1392 }.Distinct())
                    if (RasConnections(entrySize, names) != ERROR_INVALID_SIZE) break;
            }
            catch { names.Clear(); }
            return names;
        }

        // Fills names from RasEnumConnections with records of entrySize bytes; returns its code.
        private static uint RasConnections(int entrySize, HashSet<string> names)
        {
            var nameAt   = (int)Marshal.OffsetOf<RASCONN>(nameof(RASCONN.szEntryName));
            var deviceAt = (int)Marshal.OffsetOf<RASCONN>(nameof(RASCONN.szDeviceType));
            var size = entrySize;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                size = (Math.Max(size, entrySize) + entrySize - 1) / entrySize * entrySize;   // whole records
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    for (var i = 0; i < size; i++) Marshal.WriteByte(buffer, i, 0);
                    Marshal.WriteInt32(buffer, entrySize);   // the first record's dwSize says the version
                    var code = RasEnumConnections(buffer, ref size, out var count);
                    if (code == ERROR_BUFFER_TOO_SMALL) continue;   // more connections than room: size now says how much
                    if (code != 0) return code;
                    for (var i = 0; i < count && (i + 1) * entrySize <= size; i++)
                    {
                        var entry = buffer + i * entrySize;
                        if ((Marshal.PtrToStringUni(entry + deviceAt) ?? "").Equals("vpn", StringComparison.OrdinalIgnoreCase))
                            names.Add(Marshal.PtrToStringUni(entry + nameAt) ?? "");
                    }
                    return 0;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            return ERROR_BUFFER_TOO_SMALL;
        }

        // RASCONNW as of Windows 7 (ras.h packs it to 4: 1388 bytes on x64, the entry name at 12).
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
        private struct RASCONN
        {
            public int dwSize;
            public IntPtr hrasconn;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szEntryName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)]  public string szDeviceType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szDeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szPhonebook;
            public int dwSubEntry;
            public Guid guidEntry;
            public int dwFlags;
            public long luid;
            public Guid guidCorrelationId;
        }

        private const uint ERROR_BUFFER_TOO_SMALL = 603, ERROR_INVALID_SIZE = 632;

        [DllImport("rasapi32.dll", EntryPoint = "RasEnumConnectionsW", CharSet = CharSet.Unicode)]
        private static extern uint RasEnumConnections(IntPtr connections, ref int size, out int count);

        // IPv4 as such (not mapped into IPv6), IPv6 without a zone, so addresses compare by value.
        private static IPAddress Plain(IPAddress a)
        {
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            return a.AddressFamily == AddressFamily.InterNetworkV6 ? new IPAddress(a.GetAddressBytes()) : a;
        }

        // This machine itself: loopback, or one of its own addresses. A connection between two of
        // them never leaves the machine, so the firewall doesn't filter it. If the adapters can't
        // be read, only loopback counts.
        private static Func<IPAddress, bool> ThisMachine()
        {
            var own = new HashSet<IPAddress>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                    foreach (var u in nic.GetIPProperties().UnicastAddresses)
                        own.Add(Plain(u.Address));
            }
            catch { }
            return a => IPAddress.IsLoopback(a) || own.Contains(a);
        }

        [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
        private const int SM_REMOTESESSION = 0x1000;

        /// <summary>
        /// True when this session is remote. With no client found on the RDP port that means a
        /// Hyper-V enhanced session, or RDP arriving another way (a gateway, a forwarded port).
        /// </summary>
        public static bool IsRemoteSession() => GetSystemMetrics(SM_REMOTESESSION) != 0;

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetGetJoinInformation(string? server, out IntPtr name, out int status);
        [DllImport("netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buffer);
        private const int NetSetupDomainName = 3;

        /// <summary>Domain-joined machines refresh policy against a domain controller.</summary>
        public static bool DomainJoined()
        {
            try
            {
                if (NetGetJoinInformation(null, out var name, out var status) != 0) return false;
                NetApiBufferFree(name);
                return status == NetSetupDomainName;
            }
            catch { return false; }
        }

        /// <summary>
        /// RDP-&lt;last number&gt;-IN, the Setup naming. The full address instead when the short
        /// name is taken by another client in this lock-down, or by an existing rule for another
        /// address: a rule must never replace another client's rule.
        /// </summary>
        public static string RdpRuleName(string address, IReadOnlyCollection<string> allClients)
        {
            static string Last(string a) => a.Contains(':') ? a.Split(':').Last(s => s.Length > 0) : a.Split('.').Last();
            var shortName = $"RDP-{Last(address)}-IN";
            var sharedHere = allClients.Count(c => Last(c) == Last(address)) > 1;
            string? existing = null;
            using (var k = Registry.LocalMachine.OpenSubKey(RuleWriter.RegGPO))
                existing = k?.GetValue(RuleWriter.KeyFor(shortName)) as string;
            var takenElsewhere = existing != null && !existing.Contains($"={address}|", StringComparison.OrdinalIgnoreCase);
            return sharedHere || takenElsewhere ? $"RDP-{address.Replace('.', '-').Replace(':', '-')}-IN" : shortName;
        }

        public static RuleWriter.Spec RdpRule(string address, int port, IReadOnlyCollection<string> allClients) =>
            new(RdpRuleName(address, allClients), Inbound: true, RuleWriter.Tcp, new[] { port.ToString(CultureInfo.InvariantCulture) }, new[] { address },
                Program: @"%SystemRoot%\system32\svchost.exe", Service: "TermService");

        /// <summary>
        /// What writing a rule of this name replaces, said after the name in a confirmation: ""
        /// when there is no such rule (or the store can't be read); " (replacing your switched-off
        /// rule of that name)"; " (replacing the rule of that name, which doesn't let this address
        /// in)" when it is on but doesn't let this client in on this port (strict judgement);
        /// otherwise " (replacing the rule of that name)". Any thread.
        /// </summary>
        public static string ReplaceNote(string ruleName, string client, int port)
        {
            string? raw;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(RuleWriter.RegGPO);
                raw = key?.GetValue(RuleWriter.KeyFor(ruleName)) as string;
            }
            catch { return ""; }
            if (raw == null) return "";
            if (!RuleText.IsOn(raw)) return " (replacing your switched-off rule of that name)";
            if (!IPAddress.TryParse(client, out var address) || !AllowsRdp(raw, address, port))
                return " (replacing the rule of that name, which doesn't let this address in)";
            return " (replacing the rule of that name)";
        }

        /// <summary>
        /// True if a switched-on rule of this app (CUSTOM_ in the policy store) lets this client
        /// reach the Remote Desktop service on that port: inbound, Allow, TCP or no protocol, the
        /// port or none, the address or none, svchost or no program, TermService or no service.
        /// A rule with a field this can't judge (a profile, a local address, an interface, a
        /// keyword) doesn't count: the answer decides whether a session may be cut, so a rule
        /// that might not apply is no rule.
        /// </summary>
        public static bool OwnRuleAllowsRdp(string client, int port) => OwnRuleAllowsRdp(client, port, OwnRules());

        /// <summary>The same, judged on a given set of the app's rules (value name → rule), e.g. as they would be after a change.</summary>
        public static bool OwnRuleAllowsRdp(string client, int port, IReadOnlyDictionary<string, string> rules) =>
            OwnRulesAllowingRdp(client, port, rules).Count > 0;

        /// <summary>The value names of the rules in <paramref name="rules"/> that let this client in, as <see cref="OwnRuleAllowsRdp(string, int)"/> judges.</summary>
        public static List<string> OwnRulesAllowingRdp(string client, int port, IReadOnlyDictionary<string, string> rules)
        {
            if (!IPAddress.TryParse(client, out var address)) return new List<string>();
            return rules.Where(r => r.Key.StartsWith("CUSTOM_", StringComparison.OrdinalIgnoreCase) && AllowsRdp(r.Value, address, port))
                        .Select(r => r.Key).ToList();
        }

        /// <summary>
        /// The value names of the switched-on rules in <paramref name="rules"/> that may let this
        /// client in: as <see cref="OwnRulesAllowingRdp"/>, but a field this can't judge (a local
        /// address, a profile, an interface, a keyword) counts as matching. For "is the rule
        /// that lets the client in being touched?", where a rule that might is one that does.
        /// </summary>
        public static List<string> OwnRulesMayAllowRdp(string client, int port, IReadOnlyDictionary<string, string> rules)
        {
            if (!IPAddress.TryParse(client, out var address)) return rules.Keys.ToList();   // can't judge: any may
            return rules.Where(r => r.Key.StartsWith("CUSTOM_", StringComparison.OrdinalIgnoreCase) && AllowsRdp(r.Value, address, port, strict: false))
                        .Select(r => r.Key).ToList();
        }

        /// <summary>
        /// The value names of the switched-on inbound Block rules in <paramref name="rules"/> that may
        /// stop this client (a field this can't judge counts as matching). Block beats Allow.
        /// </summary>
        public static List<string> OwnBlocksMayMatchRdp(string client, int port, IReadOnlyDictionary<string, string> rules)
        {
            if (!IPAddress.TryParse(client, out var address))
                return rules.Where(r => r.Key.StartsWith("CUSTOM_", StringComparison.OrdinalIgnoreCase) && IsOnRule(r.Value, "Block", "In"))
                            .Select(r => r.Key).ToList();   // can't judge: any may
            return rules.Where(r => r.Key.StartsWith("CUSTOM_", StringComparison.OrdinalIgnoreCase) &&
                                    AllowsRdp(r.Value, address, port, strict: false, block: true))
                        .Select(r => r.Key).ToList();
        }

        /// <summary>True for a switched-on inbound Allow rule: the only kind that can let a Remote Desktop client in.</summary>
        public static bool IsOnInboundAllow(string raw) => IsOnRule(raw, "Allow", "In");

        /// <summary>True for a switched-on inbound Block rule, which beats any Allow.</summary>
        public static bool IsOnInboundBlock(string raw) => IsOnRule(raw, "Block", "In");

        /// <summary>True for a switched-on outbound Allow rule: under outbound block, what lets a program (a VPN client) out.</summary>
        public static bool IsOnOutboundAllow(string raw) => IsOnRule(raw, "Allow", "Out");

        private static bool IsOnRule(string raw, string action, string dir)
        {
            var fields = RuleText.Fields(raw).ToList();
            string One(string k) => fields.FirstOrDefault(f => f.Key.Equals(k, StringComparison.OrdinalIgnoreCase)).Value?.Trim() ?? "";
            return RuleText.IsOn(raw) && One("Action").Equals(action, StringComparison.OrdinalIgnoreCase) &&
                   One("Dir").Equals(dir, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>The app's rules (CUSTOM_ in the policy store) as they stand: value name → rule. Throws if the store can't be read.</summary>
        public static Dictionary<string, string> OwnRules()
        {
            var rules = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using var key = Registry.LocalMachine.OpenSubKey(RuleWriter.RegGPO);
            if (key == null) return rules;
            foreach (var name in key.GetValueNames())
                if (name.StartsWith("CUSTOM_", StringComparison.OrdinalIgnoreCase) && key.GetValue(name) is string raw)
                    rules[name] = raw;
            return rules;
        }

        // Strict: only a rule whose every field is understood and matches lets the client in (to
        // stay quiet on "it is let in after the change"). Not strict: a field this can't judge
        // counts as matching, so the rule may let the client in (to stay quiet on "nothing that
        // lets it in now is touched"). Either way the doubt falls on the side of asking.
        // With block: the same for a Block rule, i.e. whether it would stop this client.
        private static bool AllowsRdp(string raw, IPAddress client, int port, bool strict = true, bool block = false)
        {
            const StringComparison ic = StringComparison.OrdinalIgnoreCase;
            bool allow = false, inbound = false, remoteLimited = false, remoteCovered = false, portLimited = false, portCovered = false;
            var profiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var svchost = Path.Combine(Environment.SystemDirectory, "svchost.exe");
            var v4 = client.AddressFamily == AddressFamily.InterNetwork;

            foreach (var (k, value) in RuleText.Fields(raw))
            {
                var v = value.Trim();
                switch (k.ToUpperInvariant())
                {
                    case "ACTION":
                        if (!v.Equals(block ? "Block" : "Allow", ic)) return false;
                        allow = true;
                        break;
                    case "DIR":
                        if (!v.Equals("In", ic)) return false;
                        inbound = true;
                        break;
                    case "ACTIVE":
                        if (v.Equals("FALSE", ic)) return false;
                        break;
                    case "PROTOCOL":
                        if (Protocols.Number(v) is { } n
                                ? !(int.TryParse(n, NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p == RuleWriter.Tcp)
                                : !(v.Length == 0 || v.Equals("Any", ic) || !strict))
                            return false;
                        break;
                    case "LPORT":
                        portLimited = true;
                        if (PortCovers(v, port) || (!strict && !PortsReadable(v))) portCovered = true;
                        break;
                    case "RA4":
                        remoteLimited = true;
                        var span4 = v.Equals("Any", ic) || Ipv4Scope.IsSlashZero(v) ? null : Ipv4Scope.Parse(v, out _);
                        if (v.Equals("Any", ic) ? v4
                            : span4 is { } span ? v4 && Ipv4Scope.TryAddress(client.ToString(), out var ip, out _) && span.Contains(ip)
                            : !strict)
                            remoteCovered = true;
                        break;
                    case "RA6":
                        remoteLimited = true;
                        var one = IPAddress.TryParse(v, out var single) ? single : null;
                        var net = IPNetwork.TryParse(v, out var parsed) ? parsed : (IPNetwork?)null;
                        if (v.Equals("Any", ic) ? !v4
                            : one != null ? !v4 && one.Equals(client)
                            : net is { } range ? !v4 && range.Contains(client)
                            : !strict)
                            remoteCovered = true;
                        break;
                    case "APP":
                        var app = Environment.ExpandEnvironmentVariables(v);
                        // A path that can't be expanded here (a variable this process lacks) can't be judged.
                        if (!strict && (app.Contains('%') || !Path.IsPathRooted(app))) break;
                        if (!app.Equals(svchost, ic)) return false;
                        break;
                    case "SVC":
                        // "*" is any service, so TermService too.
                        if (!v.Equals("TermService", ic) && v != "*") return false;
                        break;
                    case "PROFILE":
                        profiles.Add(v);
                        break;
                    case "NAME": case "DESC": case "EMBEDCTXT":
                        break;
                    default:
                        // Keyword fields (RA42=LocalSubnet, LPort2_10=…) only widen the field they
                        // belong to, but on their own they limit it to what they name.
                        var key = k.ToUpperInvariant();
                        if (key.StartsWith("RA4", StringComparison.Ordinal) || key.StartsWith("RA6", StringComparison.Ordinal))
                        { remoteLimited = true; if (!strict) remoteCovered = true; break; }
                        if (key.StartsWith("LPORT", StringComparison.Ordinal))
                        { portLimited = true; if (!strict) portCovered = true; break; }
                        if (strict) return false;
                        break;   // LA4, an interface, …: may match
                }
            }
            if (strict && profiles.Count > 0 && !(profiles.Contains("Domain") && profiles.Contains("Private") && profiles.Contains("Public")))
                return false;
            return allow && inbound && (!remoteLimited || remoteCovered) && (!portLimited || portCovered);
        }

        // Every entry a number or a range, as PortCovers reads them.
        private static bool PortsReadable(string value) =>
            value.Split(',').Select(s => s.Trim()).All(s => s.Length > 0 && Ipv4Scope.BadPorts(s) == null);

        // "3389", "3000-4000" or a comma list of them; a keyword (RPC, IPHTTPS…) covers nothing.
        private static bool PortCovers(string value, int port) =>
            value.Split(',').Select(s => s.Trim()).Any(s =>
            {
                if (s.Length == 0 || Ipv4Scope.BadPorts(s) != null) return false;
                var ends = s.Split('-');
                return int.TryParse(ends[0], NumberStyles.None, CultureInfo.InvariantCulture, out var first) &&
                       int.TryParse(ends[^1], NumberStyles.None, CultureInfo.InvariantCulture, out var last) &&
                       port >= first && port <= last;
            });

        /// <summary>True if every profile still holds the lock-down's values.</summary>
        public static bool LockdownInRegistry() => ProfileKeys.All(p =>
        {
            using var k = Registry.LocalMachine.OpenSubKey($@"{PolicyRoot}\{p}");
            return k?.GetValue("DefaultInboundAction") is 1 && k.GetValue("DefaultOutboundAction") is 1 &&
                   k.GetValue("AllowLocalPolicyMerge") is 0;
        });

        // ── Snapshot and restore ───────────────────────────────────────────────

        /// <summary>
        /// Saves the policy key (deleted, then recreated as it is now) and the local rules as a
        /// .reg file, and the local store with the firewall's own export (.wfw, same name).
        /// Restoring both brings back exactly this state at once, including removing anything
        /// the lock-down added. Without the export there is no restore that reaches the running
        /// firewall, so a failed export stops the lock-down.
        /// </summary>
        /// <returns>The .reg path, and the local rules as they were saved: the only ones removed later.</returns>
        public static (string Reg, Dictionary<string, string>? LocalBefore) Snapshot() => Snapshot("before-lockdown");

        /// <summary>The same, with the files named for what is about to change ("before-rdp-rule").</summary>
        public static (string Reg, Dictionary<string, string>? LocalBefore) Snapshot(string name)
        {
            var localBefore = LocalRules.ReadAll();
            var sb = new StringBuilder();
            sb.AppendLine($@"[-HKEY_LOCAL_MACHINE\{PolicyRoot}]");
            sb.AppendLine();
            using (var root = Registry.LocalMachine.OpenSubKey(PolicyRoot))
                if (root != null) WriteTree(sb, root, $@"HKEY_LOCAL_MACHINE\{PolicyRoot}");
            using (var local = Registry.LocalMachine.OpenSubKey(LocalRulesKey))
                if (local != null) WriteKey(sb, local, $@"HKEY_LOCAL_MACHINE\{LocalRulesKey}");
            var reg = AppFolder.WriteReg(name, sb.ToString());
            if (LocalRules.Export(WfwOf(reg)) is { } problem)
            {
                // Half a snapshot would pass for a whole one later, so neither file stays.
                try { File.Delete(reg); } catch { }
                try { File.Delete(WfwOf(reg)); } catch { }
                throw new InvalidOperationException(problem);
            }
            return (reg, localBefore);
        }

        /// <summary>The firewall export saved with a snapshot.</summary>
        public static string WfwOf(string snapshot) => Path.ChangeExtension(snapshot, "wfw");

        private static void WriteTree(StringBuilder sb, RegistryKey key, string name)
        {
            WriteKey(sb, key, name);
            foreach (var sub in key.GetSubKeyNames())
            {
                using var child = key.OpenSubKey(sub);
                if (child != null) WriteTree(sb, child, $@"{name}\{sub}");
            }
        }

        private static void WriteKey(StringBuilder sb, RegistryKey key, string name)
        {
            sb.AppendLine($"[{name}]");
            foreach (var v in key.GetValueNames())
            {
                var label = v.Length == 0 ? "@" : $"\"{Escape(v)}\"";
                var data = key.GetValue(v, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                sb.AppendLine(key.GetValueKind(v) switch
                {
                    RegistryValueKind.DWord        => $"{label}=dword:{unchecked((uint)(int)data!):x8}",
                    RegistryValueKind.String       => $"{label}=\"{Escape((string)data!)}\"",
                    RegistryValueKind.ExpandString => $"{label}=hex(2):{Hex(Encoding.Unicode.GetBytes((string)data! + "\0"))}",
                    RegistryValueKind.MultiString  => $"{label}=hex(7):{Hex(Encoding.Unicode.GetBytes(string.Concat(((string[])data!).Select(s => s + "\0")) + "\0"))}",
                    RegistryValueKind.QWord        => $"{label}=hex(b):{Hex(BitConverter.GetBytes((long)data!))}",
                    RegistryValueKind.None         => $"{label}=hex(0):{Hex(data as byte[] ?? Array.Empty<byte>())}",
                    _                              => $"{label}=hex:{Hex(data as byte[] ?? Array.Empty<byte>())}",
                });
            }
            sb.AppendLine();
        }

        private static string Escape(string s) => s.Replace(@"\", @"\\").Replace("\"", "\\\"");
        private static string Hex(byte[] b) => string.Join(",", b.Select(x => x.ToString("x2")));

        /// <summary>
        /// Imports the snapshot: the .reg for the policy key, then the firewall export for the
        /// local rules, so the running firewall has them back at once. Throws if the .reg import
        /// fails (nothing was put back). A failed firewall import is returned instead: the
        /// policy is back and must still be applied, and the local rules then return only from
        /// the registry, at the next restart.
        /// </summary>
        public static string? Restore(string snapshot)
        {
            var (code, output) = Run(WindowsTools.Tool.Reg, $"import \"{snapshot}\"", 60_000);
            if (code != 0) throw new InvalidOperationException($"reg import failed ({code}): {output}");
            var wfw = WfwOf(snapshot);
            if (!File.Exists(wfw)) return $"{Path.GetFileName(wfw)} is missing, so Windows' local rules come back only at the next restart";
            return LocalRules.Import(wfw) is { } problem
                ? $"{problem}; Windows' local rules come back only at the next restart"
                : null;
        }

        /// <summary>
        /// What putting the saved state back found. RestoreError: nothing was put back.
        /// BackstopLeft: the failsafe task is still there to try again, or may be
        /// (BackstopUnsure: Task Scheduler gave no clear answer).
        /// </summary>
        public sealed record PutBackResult(string? RestoreError, bool BackstopLeft, string? LocalProblem, PolicyApply.Result? Check,
                                           bool BackstopUnsure = false);

        /// <summary>
        /// Restore, apply and check, for a failsafe that wasn't kept. Runs on a worker, touches
        /// no control. The backstop is removed only once the firewall is seen to apply the old
        /// state; until then it stays armed as a second attempt.
        /// </summary>
        public static async Task<PutBackResult> PutBackAsync(string snapshot, string why, bool backstopArmed, Action<string>? say = null)
        {
            say?.Invoke("Putting the saved state back…");
            string? localProblem;
            try { localProblem = Restore(snapshot); }
            catch (Exception ex)
            {
                var stateNow = backstopArmed ? BackstopState() : false;
                return new PutBackResult(ex.Message, stateNow != false, null, null, stateNow == null);
            }

            say?.Invoke("Applying the policy (gpupdate) and checking that the firewall applies it…");
            var check = await PolicyApply.RunAsync($"{why}: firewall put back as it was");
            // The task may have fired meanwhile and removed itself: only one still there is left.
            var state = backstopArmed ? BackstopState() : false;
            if (localProblem == null && state != false && check.InForce)
                state = RemoveBackstop();
            return new PutBackResult(null, state != false, localProblem, check, state == null);
        }

        /// <summary>
        /// What a put-back found, as one status line: the text, whether it is a problem, and
        /// the check's details for a tooltip. <paramref name="why"/> starts the sentence ("RDP-51-IN not kept").
        /// </summary>
        public static (string Text, bool Error, string? Detail) PutBackText(PutBackResult u, string snapshot, string why)
        {
            if (u.RestoreError != null)
                return ($"{why}, and putting the firewall back failed: {u.RestoreError.TrimEnd('.')}. " +
                        (!u.BackstopLeft ? "" : u.BackstopUnsure
                            ? "The failsafe task may still be armed (Task Scheduler gave no clear answer); if so, it tries again. "
                            : "The failsafe task will try again. ") +
                        $"The saved state is {snapshot} (double-click to import, as administrator) with " +
                        $"{Path.GetFileName(WfwOf(snapshot))} next to it " +
                        "(netsh advfirewall import, or Import Policy in Windows' firewall console).", true, null);

            var check = u.Check!;
            if (u.LocalProblem != null)
                // The policy is back; the failsafe task, if still armed, tries the import again.
                return ($"{why}: the policy is put back ({check.Summary.TrimEnd('.')}), but {u.LocalProblem}." +
                        (!u.BackstopLeft ? "" : u.BackstopUnsure
                            ? " The failsafe task may still be armed (Task Scheduler gave no clear answer); if so, it tries the import again."
                            : " The failsafe task stays armed and tries the import again."), true, check.Detail);
            if (!check.InForce)
                return (check.Summary +
                        (!u.BackstopLeft ? "" : u.BackstopUnsure
                            ? " The failsafe task may still be armed (Task Scheduler gave no clear answer); if so, it tries again. A restart also applies it."
                            : " The failsafe task stays armed and tries again; a restart also applies it."), true, check.Detail);
            if (u.BackstopLeft)
                return (u.BackstopUnsure
                    ? $"{check.Summary} Whether the failsafe task is gone couldn't be told (Task Scheduler gave no clear answer): if \"{BackstopTask}\" is in Task Scheduler, delete it."
                    : $"{check.Summary} The failsafe task could not be removed: delete \"{BackstopTask}\" in Task Scheduler.", true, check.Detail);
            return (check.Summary, false, check.Detail);
        }

        // ── Lock down ──────────────────────────────────────────────────────────

        public sealed record Result(List<string> RdpRules, List<string> LoggingProblems);

        /// <summary>
        /// Writes the lock-down. The RDP rules go first, so the block never exists without them.
        /// Policy refresh and the in-force check are the caller's (PolicyApply).
        /// </summary>
        public static Result Apply(IReadOnlyList<string> rdpClients, int rdpPort) =>
            Apply(rdpClients.Select(c => (c, (IReadOnlyList<int>)new[] { rdpPort })).ToList());

        /// <summary>The same, each client's rule with the port(s) that client is connected on.</summary>
        public static Result Apply(IReadOnlyList<(string Client, IReadOnlyList<int> Ports)> rdpClients)
        {
            var rdpRules = new List<string>();
            var all = rdpClients.Select(c => c.Client).ToList();
            foreach (var (client, ports) in rdpClients)
            {
                if (ports.Count == 0) continue;
                var spec = RdpRule(client, ports[0], all) with
                {
                    Ports = ports.Distinct().Select(p => p.ToString(CultureInfo.InvariantCulture)).ToList()
                };
                RuleWriter.Write(spec);
                rdpRules.Add(RuleWriter.KeyFor(spec.Name));
            }

            foreach (var p in ProfileKeys)
            {
                using var k = Registry.LocalMachine.CreateSubKey($@"{PolicyRoot}\{p}")
                              ?? throw new InvalidOperationException($"Cannot open {p} in the firewall policy.");
                k.SetValue("EnableFirewall",             1, RegistryValueKind.DWord);
                k.SetValue("DefaultInboundAction",       1, RegistryValueKind.DWord);
                k.SetValue("DefaultOutboundAction",      1, RegistryValueKind.DWord);
                k.SetValue("AllowLocalPolicyMerge",      0, RegistryValueKind.DWord);
                k.SetValue("AllowLocalIPsecPolicyMerge", 0, RegistryValueKind.DWord);
            }

            var problems = new List<string>();
            if (LiveDropSource.AuditpolMissing is { } why)
                problems.Add($"the audits and process starts ({why.TrimEnd('.')})");
            else
            {
                if (!LiveDropSource.SetDropAuditing(true))  problems.Add("blocked-connection audit");
                if (!LiveDropSource.SetAllowAuditing(true)) problems.Add("allowed-connection audit");
                if (!ProcessStartLog.Enable())              problems.Add("process starts");
            }
            if (!DnsClientLog.Set(true))                    problems.Add("DNS log");

            return new Result(rdpRules, problems);
        }

        /// <summary>
        /// Windows' local rules removed through the firewall, only those saved in the snapshot.
        /// Called once the lock-down's policy is in force: with merge off it no longer depends
        /// on them, so removing them can't cut a Remote Desktop session.
        /// </summary>
        public static LocalRules.Removal RemoveLocal(Dictionary<string, string>? savedBefore) =>
            savedBefore == null ? new LocalRules.Removal(0, 0, new()) : LocalRules.Remove(savedBefore);

        // ── Backstop: a one-time scheduled task that restores if the app can't ──

        /// <summary>
        /// Creates (or moves) the backstop: at <paramref name="at"/>, as SYSTEM, import the
        /// snapshot, refresh policy, delete itself. Defined as task XML so the time is not
        /// subject to the locale's date format.
        /// </summary>
        public static void ArmBackstop(string snapshot, DateTime at)
        {
            // Full paths here too: the task runs as SYSTEM, and a tool found by bare name would run
            // with it. Unquoted, since cmd strips a leading quote off the whole line after /c, and
            // %SystemRoot% holds no spaces.
            var command = $@"/c %SystemRoot%\System32\reg.exe import ""{snapshot}"" & " +
                          $@"%SystemRoot%\System32\netsh.exe advfirewall import ""{WfwOf(snapshot)}"" & " +
                          @"%SystemRoot%\System32\gpupdate.exe /target:computer /force & " +
                          $@"%SystemRoot%\System32\schtasks.exe /delete /tn ""{BackstopTask}"" /f";
            var xml = $@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <Description>Restores the firewall as it was before a FirewallManager change with failsafe (Lock down, a Remote Desktop rule in Setup, or a change guarded with a Remote Desktop rule), unless the change was kept. Removes itself.</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>{at.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss", CultureInfo.InvariantCulture)}</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id=""System"">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context=""System"">
    <Exec>
      <Command>%SystemRoot%\System32\cmd.exe</Command>
      <Arguments>{System.Security.SecurityElement.Escape(command)}</Arguments>
    </Exec>
  </Actions>
</Task>";
            var file = AppFolder.NewFile("failsafe-task", "xml");
            try
            {
                File.WriteAllText(file, xml, Encoding.Unicode);
                var (code, output) = Run(WindowsTools.Tool.Schtasks, $"/create /tn \"{BackstopTask}\" /xml \"{file}\" /f", 30_000);
                if (code != 0) throw new InvalidOperationException($"The failsafe task could not be created ({code}): {output}");
            }
            finally { try { File.Delete(file); } catch { } }
        }

        /// <summary>Removes the backstop. True only when it is known to be gone (or never there).</summary>
        public static bool DisarmBackstop() => RemoveBackstop() == false;

        /// <summary>Removes the backstop, then <see cref="BackstopState"/>: false = gone, true = still there, null = can't tell.</summary>
        public static bool? RemoveBackstop()
        {
            Run(WindowsTools.Tool.Schtasks, $"/delete /tn \"{BackstopTask}\" /f", 30_000);
            return BackstopState();
        }

        /// <summary>
        /// True when the backstop is there or that can't be told, so a refusal that depends on it
        /// holds; <see cref="BackstopState"/> tells the two apart.
        /// </summary>
        public static bool BackstopExists() => BackstopState() != false;

        private const string TaskTree = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

        /// <summary>
        /// True: the task is there. False: it is not: schtasks ran and answered with an error,
        /// and Task Scheduler's own index has no such task. Null: can't tell (schtasks missing,
        /// not started or out of time, or the index unreadable or still listing it). Exit codes
        /// alone can't say "not there": schtasks answers every error with the same code.
        /// </summary>
        public static bool? BackstopState()
        {
            var (code, _) = Run(WindowsTools.Tool.Schtasks, $"/query /tn \"{BackstopTask}\"", 30_000);
            if (code == 0) return true;
            if (code < 0) return null;   // no answer from schtasks
            try
            {
                using var entry = Registry.LocalMachine.OpenSubKey($@"{TaskTree}\{BackstopTask}");
                return entry == null ? false : null;
            }
            catch { return null; }
        }

        private static (int Code, string Output) Run(WindowsTools.Tool tool, string args, int timeoutMs)
        {
            var file = WindowsTools.Name(tool);
            if (WindowsTools.NotFound(tool, "this step was not run") is { } missing) return (-1, missing);
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(tool), Arguments = args,
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true
                });
                if (p == null) return (-1, $"{file} could not be started");
                try { p.StandardInput.Close(); } catch { }
                var stdout = p.StandardOutput.ReadToEndAsync();
                var stderr = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } return (-1, $"{file} did not finish in time"); }
                return (p.ExitCode, (stdout.Result + " " + stderr.Result).Trim());
            }
            catch (Exception ex) { return (-1, ex.Message); }
        }
    }
}
