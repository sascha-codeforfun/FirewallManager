using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace FirewallManager
{
    /// <summary>
    /// Is an address on this machine's own network, or somewhere else? Read live from the
    /// network adapters that are up (their address and prefix), so "local" always means the
    /// networks this machine is connected to right now. Nothing is stored.
    ///
    /// Kinds: "Local" (on a connected subnet), "Remote" (anywhere else: another private range
    /// or the internet; the tooltip says which), plus "Multicast", "Broadcast", "Link-local"
    /// and "Loopback" for addresses that are neither. For a rule also "Mixed", "Any", and
    /// "None" (the rule has no IPv4 address).
    /// </summary>
    internal static class NetworkLocality
    {
        public sealed record Result(string Kind, string Tip);

        /// <summary>
        /// How far it reaches, as a colour: stays on this network = Safe (green), leaves it =
        /// Caution (amber), no limit at all = Unsafe (red). Broadcast, multicast, link-local and
        /// loopback never leave the local network, so they count as local. Mixed includes remote.
        /// </summary>
        public static string Tone(string kind) => kind switch
        {
            "Local" or "Loopback" or "Link-local" or "Broadcast" or "Multicast" => "Safe",
            "Remote" or "Mixed" => "Caution",
            "Any"               => "Unsafe",
            "No address" or "Unknown" or "None" => "Rare",     // outliers: indigo, like rare protocols
            _                   => ""
        };

        private sealed record Subnet(byte[] Network, int Prefix, AddressFamily Family, string Text, string Adapter);

        private static List<Subnet> _subnets = new();

        /// <summary>Re-reads the adapters. Call once per list load (cheap).</summary>
        public static void Refresh()
        {
            var list = new List<Subnet>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up ||
                        nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                    {
                        var ip = ua.Address;
                        if (ip.IsIPv6LinkLocal || IsIPv4LinkLocal(ip)) continue;
                        var prefix = ua.PrefixLength;
                        if (prefix <= 0) continue;
                        var net = Mask(ip.GetAddressBytes(), prefix);
                        list.Add(new Subnet(net, prefix, ip.AddressFamily,
                            $"{new IPAddress(net)}/{prefix}", nic.Name));
                    }
                }
            }
            catch { /* no adapters readable: everything classifies as Remote */ }
            _subnets = list;
        }

        /// <summary>
        /// 255.255.255.255, or the broadcast address of a network this machine is on right now
        /// (192.168.1.255 on 192.168.1.0/24). Any other address ending in .255 is a host.
        /// </summary>
        public static bool IsBroadcast(string text) =>
            IPAddress.TryParse(text.Trim(), out var ip) && (ip.Equals(IPAddress.Broadcast) || IsSubnetBroadcast(ip));

        /// <summary>Classifies one address (as it appears in the firewall log).</summary>
        public static Result Classify(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return new Result("", "");
            if (!IPAddress.TryParse(text.Trim(), out var ip))
                return new Result("Unknown", $"\"{text.Trim()}\" isn't an address this app can read");

            if (IPAddress.IsLoopback(ip))
                return new Result("Loopback", "This machine itself");
            if (ip.IsIPv6Multicast || IsIPv4Multicast(ip))
                return new Result("Multicast", "Group address: sent to every member on the network");
            if (ip.Equals(IPAddress.Broadcast) || IsSubnetBroadcast(ip))
                return new Result("Broadcast", "Sent to every device on the network");
            if (ip.IsIPv6LinkLocal || IsIPv4LinkLocal(ip))
                return new Result("Link-local", "Only valid on the directly attached link");

            var match = _subnets.FirstOrDefault(s => s.Family == ip.AddressFamily && Contains(s, ip));
            if (match != null)
                return new Result("Local", $"This network: {match.Text} ({match.Adapter})");

            return IsPrivate(ip)
                ? new Result("Remote", "Private address, but not on this machine's networks (another segment, a VPN…)")
                : new Result("Remote", "Internet address");
        }

        /// <summary>
        /// Classifies a rule's remote IPv4 address list ("Any", single IPs, ranges "a-b", subnets
        /// "a/n" or "a/mask", Windows keywords). A range or subnet is judged by its whole span:
        /// all of it on this machine's networks → local, part of it → both local and remote,
        /// none → remote. All entries local → Local, none → Remote, both → Mixed.
        /// </summary>
        public static Result ClassifyRule(string remoteAddress)
        {
            if (string.IsNullOrWhiteSpace(remoteAddress) || remoteAddress.Trim() == "Any")
                return new Result("Any", "Any address: this network and everything beyond it");

            int local = 0, remote = 0;
            var shares = new List<string>();
            foreach (var raw in remoteAddress.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                // Every address there is: shown like Any, so it catches the eye the same way.
                if (Ipv4Scope.IsSlashZero(raw))
                    return new Result("Any", $"{raw}: every IPv4 address. Windows refuses to load a rule with /0.");

                switch (raw.ToLowerInvariant())
                {
                    case "localsubnet":
                    case "defaultgateway":
                        local++; continue;
                    case "internet":
                        remote++; continue;
                }

                if (Ipv4Scope.Parse(raw, out _) is { Count: > 1 } span)
                {
                    var inside = Inside(span);
                    if (inside == span.Count) local++;
                    else if (inside == 0) remote++;
                    else
                    {
                        local++; remote++;
                        shares.Add($"{raw}: {inside.ToString("N0", CultureInfo.InvariantCulture)} of " +
                                   $"{span.Count.ToString("N0", CultureInfo.InvariantCulture)} addresses are on this network");
                    }
                    continue;
                }

                // A single address (a/32 and a-a included).
                var single = Ipv4Scope.Parse(raw, out _) is { } one ? Ipv4Scope.Text(one.First) : raw;
                var kind = Classify(single).Kind;
                if (kind is "" or "Unknown") { remote++; continue; }   // unknown keyword: treat as remote, the cautious side
                if (IsHere(kind)) local++; else remote++;
            }

            var nets = string.Join(", ", _subnets.Select(s => $"{s.Text} ({s.Adapter})"));
            var where = nets.Length > 0 ? $"This machine's networks: {nets}" : "No connected networks found";
            var part = shares.Count > 0 ? string.Join("\n", shares) + "\n" : "";
            if (local > 0 && remote == 0) return new Result("Local",  $"All addresses are on this machine's networks.\n{where}");
            if (remote > 0 && local == 0) return new Result("Remote", $"No address is on this machine's networks.\n{where}");
            return new Result("Mixed", $"Some addresses are on this machine's networks, some are not.\n{part}{where}");
        }

        // How many addresses of the span count as here: this machine's IPv4 networks (their
        // broadcast addresses included), loopback, link-local and 255.255.255.255, the same
        // kinds a single address counts as here. Overlapping networks are counted once.
        private static ulong Inside(Ipv4Scope.Span span)
        {
            var here = _subnets.Where(s => s.Family == AddressFamily.InterNetwork && s.Network.Length == 4)
                               .Select(s =>
                               {
                                   var net = (uint)s.Network[0] << 24 | (uint)s.Network[1] << 16 | (uint)s.Network[2] << 8 | s.Network[3];
                                   var mask = Ipv4Scope.MaskOf(s.Prefix);
                                   return new Ipv4Scope.Span(net & mask, (net & mask) | ~mask);
                               })
                               .Append(new Ipv4Scope.Span(0x7F000000, 0x7FFFFFFF))     // 127.0.0.0/8
                               .Append(new Ipv4Scope.Span(0xA9FE0000, 0xA9FEFFFF))     // 169.254.0.0/16
                               .Append(new Ipv4Scope.Span(0xFFFFFFFF, 0xFFFFFFFF))
                               .OrderBy(s => s.First).ToList();

            ulong count = 0;
            ulong next = span.First;                       // first address not yet counted
            foreach (var h in here)
            {
                var from = Math.Max((ulong)h.First, next);
                var to   = Math.Min((ulong)h.Last, span.Last);
                if (from > to) continue;
                count += to - from + 1;
                next = to + 1;
            }
            return count;
        }

        /// <summary>
        /// Whether this machine has addresses of a family: "on" when a network interface that is
        /// up, other than loopback, has one (link-local counts); "off" when interfaces are up but
        /// none has one; "unknown" when no interface is up or they can't be read.
        /// </summary>
        public static string FamilyState(AddressFamily family) => Family(family).State;

        /// <summary><see cref="FamilyState"/>, with the interfaces that have such an address.</summary>
        public static (string State, List<string> Interfaces) Family(AddressFamily family)
        {
            try
            {
                var up = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .ToList();
                if (up.Count == 0) return ("unknown", new());
                var with = up.Where(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.AddressFamily == family))
                             .Select(n => n.Name).ToList();
                return (with.Count > 0 ? "on" : "off", with);
            }
            catch { return ("unknown", new()); }
        }

        private static bool IsHere(string kind) => kind is "Local" or "Link-local" or "Broadcast" or "Loopback";

        // ── helpers ──────────────────────────────────────────────────────────

        private static bool Contains(Subnet s, IPAddress ip) =>
            Mask(ip.GetAddressBytes(), s.Prefix).SequenceEqual(s.Network);

        private static byte[] Mask(byte[] bytes, int prefix)
        {
            var r = (byte[])bytes.Clone();
            for (int i = 0; i < r.Length; i++)
            {
                var bits = Math.Clamp(prefix - i * 8, 0, 8);
                r[i] &= (byte)(0xFF << (8 - bits));
            }
            return r;
        }

        private static bool IsSubnetBroadcast(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            foreach (var s in _subnets.Where(s => s.Family == AddressFamily.InterNetwork && s.Prefix < 31))
            {
                if (!Contains(s, ip)) continue;
                var host = true;
                for (int i = 0; i < 4 && host; i++)
                {
                    var hostBits = (byte)~(0xFF << (8 - Math.Clamp(s.Prefix - i * 8, 0, 8)));
                    host = (b[i] & hostBits) == hostBits;
                }
                if (host) return true;
            }
            return false;
        }

        private static bool IsIPv4Multicast(IPAddress ip) =>
            ip.AddressFamily == AddressFamily.InterNetwork && ip.GetAddressBytes()[0] is >= 224 and <= 239;

        private static bool IsIPv4LinkLocal(IPAddress ip) =>
            ip.AddressFamily == AddressFamily.InterNetwork && ip.GetAddressBytes() is [169, 254, ..];

        private static bool IsPrivate(IPAddress ip)
        {
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                return (ip.GetAddressBytes()[0] & 0xFE) == 0xFC;           // fc00::/7 unique local
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 100 && b[1] is >= 64 and <= 127);                // carrier-grade NAT
        }
    }
}
