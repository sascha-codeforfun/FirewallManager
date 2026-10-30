using System;
using System.Collections.Generic;

namespace FirewallManager
{
    /// <summary>
    /// IP protocol numbers and their names, as Windows' own firewall console names them. One
    /// table for the rule list, the editor and the log, so the same number reads the same
    /// everywhere. "Any" is not a number: it is a rule (or a field) without a protocol.
    /// </summary>
    internal static class Protocols
    {
        public static readonly IReadOnlyDictionary<string, string> Names = new Dictionary<string, string>
        {
            ["0"] = "HOPOPT", ["1"] = "ICMP", ["2"] = "IGMP", ["6"] = "TCP", ["17"] = "UDP", ["41"] = "IPv6",
            ["43"] = "IPv6-Route", ["44"] = "IPv6-Frag", ["47"] = "GRE", ["50"] = "ESP", ["51"] = "AH",
            ["58"] = "ICMPv6", ["59"] = "IPv6-NoNxt", ["60"] = "IPv6-Opts", ["112"] = "VRRP", ["113"] = "PGM",
            ["115"] = "L2TP",
        };

        /// <summary>The name for a stored number; "" (no protocol) gives "Any"; an unknown number stays a number.</summary>
        public static string Name(string? number)
        {
            var n = (number ?? "").Trim();
            if (n.Length == 0) return "Any";
            return Names.TryGetValue(n, out var name) ? name : n;
        }

        /// <summary>The number for a name or a number ("ICMPv6" → "58", "58" → "58"); null for "Any" or unknown text.</summary>
        public static string? Number(string? nameOrNumber)
        {
            var t = (nameOrNumber ?? "").Trim();
            if (t.Length == 0 || t.Equals("Any", StringComparison.OrdinalIgnoreCase)) return null;
            if (int.TryParse(t, out _)) return t;
            foreach (var (num, name) in Names)
                if (name.Equals(t, StringComparison.OrdinalIgnoreCase)) return num;
            return t.Equals("ICMPv4", StringComparison.OrdinalIgnoreCase) ? "1" : null;
        }

        /// <summary>Tooltip for a protocol cell: the number behind the name.</summary>
        public static string Tip(string? nameOrNumber)
        {
            var t = (nameOrNumber ?? "").Trim();
            if (t.Length == 0 || t.Equals("Any", StringComparison.OrdinalIgnoreCase)) return "No protocol set: any protocol";
            var num = Number(t);
            if (num == null) return t;
            return Names.ContainsKey(num) ? $"Protocol {num}" : $"Protocol {num} (no name in the table)";
        }
    }
}
