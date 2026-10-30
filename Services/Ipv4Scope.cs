using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace FirewallManager
{
    /// <summary>
    /// IPv4 addresses, ranges and subnets as rules write them (a, a-b, a/n, a/mask), and ports.
    /// One reading for the editor's checks, the log's rule matching and the tooltips, so what
    /// the editor accepts is exactly what the rest of the app understands.
    /// </summary>
    internal static class Ipv4Scope
    {
        public readonly record struct Span(uint First, uint Last)
        {
            public ulong Count => (ulong)Last - First + 1;
            public bool Contains(uint ip) => ip >= First && ip <= Last;
        }

        /// <summary>One entry, or null with the reason. Only checks that it can exist, not that it is wise.</summary>
        public static Span? Parse(string text, out string? error)
        {
            error = null;
            var s = text.Trim();
            if (s.Length == 0) { error = "is empty"; return null; }
            if (s.Any(char.IsWhiteSpace)) { error = $"\"{s}\" contains a space"; return null; }

            var slash = s.IndexOf('/');
            if (slash >= 0)
            {
                if (!TryAddress(s[..slash], out var ip, out error)) return null;
                var suffix = s[(slash + 1)..];
                int bits;
                if (suffix.Length > 0 && suffix.All(char.IsAsciiDigit))
                {
                    if (!int.TryParse(suffix, NumberStyles.None, CultureInfo.InvariantCulture, out bits) || bits > 32)
                    { error = $"/{suffix} isn't a prefix length of 0–32"; return null; }
                }
                else if (TryAddress(suffix, out var mask, out _))
                {
                    if (PrefixOf(mask) is not { } p) { error = $"{suffix} isn't a subnet mask"; return null; }
                    bits = p;
                }
                else { error = $"\"{suffix}\" after the slash is neither a prefix length nor a mask"; return null; }
                var m = MaskOf(bits);
                return new Span(ip & m, (ip & m) | ~m);
            }

            var dash = s.IndexOf('-');
            if (dash >= 0)
            {
                if (!TryAddress(s[..dash], out var a, out error) || !TryAddress(s[(dash + 1)..], out var b, out error)) return null;
                if (a > b) { error = "the range runs backwards"; return null; }
                return new Span(a, b);
            }

            return TryAddress(s, out var one, out error) ? new Span(one, one) : null;
        }

        /// <summary>A subnet written with prefix 0, which Windows refuses to load (tested on Windows 10 22H2).</summary>
        public static bool IsSlashZero(string text) =>
            text.Contains('/') && Parse(text, out _) is { } span && span.Count == 1UL << 32;

        public static bool TryAddress(string text, out uint value, out string? error)
        {
            value = 0; error = null;
            var parts = text.Split('.');
            if (parts.Length != 4) { error = $"\"{text}\" isn't an IPv4 address"; return false; }
            foreach (var part in parts)
            {
                if (part.Length is 0 or > 3 || !part.All(char.IsAsciiDigit))
                { error = $"\"{text}\" isn't an IPv4 address"; return false; }
                var n = int.Parse(part, NumberStyles.None, CultureInfo.InvariantCulture);
                if (n > 255) { error = $"{n} in \"{text}\" is outside 0–255"; return false; }
                value = (value << 8) | (uint)n;
            }
            return true;
        }

        public static uint MaskOf(int bits) => bits <= 0 ? 0u : bits >= 32 ? 0xFFFFFFFF : 0xFFFFFFFF << (32 - bits);

        /// <summary>The prefix length of a mask, or null when its ones aren't contiguous from the left.</summary>
        public static int? PrefixOf(uint mask)
        {
            var bits = System.Numerics.BitOperations.PopCount(mask);
            return MaskOf(bits) == mask ? bits : null;
        }

        public static string Text(uint ip) => $"{ip >> 24}.{(ip >> 16) & 255}.{(ip >> 8) & 255}.{ip & 255}";

        /// <summary>
        /// Tooltip text for a comma-separated scope: the exact span of every subnet or range, one
        /// line each, with both notations. Empty when there is nothing to explain (single
        /// addresses, keywords, Any).
        /// </summary>
        public static string Describe(string scope)
        {
            var lines = new List<string>();
            foreach (var part in scope.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!part.Contains('/') && !part.Contains('-')) continue;
                if (Parse(part, out _) is not { } span) continue;
                var count = span.Count.ToString("N0", CultureInfo.InvariantCulture);
                var range = $"{Text(span.First)} – {Text(span.Last)}";
                if (part.Contains('/'))
                {
                    var bits = 32 - (int)Math.Log2(span.Count);
                    var mask = Text(MaskOf(bits));
                    var form = part[(part.IndexOf('/') + 1)..].Contains('.') ? $"/{bits}" : $"mask {mask}";
                    lines.Add(IsSlashZero(part)
                        ? $"{part} = every IPv4 address ({count}). Windows refuses to load a rule with /0."
                        : $"{part} = {range}, {form}, {count} addresses");
                }
                else lines.Add($"{part} = {range}, {count} addresses");
            }
            return string.Join("\n", lines);
        }

        /// <summary>Ports as the editor writes them: 1–65535 and ranges a-b, comma-separated. Null, or why not.</summary>
        public static string? BadPorts(string text)
        {
            var parts = text.Split(',');
            foreach (var raw in parts)
            {
                var part = raw.Trim();
                if (part.Length == 0) return "an empty entry between commas";
                var ends = part.Split('-');
                if (ends.Length > 2 || ends.Any(e => !IsPort(e))) return $"\"{part}\": ports are 1–65535, or a range such as 1000-2000";
                if (ends.Length == 2 && int.Parse(ends[0]) > int.Parse(ends[1])) return $"\"{part}\": the range runs backwards";
            }
            return null;
        }

        private static bool IsPort(string s) =>
            s.Length is > 0 and <= 5 && s.All(char.IsAsciiDigit) &&
            int.Parse(s, NumberStyles.None, CultureInfo.InvariantCulture) is >= 1 and <= 65535;
    }
}
