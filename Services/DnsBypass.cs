using System;
using System.Collections.Generic;
using System.Linq;

namespace FirewallManager
{
    /// <summary>
    /// DNS that goes around your resolver, or carries more than a name:
    ///   • encrypted DNS — a known DNS-over-HTTPS/TLS server (config section "encryptedDns"),
    ///     by address or by the name that was looked up;
    ///   • suspicious names — the shape DNS tunnelling and exfiltration leave behind: very long
    ///     or random-looking labels. (Many names under one domain is judged per list, by the
    ///     caller, since it needs all lookups at once.)
    /// Flags for a human to look at, not verdicts: a CDN can have a long label too.
    /// </summary>
    internal static class DnsBypass
    {
        // The effective list, re-read at most every few seconds: it is asked once per log row.
        // Read from the log's worker and the window's thread alike, so one gate around both fields.
        private static List<AppConfig.EncryptedDnsServer> _servers = new();
        private static DateTime _serversRead;
        private static readonly object _gate = new();

        private static List<AppConfig.EncryptedDnsServer> Servers
        {
            get
            {
                lock (_gate)
                {
                    if ((DateTime.Now - _serversRead).TotalSeconds > 5)
                    {
                        _servers = ConfigService.Effective().EncryptedDns;
                        _serversRead = DateTime.Now;
                    }
                    return _servers;
                }
            }
        }

        /// <summary>The provider if the address belongs to a known encrypted-DNS server.</summary>
        public static string? ServerByAddress(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return null;
            foreach (var s in Servers)
                if (s.Prefixes.Any(p => p.Length > 0 && ip.StartsWith(p, StringComparison.Ordinal)))
                    return s.Name;
            return null;
        }

        /// <summary>The provider if the name is a known encrypted-DNS server (or below one).</summary>
        public static string? ServerByName(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            name = name.TrimEnd('.');
            foreach (var s in Servers)
                if (s.Hosts.Any(h => h.Length > 0 &&
                        (name.Equals(h, StringComparison.OrdinalIgnoreCase) ||
                         name.EndsWith("." + h, StringComparison.OrdinalIgnoreCase))))
                    return s.Name;
            return null;
        }

        // Thresholds, kept deliberately high so ordinary names (CDN hosts, cloud endpoints)
        // stay quiet: a label is at most 63 characters, everyday ones rarely pass 30.
        private const int LongLabel   = 40;   // any label this long
        private const int HexLabel    = 20;   // all 0-9a-f, this long: hex-encoded data
        private const int RandomLabel = 24;   // this long, high entropy and several digits

        /// <summary>Why a name looks like it carries data, or null if it doesn't.</summary>
        public static string? SuspiciousName(string name)
        {
            foreach (var label in name.TrimEnd('.').Split('.'))
            {
                if (label.Length >= LongLabel)
                    return $"a {label.Length}-character label";
                if (label.Length >= HexLabel && label.All(Uri.IsHexDigit) && label.Any(char.IsDigit))
                    return "a hex-encoded label";
                if (label.Length >= RandomLabel && label.Count(char.IsDigit) >= 3 && Entropy(label) >= 4.0)
                    return "a random-looking label";
            }
            return null;
        }

        /// <summary>
        /// A random single word (no dot, 7–15 lowercase letters) that got no answer: the shape
        /// Chromium browsers (Edge, Chrome) use to test whether the network answers names that
        /// don't exist. Other programs may probe the same way; real single-word names (wpad,
        /// a printer) are short or get an answer.
        /// </summary>
        public static bool ProbeName(string name, bool answered) =>
            !answered && !name.Contains('.') && name.Length is >= 7 and <= 15
            && name.All(c => c is >= 'a' and <= 'z');

        /// <summary>The domain a name sits under, for counting names per domain (last two labels).</summary>
        public static string ParentDomain(string name)
        {
            var labels = name.TrimEnd('.').Split('.');
            return labels.Length <= 2 ? name : string.Join('.', labels[^2..]);
        }

        /// <summary>Record types worth noting: they carry text or raw data back, not an address.</summary>
        public static string? UnusualType(int type) => type switch
        {
            16 => "TXT",
            10 => "NULL",
            _  => null,
        };

        // Shannon entropy in bits per character: random base32/hex text ≈ 4–5, words ≈ 3–3.5.
        private static double Entropy(string s)
        {
            var counts = new Dictionary<char, int>();
            foreach (var c in s.ToLowerInvariant()) counts[c] = counts.TryGetValue(c, out var n) ? n + 1 : 1;
            double h = 0;
            foreach (var n in counts.Values)
            {
                var p = (double)n / s.Length;
                h -= p * Math.Log2(p);
            }
            return h;
        }
    }
}
