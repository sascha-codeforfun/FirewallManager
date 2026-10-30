using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FirewallManager
{
    /// <summary>
    /// Text that goes into a PowerShell script as data. Each string travels Base64-encoded
    /// (letters, digits, + / =) and is decoded in the script, so no value from anywhere can end
    /// a quote or run as code. Quoting would have to know every character PowerShell treats as a
    /// quote, curly ones included; Base64 has none to know.
    /// </summary>
    internal static class PsData
    {
        /// <summary>A PowerShell expression yielding the strings, in order, exactly as given.</summary>
        public static string Strings(IEnumerable<string> values)
        {
            var encoded = values.Select(v => "'" + Encode(v) + "'").ToList();
            return encoded.Count == 0
                ? "@()"
                : "@(foreach ($__b64 in @(" + string.Join(",", encoded) +
                  ")) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__b64)) })";
        }

        /// <summary>A PowerShell expression yielding the one string exactly as given.</summary>
        public static string One(string value) =>
            "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Encode(value) + "')))";

        private static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value ?? ""));
    }
}
