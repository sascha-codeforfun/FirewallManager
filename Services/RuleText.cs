using System;
using System.Collections.Generic;
using System.Linq;

namespace FirewallManager
{
    /// <summary>
    /// Reading and changing a rule string ("v2.33|Action=Allow|…|Active=TRUE|Name=…|") the way
    /// Windows reads it. One place, so the list, the editor, the quick switches and the
    /// in-force check never disagree about a rule.
    /// </summary>
    internal static class RuleText
    {
        /// <summary>The key=value fields in order; a field given twice appears twice.</summary>
        public static IEnumerable<(string Key, string Value)> Fields(string raw) =>
            (raw ?? "").Split('|')
                       .Where(p => p.Contains('='))
                       .Select(p => (p[..p.IndexOf('=')].Trim(), p[(p.IndexOf('=') + 1)..]));

        /// <summary>
        /// Windows loads a rule without an Active field as switched on (tested on Windows 10
        /// 22H2), so only an explicit Active=FALSE, in any case, is off. The app's own rules
        /// always carry the field; this is for rules written by anything else.
        /// </summary>
        public static bool IsOn(string raw) =>
            !Fields(raw).Any(f => f.Key.Equals("Active", StringComparison.OrdinalIgnoreCase) &&
                                  f.Value.Trim().Equals("FALSE", StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// The rule with its on/off field set. A rule without one gets it before the name, as
        /// Windows' own tools write it. Every other field stays exactly as it was.
        /// </summary>
        public static string WithActive(string raw, bool on)
        {
            var fields = (raw ?? "").Split('|').ToList();
            var field = on ? "Active=TRUE" : "Active=FALSE";
            var at = fields.FindIndex(f => f.TrimStart().StartsWith("Active=", StringComparison.OrdinalIgnoreCase));
            if (at >= 0) fields[at] = field;
            else
            {
                var name = fields.FindIndex(f => f.StartsWith("Name=", StringComparison.OrdinalIgnoreCase));
                fields.Insert(name >= 1 ? name : Math.Max(1, fields.Count - 1), field);
            }
            return string.Join("|", fields);
        }
    }
}
