using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// Writes GPO-Script rules for Setup's recipes: one rule per call, in the policy store
    /// (HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules), in the same form the
    /// rule editor saves. Also finds a rule that already does the same, so a recipe can say so
    /// instead of adding a second one.
    /// </summary>
    internal static class RuleWriter
    {
        public const string RegGPO = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";
        private const string RegProfiles = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";

        public const int Tcp = 6, Udp = 17;

        /// <summary>
        /// One rule. <see cref="Remote"/> empty = any destination/source; <see cref="Program"/>
        /// a full path, or "System" for the kernel (file sharing); <see cref="Service"/> one
        /// service inside svchost.exe.
        /// </summary>
        public sealed record Spec(
            string Name, bool Inbound, int Protocol, IReadOnlyList<string> Ports,
            IReadOnlyList<string> Remote, string Program = "", string Service = "");

        // ── Names and keys of the app's own rules ───────────────────────────
        //  Every rule this app writes carries CUSTOM twice: in its registry value name (the key,
        //  CUSTOM_<name> with _ for a space), by which the app knows its own rules, and in its
        //  stored name (CUSTOM <name>), which is what Windows' own tools (wf.msc, gpedit, netsh)
        //  show: the only way to tell there where a rule came from. The app shows the plain name.
        //  Setup, the rule editor and the quick switches all go through these three.

        /// <summary>The name without the app's CUSTOM prefix, as the app shows it.</summary>
        public static string Plain(string name)
        {
            var n = name.Trim();
            // A prefix written twice by some earlier version comes off too.
            while (true)
            {
                if (n.StartsWith("CUSTOM ", StringComparison.Ordinal)) n = n["CUSTOM ".Length..].Trim();
                else if (n.StartsWith("CUSTOM_", StringComparison.Ordinal)) n = n["CUSTOM_".Length..].Replace('_', ' ').Trim();
                else return n;
            }
        }

        /// <summary>The name as stored in the rule: "CUSTOM &lt;name&gt;", never prefixed twice.</summary>
        public static string StoredName(string name) => "CUSTOM " + Plain(name);

        /// <summary>The rule's registry value name: "CUSTOM_&lt;name&gt;" with _ for a space, never prefixed twice.</summary>
        public static string KeyFor(string name) => "CUSTOM_" + Plain(name).Replace(' ', '_');

        /// <summary>
        /// True for one of the app's rules (CUSTOM_ key) whose stored name lacks CUSTOM: Windows'
        /// own tools can't tell where it came from. Rules from early versions; editing fixes it.
        /// </summary>
        public static bool NameUnmarked(string key, string storedName) =>
            key.StartsWith("CUSTOM_", StringComparison.Ordinal) &&
            !storedName.StartsWith("CUSTOM ", StringComparison.Ordinal);

        public static bool KeyExists(string name)
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegGPO);
            return key?.GetValue(KeyFor(name)) != null;
        }

        /// <summary>Writes (or replaces) the rule, active. Throws if the store can't be opened.</summary>
        public static void Write(Spec s)
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegGPO, writable: true)
                         ?? Registry.LocalMachine.CreateSubKey(RegGPO)
                         ?? throw new InvalidOperationException("Cannot open the firewall policy store (run as administrator).");

            key.SetValue(KeyFor(s.Name), Value(s), RegistryValueKind.String);
        }

        /// <summary>The value Write stores for a spec (the guard judges a replacing rule by it).</summary>
        public static string Value(Spec s)
        {
            // One field per value: WFP rejects comma lists in RA4 silently (see the rule editor).
            var fields = new List<string>
            {
                "Action=Allow",
                $"Dir={(s.Inbound ? "In" : "Out")}",
                $"Protocol={s.Protocol}",
            };
            var portKey = s.Inbound ? "LPort" : "RPort";
            fields.AddRange(s.Ports.Select(p => $"{portKey}={p}"));
            fields.AddRange(s.Remote.Select(a => a.Contains(':') ? $"RA6={a}" : $"RA4={a}"));
            if (s.Program.Length > 0) fields.Add($"App={ToEnvPath(s.Program)}");
            if (s.Service.Length > 0) fields.Add($"Svc={s.Service}");

            return $"v2.33|{string.Join("|", fields)}|Active=TRUE|Name={StoredName(s.Name)}|";
        }

        // As gpedit writes them, and as the rule editor saves: %SystemDrive% / %SystemRoot%.
        private static string ToEnvPath(string path) => PortablePath.ToPortable(path);

        /// <summary>
        /// An existing policy rule that allows the same thing (direction, protocol, the same
        /// ports, the same addresses, the same program and service) and holds nothing beyond the
        /// fields <see cref="Write"/> writes, with whether it is switched on; null when there is
        /// none. A switched-on match comes first. Any other field (Profile, LA4, the other side's
        /// port, a description…) changes what the rule does, so such a rule is not the same.
        /// </summary>
        public static (string Name, bool On)? FindEquivalent(Spec s)
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegGPO);
            if (key == null) return null;

            static string Norm(string p) => Environment.ExpandEnvironmentVariables(p).Trim();
            static HashSet<string> Set(IEnumerable<string> values) =>
                values.SelectMany(v => v.Split(',')).Select(v => v.Trim()).Where(v => v.Length > 0)
                      .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var portKey   = s.Inbound ? "LPort" : "RPort";
            var wantPorts = Set(s.Ports);
            var wantV4    = Set(s.Remote.Where(a => !a.Contains(':')));
            var wantV6    = Set(s.Remote.Where(a => a.Contains(':')));
            var wantProg  = Norm(s.Program);

            // Exactly the fields Write writes for this spec: once each, or once per value.
            var single = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Action", "Dir", "Protocol", "Active", "Name" };
            if (s.Program.Length > 0) single.Add("App");
            if (s.Service.Length > 0) single.Add("Svc");
            var multi = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (wantPorts.Count > 0) multi.Add(portKey);
            if (wantV4.Count > 0) multi.Add("RA4");
            if (wantV6.Count > 0) multi.Add("RA6");

            (string Name, bool On)? off = null;
            foreach (var name in key.GetValueNames())
            {
                var raw = key.GetValue(name)?.ToString() ?? "";
                var f = RuleText.Fields(raw).ToList();
                if (f.Any(x => !single.Contains(x.Key) && !multi.Contains(x.Key))) continue;
                if (f.GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase).Any(g => single.Contains(g.Key) && g.Count() > 1)) continue;
                string One(string k) => f.FirstOrDefault(x => x.Key.Equals(k, StringComparison.OrdinalIgnoreCase)).Value?.Trim() ?? "";
                HashSet<string> All(string k) => Set(f.Where(x => x.Key.Equals(k, StringComparison.OrdinalIgnoreCase)).Select(x => x.Value));

                if (!One("Action").Equals("Allow", StringComparison.OrdinalIgnoreCase)) continue;
                if (!One("Dir").Equals(s.Inbound ? "In" : "Out", StringComparison.OrdinalIgnoreCase)) continue;
                if (One("Protocol") != s.Protocol.ToString(System.Globalization.CultureInfo.InvariantCulture)) continue;
                if (!All(portKey).SetEquals(wantPorts)) continue;
                if (!All("RA4").SetEquals(wantV4) || !All("RA6").SetEquals(wantV6)) continue;
                if (!Norm(One("App")).Equals(wantProg, StringComparison.OrdinalIgnoreCase)) continue;
                if (!One("Svc").Equals(s.Service, StringComparison.OrdinalIgnoreCase)) continue;

                var shown = One("Name");
                // Shown as the app shows names: without CUSTOM.
                var match = (Plain(shown.Length > 0 ? shown : name), RuleText.IsOn(raw));
                if (match.Item2) return match;
                off ??= match;
            }
            return off;
        }

        /// <summary>
        /// The profiles ("Domain", "Private", "Public") on which local merge is on in policy:
        /// AllowLocalPolicyMerge anything but 0, or not set (Windows then merges).
        /// </summary>
        public static List<string> ProfilesWithMergeOn()
        {
            var on = new List<string>();
            foreach (var (label, profile) in new[] { ("Domain", "DomainProfile"), ("Private", "PrivateProfile"), ("Public", "PublicProfile") })
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey($@"{RegProfiles}\{profile}");
                    if (k?.GetValue("AllowLocalPolicyMerge") is int v && v == 0) continue;
                }
                catch { /* unreadable: can't be shown off, so it counts as on */ }
                on.Add(label);
            }
            return on;
        }

        /// <summary>
        /// Local rules stop counting on all three profiles, so only policy rules apply (IPsec
        /// merge goes with it). Setup asks before calling this; Lock down writes the same values
        /// itself as part of its safe state.
        /// </summary>
        public static void MergeOffAllProfiles()
        {
            foreach (var profile in new[] { "DomainProfile", "PrivateProfile", "PublicProfile" })
            {
                using var k = Registry.LocalMachine.CreateSubKey($@"{RegProfiles}\{profile}");
                if (k == null) continue;
                k.SetValue("AllowLocalPolicyMerge",      0, RegistryValueKind.DWord);
                k.SetValue("AllowLocalIPsecPolicyMerge", 0, RegistryValueKind.DWord);
            }
        }

        /// <summary>One plain sentence: what the rule allows.</summary>
        public static string Describe(Spec s)
        {
            var who   = s.Program.Length == 0 ? "any program"
                      : s.Program.Equals("System", StringComparison.OrdinalIgnoreCase) ? "Windows (System)"
                      : s.Service.Length > 0 ? $"{System.IO.Path.GetFileName(s.Program)} ({s.Service})"
                      : System.IO.Path.GetFileName(s.Program);
            var proto = s.Protocol == Tcp ? "TCP" : s.Protocol == Udp ? "UDP" : $"protocol {s.Protocol}";
            var ports = string.Join(" and ", s.Ports);
            var where = s.Remote.Count == 0 ? "any address" : string.Join(", ", s.Remote);
            return s.Inbound
                ? $"Allow {where} to reach {who} on {proto} {ports}."
                : $"Allow {who} out on {proto} {ports} to {where}.";
        }
    }
}
