using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FirewallManager
{
    /// <summary>
    /// Windows Service Hardening rules: per-service permits and blocks that Windows itself keeps
    /// in two stores of their own (Static, shipped with Windows; Configurable, added by services
    /// such as Defender). They apply whatever the profiles' merge setting says, and Purge Local,
    /// merge off and Lock down don't touch them, so the only way to see them is to ask Windows. Read
    /// only, but for one thing: obsolete Configurable rules can be purged (see Purge).
    /// </summary>
    internal static class ServiceHardening
    {
        public sealed record Rule(string Store, string Name, string Direction, string Action, bool Enabled,
                                  string Protocol, string LocalPorts, string RemotePorts, string Remote,
                                  string Program, string Service)
        {
            /// <summary>The program file isn't on this machine: a rule left behind by an old install.</summary>
            public bool   ProgramMissing { get; init; }
            /// <summary>Who may run the program file, by its permissions (short names).</summary>
            public string CanRun         { get; init; } = "";
            public string ProgramTip     { get; init; } = "";
            /// <summary>"HARD …", "soft", "block", "no own filter", "no filter" or "?", "*" when the name is shared (see HardVerdict).</summary>
            public string Hard           { get; init; } = "";
            /// <summary>For a rule Windows' tools don't parse: what its live filters say, in short.</summary>
            public string HardNote       { get; init; } = "";
            public string HardTip        { get; init; } = "";

            /// <summary>Someone outside Windows' usual set may run the file, or someone is denied.</summary>
            public bool   UnusualRun     { get; init; }
            /// <summary>What makes it unusual: the accounts outside the usual set, and any denied.</summary>
            public string UnusualWhat    { get; init; } = "";

            /// <summary>The rule's ID: its value name in the registry.</summary>
            public string Id             { get; init; } = "";
            /// <summary>
            /// The registry string, for a rule Windows' own tools return without name or conditions
            /// (non-standard spelling); its fields were read from here instead. "" otherwise.
            /// </summary>
            public string RawRule        { get; init; } = "";
            public bool   Unparsed       => RawRule.Length > 0;
            /// <summary>The registry name is a resource reference ("@file,-id") that couldn't be resolved.</summary>
            public bool   NameUnresolved { get; init; }

            // What an Allow rule leaves open: "Any" in a scope field. The colours show what the rule
            // says; whether it matters here is read from Hard and Store.
            public bool   IsAllow           => Action == "Allow";
            public bool   UnscopedProtocol   => IsAllow && Protocol == "Any";
            // The other side's port matters going out, this machine's port coming in; the port on
            // the connecting side is random either way, so "Any" there limits nothing away.
            public bool   UnscopedRemotePort => IsAllow && Direction == "Outbound" && RemotePorts == "Any";
            public bool   UnscopedRemote     => IsAllow && Remote == "Any";
            /// <summary>The full list, and the exact span of each subnet or range in it.</summary>
            public string RemoteTip          => Ipv4Scope.Describe(Remote) is { Length: > 0 } span ? $"{Remote}\n\n{span}" : Remote;
            public bool   UnscopedLocalPort  => IsAllow && Direction == "Inbound" && LocalPorts == "Any";
            /// <summary>
            /// Purgeable: added by a service (Configurable), for a program that is gone. The only
            /// rules removed here; blocks for an existing program stay. See "Purging obsolete rules".
            /// </summary>
            public bool   Obsolete           => IsConfigurable && ProgramMissing && Id.Length > 0;
            public bool   UnscopedProgram    => IsAllow && Program == "Any";

            public string ServiceShown => Service.Equals("Any", StringComparison.OrdinalIgnoreCase) ? "(none)" : Service;
            public string DirShort     => Direction == "Outbound" ? "Out" : Direction == "Inbound" ? "In" : Direction;
            public string EnabledShown => Enabled ? "on" : "off";

            // Names and paths come from Windows and from other tools, so what can't be seen in
            // them is shown (TextHygiene.Reveal); the stored text stays as it is.
            public string ProgramShown
            {
                get
                {
                    var (shown, findings) = TextHygiene.Reveal(Program);
                    return ProgramMissing ? $"⚠ missing: {shown}" : findings.Count > 0 ? $"⚠ {shown}" : Program;
                }
            }
            public string CanRunShown  => UnusualRun ? $"⚠ {CanRun}" : CanRun;
            public bool   IsConfigurable => Store == "Configurable";
            /// <summary>
            /// The verdicts worth a look, by what to do: "Above" could get past your rules,
            /// "Unknown" can't be told (HARD uncompared, "?", not parsed), "Outlier" is hard but
            /// provably doesn't get past them (not above, other layer); "" otherwise.
            /// </summary>
            public string HardLevel => Hard.StartsWith("HARD, above", StringComparison.Ordinal) ? "Above"
                                     : Hard.StartsWith("HARD, not above", StringComparison.Ordinal) ||
                                       Hard.StartsWith("HARD, other layer", StringComparison.Ordinal) ? "Outlier"
                                     : Hard.StartsWith("HARD", StringComparison.Ordinal) || Unparsed ||
                                       Hard.StartsWith("?", StringComparison.Ordinal) ? "Unknown" : "";
            public string NameShown
            {
                get
                {
                    if (Name.Length == 0) return "(no name)";
                    var (shown, findings) = TextHygiene.Reveal(Name);
                    return findings.Count > 0 ? $"⚠ {shown}" : Name;
                }
            }
            public string NameTip
            {
                get
                {
                    var findings = TextHygiene.Reveal(Name).Findings;
                    return findings.Count > 0 ? $"{NameShown}\n\n{string.Join("\n", findings)}" : NameShown;
                }
            }
        }

        /// <summary>
        /// The rules, the stores that couldn't be read, every hard permit on the machine (all
        /// providers, all layers; null when the filtering engine couldn't be read), and the
        /// sublayer the firewall's own rules sit in (null when it couldn't be found).
        /// </summary>
        public sealed record Snapshot(List<Rule> Rules, List<string> Problems, List<WfpFilters.Filter>? HardPermits,
                                      FirewallSubLayer? Firewall);

        public sealed record FirewallSubLayer(Guid Key, string Name, int Weight)
        {
            /// <summary>The layers in which this sublayer has filters; null when they couldn't be read.</summary>
            public IReadOnlySet<Guid>? Layers { get; init; }
        }

        /// <summary>Where a hard permit stands against the firewall rules' sublayer.</summary>
        public enum HardRank { Unknown, Above, NotAbove, OtherLayer }

        /// <summary>
        /// Above, below or in the firewall rules' sublayer, or in a layer where that sublayer has
        /// no filters (so the permit never meets your rules); Unknown when that can't be said.
        /// WFP leaves the order of different sublayers with equal weight open.
        /// </summary>
        public static HardRank Outranks(WfpFilters.Filter f, FirewallSubLayer? firewall)
        {
            if (firewall == null) return HardRank.Unknown;
            if (firewall.Layers != null && !firewall.Layers.Contains(f.Layer)) return HardRank.OtherLayer;
            if (f.SubLayer == firewall.Key) return HardRank.NotAbove;
            if (f.SubLayerWeight < 0 || firewall.Weight < 0 || f.SubLayerWeight == firewall.Weight) return HardRank.Unknown;
            if (f.SubLayerWeight < firewall.Weight) return HardRank.NotAbove;
            // Above in weight, but without the layers it can't be said that the two meet.
            return firewall.Layers == null ? HardRank.Unknown : HardRank.Above;
        }

        public const string OtherLayerTip =
            "A hard permit, but in a layer where your rules have no filters, so it neither competes with them nor gets past them.";

        // Filters are fetched per store in one go and joined by InstanceID: asking per rule takes
        // minutes for the few hundred rules there are. A rule whose filter didn't come back that
        // way is asked on its own.
        private const string Script = @"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$ErrorActionPreference = 'Stop'
function Clean($v) { (@($v) -join ',') -replace ""[`t`r`n]"", ' ' }
foreach ($store in 'StaticServiceStore', 'ConfigurableServiceStore') {
    $rules = @()
    try { $rules = @(Get-NetFirewallRule -PolicyStore $store) } catch { ""X`t$store`t$(Clean $_.Exception.Message)""; continue }
    $ports = @{}; $addrs = @{}; $apps = @{}; $svcs = @{}
    try { Get-NetFirewallPortFilter        -PolicyStore $store | ForEach-Object { $ports[$_.InstanceID] = $_ } } catch { }
    try { Get-NetFirewallAddressFilter     -PolicyStore $store | ForEach-Object { $addrs[$_.InstanceID] = $_ } } catch { }
    try { Get-NetFirewallApplicationFilter -PolicyStore $store | ForEach-Object { $apps[$_.InstanceID]  = $_ } } catch { }
    try { Get-NetFirewallServiceFilter     -PolicyStore $store | ForEach-Object { $svcs[$_.InstanceID]  = $_ } } catch { }
    foreach ($r in $rules) {
        $id = $r.InstanceID
        $pf = $ports[$id]; $af = $addrs[$id]; $ap = $apps[$id]; $sf = $svcs[$id]
        try {
            if (-not $pf) { $pf = $r | Get-NetFirewallPortFilter }
            if (-not $af) { $af = $r | Get-NetFirewallAddressFilter }
            if (-not $ap) { $ap = $r | Get-NetFirewallApplicationFilter }
            if (-not $sf) { $sf = $r | Get-NetFirewallServiceFilter }
        } catch { }
        ""W`t$store`t$(Clean $r.DisplayName)`t$($r.Direction)`t$($r.Action)`t$($r.Enabled)`t$(Clean $pf.Protocol)`t$(Clean $pf.LocalPort)`t$(Clean $pf.RemotePort)`t$(Clean $af.RemoteAddress)`t$(Clean $ap.Program)`t$(Clean $sf.Service)`t$(Clean $r.Name)""
    }
}
";

        /// <summary>The rules with their program facts and filter verdicts. Slow: run off the UI thread.</summary>
        public static Snapshot Read()
        {
            var (rules, problems) = ReadRules();

            var programs = new Dictionary<string, (bool Missing, string CanRun, string Tip, bool Unusual, string UnusualWhat)>(StringComparer.OrdinalIgnoreCase);
            var (filters, wfpProblem) = WfpFilters.Read();
            if (wfpProblem != null) problems.Add($"filtering engine: {wfpProblem}");
            var byName = (filters ?? new()).GroupBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
                                           .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
            var firewall = filters == null ? null : FindFirewallSubLayer(filters);
            // A hard permit only gets past your rules in a layer where their sublayer has filters.
            if (firewall != null)
            {
                var key = firewall.Key;
                firewall = firewall with { Layers = filters!.Where(f => f.SubLayer == key).Select(f => f.Layer).ToHashSet() };
            }
            var shared = rules.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                              .Where(g => g.Count() > 1).Select(g => g.Key)
                              .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var enriched = rules.Select(r =>
            {
                if (!programs.TryGetValue(r.Program, out var facts)) programs[r.Program] = facts = ProgramFacts(r.Program);
                var (hard, hardTip) = HardVerdict(r, filters == null ? null : byName.GetValueOrDefault(r.Name) ?? new(),
                                                  firewall, shared.Contains(r.Name));
                // A rule for a service matches that service's identity, not whoever runs the file.
                var serviceNote = r.Service.Equals("Any", StringComparison.OrdinalIgnoreCase) || facts.Tip.Length == 0 ? ""
                    : $"\n\nThis rule applies only to the service {r.Service}, matched by its service identity, " +
                      "not to everyone who can run this file.";
                var programFindings = TextHygiene.Reveal(r.Program).Findings;
                var programNote = programFindings.Count > 0 ? "\n\n" + string.Join("\n", programFindings) : "";
                var hardNote = "";
                if (r.Unparsed) (hard, hardTip, hardNote) = UnparsedVerdict(hard, hardTip, r);
                return r with
                {
                    ProgramMissing = facts.Missing, CanRun = facts.CanRun, ProgramTip = facts.Tip + serviceNote + programNote, UnusualRun = facts.Unusual, UnusualWhat = facts.UnusualWhat,
                    Hard = hard, HardTip = hardTip, HardNote = hardNote,
                };
            }).ToList();

            return new Snapshot(enriched, problems, filters?.Where(f => f.IsHard).ToList(), firewall);
        }

        // The sublayer of the firewall's own rules: where the filters of this machine's policy
        // rules sit (by their names), or failing that the firewall's default filters.
        private static FirewallSubLayer? FindFirewallSubLayer(List<WfpFilters.Filter> filters)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules");
                foreach (var value in key?.GetValueNames() ?? Array.Empty<string>())
                    if (key!.GetValue(value) is string rule &&
                        rule.Split('|').FirstOrDefault(x => x.StartsWith("Name=", StringComparison.Ordinal)) is { } name)
                        names.Add(name[5..]);
            }
            catch { }
            if (names.Count == 0) names.UnionWith(new[] { "Default Outbound", "Default Inbound" });

            var top = filters.Where(f => names.Contains(f.Name))
                             .GroupBy(f => f.SubLayer).OrderByDescending(g => g.Count()).FirstOrDefault();
            return top == null ? null : new FirewallSubLayer(top.Key, top.First().SubLayerName, top.First().SubLayerWeight);
        }

        // A rule's filters carry its display name and its action: an Allow rule is compared with
        // permit filters, a Block rule with block filters. Filters of the same name in the
        // firewall's own sublayer belong to a firewall rule, not to this one. Rules that share a
        // name can't be told apart, so their verdict covers all of them (marked "*").
        private static (string Verdict, string Tip) HardVerdict(Rule r, List<WfpFilters.Filter>? named,
                                                                FirewallSubLayer? firewall, bool sharedName)
        {
            if (named == null) return ("?", "The filtering engine couldn't be read.");
            if (r.Name.Length == 0) return ("?", "This rule has no name, so its live filters can't be found.");
            var isBlock = r.Action.Equals("Block", StringComparison.OrdinalIgnoreCase);
            var mine = named.Where(f => (firewall == null || f.SubLayer != firewall.Key) &&
                                        (isBlock ? f.IsBlock : f.IsPermit)).ToList();
            var star = sharedName ? "*" : "";
            var sharedTip = sharedName
                ? "\n\n* Several rules here share this name. Their filters can't be told apart, so this covers all of them."
                : "";
            // Most service blocks have no filter under their own name. Which unnamed filters carry
            // them can't be told from outside without reading WFP's conditions in full, so the app
            // says only that, and that a block can't open anything.
            if (mine.Count == 0 && isBlock && r.Enabled)
                return ("no own filter" + star,
                    "No live filter carries this rule's name. Windows may carry it out through filters not named after it " +
                    "(for services it typically does); the app can't tell which, so it claims neither way. " +
                    "A block only restricts: it can't let anything past your rules." + sharedTip);
            if (mine.Count == 0)
                return ("no filter" + star, (r.Enabled
                    ? "No live filter with this rule's name and action: Windows hasn't applied it (yet), or names it differently."
                    : "Off, and no live filter: it takes no part in any decision.") + sharedTip);

            var tip = "\n\nLive filters: " + string.Join("; ", mine.Select(f => f.Describe)) +
                      (firewall != null ? $"\nYour rules' sublayer: {firewall.Name} (weight {firewall.Weight})." : "") + sharedTip;

            var hard = mine.Where(f => f.IsHard).ToList();
            if (hard.Count > 0)
            {
                var rank = hard.Select(f => Outranks(f, firewall)).ToList();
                if (rank.Contains(HardRank.Above))
                    return ("HARD, above yours" + star,
                        "A hard permit in a sublayer that outranks the one with your rules, in a layer where your rules have filters. " +
                        "In its layer, their blocks, the firewall's default block included, can't override it: it could get through " +
                        "where your rules say no." + tip);
                if (rank.All(x => x == HardRank.OtherLayer))
                    return ("HARD, other layer" + star, OtherLayerTip + tip);
                if (!rank.Contains(HardRank.Unknown))
                    return ("HARD, not above" + star,
                        "A hard permit, but its sublayer doesn't outrank the one with your rules, so their blocks still win." +
                        (rank.Contains(HardRank.OtherLayer)
                            ? " Its other hard filters are in layers where your rules have no filters, so they don't meet them."
                            : "") + tip);
                return ("HARD" + star,
                    "A hard permit. The sublayer of your rules couldn't be compared with it, so whether it gets past them is unknown." + tip);
            }
            if (isBlock)
                return ("block" + star,
                    "A block: in its layer it wins over permits from other sublayers, unless one of those is hard and " +
                    "outranks it. So it can stop this service even where your rules allow it." + tip);
            return ("soft" + star,
                "A normal permit: a block from any other sublayer, such as the firewall's default block, still wins." + tip);
        }

        // The rule's own verdict stays in the tooltip; the column says first that Windows' tools
        // don't read the rule, since that is the more likely reason for a missing filter.
        private static (string Verdict, string Tip, string Note) UnparsedVerdict(string verdict, string tip, Rule r)
        {
            var (filters, note) =
                r.NameUnresolved || r.Name.Length == 0
                    ? ("Its name couldn't be resolved, so its live filters can't be looked up.", "name not resolved, live filters not looked up")
                : verdict.StartsWith("?", StringComparison.Ordinal)
                    ? ("Its live filters couldn't be checked.", "live filters couldn't be checked")
                : verdict.StartsWith("no ", StringComparison.Ordinal)
                    ? ("No live filter carries its name, which suggests Windows doesn't apply it: a hint, not proof.",
                       "no live filter under its name (likely not applied)")
                    : ($"Live filters do carry its name, so Windows applies it; their verdict: {verdict}.",
                       $"live filters: {verdict} (applied)");
            // A HARD verdict keeps its place: it is what the colours are for.
            var shown = verdict.StartsWith("HARD", StringComparison.Ordinal) ? $"{verdict} · not parsed" : "not parsed";
            return (shown,
                "Windows' own firewall tools return this rule without name or conditions: it is written in a " +
                "non-standard spelling (for example V2.0, lower-case field names, the protocol by name). The fields " +
                $"shown here are read from its registry string. {filters}\n\nRegistry: {r.RawRule}\n\n" + tip,
                note);
        }

        // Who may run the file: allow entries with execute rights, and deny entries. The owner
        // can always change these, which the tooltip says.
        private static (bool Missing, string CanRun, string Tip, bool Unusual, string UnusualWhat) ProgramFacts(string program)
        {
            if (program.Equals("Any", StringComparison.OrdinalIgnoreCase) || program.Equals("System", StringComparison.OrdinalIgnoreCase))
                return (false, "", "", false, "");
            var path = Environment.ExpandEnvironmentVariables(program);
            var shownPath = TextHygiene.Reveal(path).Shown;
            if (!File.Exists(path))
                return GoneFor(program)
                    ? (true, "", $"{shownPath}\n\nNot on this machine: the rule is left over from a program that is gone or moved.", false, "")
                    : (false, "?", $"{shownPath}\n\nCan't be checked from here, so it isn't known whether the file is there.", true, "file can't be checked");
            try
            {
                var security = new FileInfo(path).GetAccessControl();
                var owner = security.GetOwner(typeof(SecurityIdentifier));
                var entries = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>()
                                      .Where(e => !e.PropagationFlags.HasFlag(PropagationFlags.InheritOnly) && Runs(e))
                                      .ToList();
                var allowed = entries.Where(e => e.AccessControlType == AccessControlType.Allow).Select(e => Short(e.IdentityReference)).Distinct().ToList();
                var denied  = entries.Where(e => e.AccessControlType == AccessControlType.Deny).Select(e => Short(e.IdentityReference)).Distinct().ToList();
                // Compared by SID, so the check holds on any Windows language.
                var unusual = entries.Where(e => e.AccessControlType == AccessControlType.Allow &&
                                                 !UsualRunners.Contains(e.IdentityReference.Value))
                                     .Select(e => Short(e.IdentityReference)).Distinct().ToList();
                var canRun = string.Join(", ", allowed) + (denied.Count > 0 ? $"; denied: {string.Join(", ", denied)}" : "");
                var tip = $"{shownPath}\n\nMay run it: {(allowed.Count > 0 ? string.Join(", ", allowed) : "nobody")}" +
                          (denied.Count > 0 ? $"\nDenied: {string.Join(", ", denied)}" : "") +
                          (unusual.Count > 0 ? $"\nOutside Windows' usual set: {string.Join(", ", unusual)}" : "") +
                          $"\nOwner: {Short(owner)} (the owner can always change these permissions)";
                var what = string.Join("; ", new[]
                {
                    unusual.Count > 0 ? $"outside Windows' usual set: {string.Join(", ", unusual)}" : "",
                    denied.Count > 0 ? $"denied: {string.Join(", ", denied)}" : "",
                }.Where(x => x.Length > 0));
                return (false, canRun, tip, what.Length > 0, what);
            }
            catch (Exception ex) { return (false, "?", $"{shownPath}\n\nIts permissions can't be read: {ex.Message}", true, "permissions unreadable"); }

            static bool Runs(FileSystemAccessRule e) =>
                (e.FileSystemRights & FileSystemRights.ExecuteFile) != 0 ||
                ((int)e.FileSystemRights & (GenericExecute | GenericAll)) != 0;
        }

        private const int GenericExecute = 0x20000000, GenericAll = 0x10000000;

        // Who may run a Windows system file as shipped: SYSTEM, Administrators, Users,
        // TrustedInstaller, ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION PACKAGES.
        private static readonly HashSet<string> UsualRunners = new(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            "S-1-15-2-1", "S-1-15-2-2",
        };

        // "NT AUTHORITY\SYSTEM" → "SYSTEM": the authority adds nothing for the well-known accounts.
        private static string Short(IdentityReference? id)
        {
            if (id == null) return "unknown";
            try
            {
                var name = id.Translate(typeof(NTAccount)).Value;
                var slash = name.IndexOf('\\');
                return slash >= 0 && !name.StartsWith("NT SERVICE", StringComparison.OrdinalIgnoreCase) ? name[(slash + 1)..] : name;
            }
            catch { return id.Value; }
        }

        private static (List<Rule> Rules, List<string> Problems) ReadRules()
        {
            var rules = new List<Rule>();
            var problems = new List<string>();
            var (ok, output) = PolicyApply.RunPowerShell(Script, 180_000);
            foreach (var line in output.Split('\n').Select(l => l.TrimEnd('\r')))
            {
                var f = line.Split('\t');
                if (f[0] == "X" && f.Length >= 3) problems.Add($"{StoreName(f[1])}: {f[2]}");
                if (f[0] != "W" || f.Length < 12) continue;
                var rule = new Rule(StoreName(f[1]), f[2], f[3], f[4],
                                    f[5].Equals("True", StringComparison.OrdinalIgnoreCase),
                                    Any(f[6]), Any(f[7]), Any(f[8]), Any(f[9]), Any(f[10]), Any(f[11]))
                           { Id = f.Length > 12 ? f[12] : "" };
                rules.Add(rule.Name.Length == 0 && rule.Id.Length > 0 ? FromRegistry(rule) ?? rule : rule);
            }
            if (!ok && rules.Count == 0)
                problems.Add(string.Join(" ", output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)).Trim());
            return (rules, problems);
        }

        // ── Rules Windows' tools don't read ─────────────────────────────────
        // A few shipped rules use a spelling the cmdlets don't parse (V2.0, "rport", "Protocol=tcp"):
        // they come back with action and direction only. Their registry string still says what
        // they are, so it is read here, with field names in any case.

        private const string RestrictedServices =
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices";

        private static Rule? FromRegistry(Rule rule)
        {
            string? raw;
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"{RestrictedServices}\{rule.Store}\System");
                raw = key?.GetValue(rule.Id) as string;
            }
            catch { return null; }
            if (string.IsNullOrWhiteSpace(raw)) return null;

            var fields = raw.Split('|').Skip(1).Where(x => x.Contains('='))
                            .Select(x => (Key: x[..x.IndexOf('=')].Trim(), Value: x[(x.IndexOf('=') + 1)..].Trim()))
                            .ToList();
            string All(Func<string, bool> key) =>
                string.Join(",", fields.Where(x => key(x.Key) && x.Value.Length > 0).Select(x => x.Value));
            string One(string key) => All(k => k.Equals(key, StringComparison.OrdinalIgnoreCase));
            bool Starts(string k, string prefix) => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

            var dir = One("Dir");
            var protocol = One("Protocol");
            var action = One("Action");
            var name = One("Name");
            var unresolved = false;
            // The filters carry the resolved text, so that is what they are looked up by.
            if (IndirectNames.IsReference(name))
            {
                if (IndirectNames.Resolve(name) is { } resolved) name = resolved;
                else unresolved = true;
            }
            return rule with
            {
                Name        = name,
                NameUnresolved = unresolved,
                Action      = action.Equals("Allow", StringComparison.OrdinalIgnoreCase) ? "Allow"
                            : action.Equals("Block", StringComparison.OrdinalIgnoreCase) ? "Block" : rule.Action,
                Direction   = dir.Equals("Out", StringComparison.OrdinalIgnoreCase) ? "Outbound"
                            : dir.Equals("In", StringComparison.OrdinalIgnoreCase) ? "Inbound" : rule.Direction,
                Enabled     = One("Active") is { Length: > 0 } active
                              ? active.Equals("TRUE", StringComparison.OrdinalIgnoreCase) : rule.Enabled,
                Protocol    = protocol.ToLowerInvariant() switch
                {
                    "6" or "tcp" => "TCP", "17" or "udp" => "UDP", "1" or "icmp" => "ICMPv4", "58" => "ICMPv6",
                    "" => "Any", _ => protocol,
                },
                LocalPorts  = Any(All(k => Starts(k, "LPort"))),
                RemotePorts = Any(All(k => Starts(k, "RPort"))),
                Remote      = Any(All(k => Starts(k, "RA4") || Starts(k, "RA6"))),
                Program     = Any(One("App")),
                Service     = Any(One("Svc")),
                RawRule     = raw,
            };
        }

        // ── Purging obsolete rules ──────────────────────────────────────────
        // Services such as Defender add a Configurable rule pair for every new program version
        // and never remove the old ones, so rules for files long gone pile up. Only those are
        // purged: Configurable (Static is Windows' own set, which servicing manages), program
        // missing. Each one is backed up first; one that can't be backed up is left alone.
        //
        // What the app removes here, and what it deliberately doesn't:
        // - Obsolete rules (Configurable, program gone) are purged. A rule scoped to a file that
        //   isn't there governs nothing: it clutters the list and could interfere later.
        // - A block for a program that is there is never removed or switched off. A block only
        //   takes away: while it is in place nothing can allow that traffic, so it adds safety.
        //   Whoever ships one likely has a reason, and what removing it does is untested here.
        //   Don't add a way to remove one without testing that first.
        // - Allow rules come in two kinds. A normal (soft) permit has no verdict yet: under a
        //   lock-down's default block it opens nothing, so there is no need to touch it now.
        //   A hard permit in a sublayer above your rules', in a layer where they have filters, is
        //   a different kind: it gets past your blocks. The Hard column and the count line flag one; if one shows up, it needs looking
        //   at before anything else here.

        /// <summary>Notes: what went otherwise than planned but isn't a failure.</summary>
        public sealed record PurgeResult(int ByService, int ByRegistry, List<string> Failed, List<string> Notes, string? Backup);

        public static PurgeResult Purge(IEnumerable<Rule> rules)
        {
            var failed = new List<string>();
            var notes = new List<string>();
            var path = $@"{RestrictedServices}\Configurable\System";

            // The program is checked again on the value about to be deleted, not on the list as
            // it was read: a service may have rewritten the rule for a new version since.
            var raw = new Dictionary<string, string>();
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path))
            {
                var names = new HashSet<string>(key?.GetValueNames() ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                foreach (var r in rules.Where(r => r.Obsolete).GroupBy(r => r.Id).Select(g => g.First()))
                {
                    var kind = key != null && names.Contains(r.Id) ? key.GetValueKind(r.Id) : (Microsoft.Win32.RegistryValueKind?)null;
                    if (kind == null)
                        notes.Add($"{r.NameShown}: already gone from the registry; the list shows it until the next restart");
                    else if (kind != Microsoft.Win32.RegistryValueKind.String ||
                             key!.GetValue(r.Id, null, Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value)
                        failed.Add($"{r.NameShown}: its registry value isn't a plain string, so it wasn't backed up or removed");
                    else if (!SameFile(App(value), r.Program) || !GoneFor(App(value)))
                        failed.Add($"{r.NameShown}: its program is there again, has changed or can't be checked, so it was left alone");
                    else raw[r.Id] = value;
                }
            }
            if (raw.Count == 0) return new PurgeResult(0, 0, failed, notes, null);

            var body = new System.Text.StringBuilder();
            body.AppendLine($@"[HKEY_LOCAL_MACHINE\{path}]");
            foreach (var (id, value) in raw)
                body.AppendLine($"\"{RegEscape(id)}\"=\"{RegEscape(value)}\"");
            string backup;
            try { backup = AppFolder.WriteReg("service-rules", body.ToString()); }
            catch (Exception ex)
            {
                failed.Add($"The backup couldn't be written, so nothing was removed: {ex.Message}");
                return new PurgeResult(0, 0, failed, notes, null);
            }

            // Through the firewall service first, so the rule is gone at once, not only from the
            // registry it reads at start. In batches, as the script travels on the command line
            // and each ID goes in Base64 (PsData), which makes it longer. Names are escaped
            // because -Name takes wildcards.
            var removed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var batch in raw.Keys.Chunk(50))
            {
                var script = @"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
foreach ($id in " + PsData.Strings(batch) + @") {
    try { Remove-NetFirewallRule -PolicyStore ConfigurableServiceStore -Name ([WildcardPattern]::Escape($id)) -ErrorAction Stop; ""OK`t$id"" }
    catch { ""ERR`t$id`t$($_.Exception.Message -replace ""[`t`r`n]"", ' ')"" }
}
";
                var (ok, output) = PolicyApply.RunPowerShell(script, 120_000);
                var lines = output.Split('\n').Select(l => l.TrimEnd('\r').Split('\t')).ToList();
                foreach (var f in lines.Where(f => f.Length >= 2 && f[0] == "OK")) removed.Add(f[1]);
                foreach (var f in lines.Where(f => f.Length >= 3 && f[0] == "ERR"))
                    notes.Add($"{f[1]}: the firewall service didn't remove it ({f[2]}), so the registry is tried");
                if (!ok) notes.Add($"PowerShell didn't finish a batch ({output.Trim()}); what it didn't confirm goes through the registry");
            }

            // What the service didn't take goes from the registry; the firewall reads it at the
            // next restart. A value already gone was taken by the service without a word back.
            var byRegistry = 0;
            var rest = raw.Keys.Where(id => !removed.Contains(id)).ToList();
            if (rest.Count > 0)
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path, writable: true);
                    foreach (var id in rest)
                    {
                        if (key == null) { failed.Add($"{id}: the rules key can't be opened for writing"); continue; }
                        var now = key.GetValue(id, null, Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames);
                        if (now == null) { removed.Add(id); continue; }
                        // Only what was checked and backed up: a rule rewritten meanwhile is a new one.
                        if (now is not string current || current != raw[id])
                        {
                            failed.Add($"{id}: changed since the check, so it was left alone");
                            continue;
                        }
                        try { key.DeleteValue(id); byRegistry++; }
                        catch (Exception ex) { failed.Add($"{id}: {ex.Message}"); }
                    }
                }
                catch (Exception ex) { failed.AddRange(rest.Select(id => $"{id}: {ex.Message}")); }
            }
            return new PurgeResult(removed.Count, byRegistry, failed, notes, backup);
        }

        private static string App(string raw) =>
            raw.Split('|').Select(x => x.Trim())
               .FirstOrDefault(x => x.StartsWith("App=", StringComparison.OrdinalIgnoreCase))?[4..].Trim() ?? "";

        private static bool SameFile(string a, string b) =>
            Environment.ExpandEnvironmentVariables(a).Equals(Environment.ExpandEnvironmentVariables(b), StringComparison.OrdinalIgnoreCase);

        // Services run as SYSTEM or a service account, so a per-user variable means another
        // folder for them than for whoever runs this app: such a path can't be judged from here.
        private static readonly string[] PerUser =
            { "%USERPROFILE%", "%LOCALAPPDATA%", "%APPDATA%", "%TEMP%", "%TMP%", "%HOMEPATH%", "%HOMEDRIVE%", "%USERNAME%", "%ONEDRIVE%" };

        /// <summary>True when the program, as written in the rule, is surely not on this machine.</summary>
        private static bool GoneFor(string program) =>
            program.Length > 0 && !PerUser.Any(v => program.Contains(v, StringComparison.OrdinalIgnoreCase)) &&
            Gone(Environment.ExpandEnvironmentVariables(program));

        /// <summary>
        /// True only when Windows says the file or its folder doesn't exist on a drive that is
        /// there. A file that merely can't be read (access denied, a variable that didn't expand,
        /// a drive not attached) isn't gone.
        /// </summary>
        private static bool Gone(string path)
        {
            if (path.Contains('%') || !Path.IsPathFullyQualified(path)) return false;
            if (Path.GetPathRoot(path) is not { Length: > 0 } root || !Directory.Exists(root)) return false;
            if (GetFileAttributesW(path) != InvalidFileAttributes) return false;
            var error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            return error == ErrorFileNotFound || error == ErrorPathNotFound;
        }

        private const uint InvalidFileAttributes = 0xFFFFFFFF;
        private const int ErrorFileNotFound = 2, ErrorPathNotFound = 3;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFileAttributesW(string fileName);

        private static string RegEscape(string raw) => raw.Replace(@"\", @"\\").Replace("\"", "\\\"");

        private static string StoreName(string store) => store switch
        {
            "StaticServiceStore"       => "Static",
            "ConfigurableServiceStore" => "Configurable",
            _                          => store,
        };

        private static string Any(string v) => string.IsNullOrWhiteSpace(v) ? "Any" : v.Trim();
    }
}
