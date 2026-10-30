using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

using HueThemeKit;

namespace FirewallManager
{
    public partial class LogViewerWindow : Window
    {
        private static readonly string LogFile =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                @"System32\LogFiles\Firewall\pfirewall.log");

        public class LogEntry : System.ComponentModel.INotifyPropertyChanged
        {
            // Only the filter's label changes after a row is shown (RelabelFilters): the grid is told.
            public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
            public string Time      { get; set; } = "";
            public string Action    { get; set; } = "";
            public string Protocol  { get; set; } = "";
            public string? ProtocolTip => IsMarker ? null : Protocols.Tip(Protocol);
            public string SrcIP     { get; set; } = "";
            public string DstIP     { get; set; } = "";
            public string SrcPort   { get; set; } = "";
            public string DstPort   { get; set; } = "";
            public string Direction { get; set; } = "";
            public string Resolved  { get; set; } = "";   // name for the far side; where it came from is in ResolvedSource
            public string Program   { get; set; } = "";   // full path; Live source only (the file has none)
            // Services in that process ("MapsBroker"), if any: a service host alone says nothing
            // about who tried.
            public string Services  { get; set; } = "";
            public string ServicesLong { get; set; } = "";
            // The far side of the connection (Dst for SEND, Src for RECEIVE): on this network or not.
            public string Locality    { get; set; } = "";
            public string LocalityTip { get; set; } = "";
            public string LocalityTone => LogTone(Locality);
            // svchost.exe only hosts services, so without one the name says nothing: mark the
            // service unknown (its process ended before it could be looked up).
            public bool   ServiceUnknown => string.IsNullOrEmpty(Services)
                && LiveDropSource.ShortProgram(Program).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase);
            // From the recorded process start (event 4688), when process starts are recorded.
            public string CommandLine   { get; set; } = "";
            public string ParentProgram { get; set; } = "";
            public DateTime? StartTime  { get; set; }          // when that process started, if recorded
            public string ServiceGroup  { get; set; } = "";   // "-k netsvcs" when services share hosts
            public string ProgramName => ServiceUnknown && ServiceGroup.Length > 0
                ? $"{LiveDropSource.ShortProgram(Program)} ({ServiceGroup} group)"
                : ServiceUnknown
                ? $"{LiveDropSource.ShortProgram(Program)} (service unknown)"
                : string.IsNullOrEmpty(Services)
                ? LiveDropSource.ShortProgram(Program)
                : $"{LiveDropSource.ShortProgram(Program)} ({Services})";
            // The path and the services come from Windows and other software: what can't be seen
            // in them is shown, the name gets a ⚠ and the tooltip the findings. ProgramName stays
            // the plain text wherever it is used as data (talker key, export).
            private List<string> ProgramFindings =>
                TextHygiene.Reveal(Program).Findings.Concat(TextHygiene.Reveal(Services).Findings).Distinct().ToList();
            // Ctrl+C and sorting in the grid use the stored text, not the shown form.
            public string ProgramPlain => ProgramName;
            public string ProgramShown => ProgramFindings.Count == 0 ? ProgramName : "⚠ " + TextHygiene.Reveal(ProgramName).Shown;
            public string ProgramTip => BaseTip + StartTip +
                (ProgramFindings is { Count: > 0 } found ? "\n\n" + string.Join("\n", found) : "") +
                (_verdict?.Tip is { Length: > 0 } known ? "\n\n" + known : "");

            // What the program file is (ProgramTrust), coloured as in the rules list.
            private ProgramVerdict? _verdict;
            public ProgramTone ProgramTone => _verdict?.Tone ?? ProgramTone.None;
            public void SetVerdict(ProgramVerdict? verdict)
            {
                if (Equals(_verdict, verdict)) return;
                _verdict = verdict;
                PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(ProgramTone)));
                PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(ProgramTip)));
            }
            private string PathShown => TextHygiene.Reveal(Program).Shown;
            private string BaseTip => ServiceUnknown && ServiceGroup.Length > 0
                ? $"{PathShown}\n\nOne of the services in the \"{ServiceGroup}\" group: on this machine services share hosts, so the recorded start names only the group."
                : ServiceUnknown
                ? $"{PathShown}\n\nThis svchost.exe ended before its services could be read, and no recorded process start " +
                  "names them. Turning on Process starts records them from now on."
                : string.IsNullOrEmpty(ServicesLong)
                ? PathShown
                : $"{PathShown}\n\nServices in this process:\n{ServicesLong}";
            private string StartTip =>
                (CommandLine.Length > 0 ? $"\n\nStarted as: {CommandLine}" : "") +
                (ParentProgram.Length > 0 ? $"\nStarted by: {TextHygiene.Reveal(ParentProgram).Shown}" : "");
            public DateTime Ts      { get; set; }          // parsed timestamp, for the time scope

            // DNS mark: which kind, and in words without a mark ("unexpected DNS",
            // "encrypted DNS (Cloudflare)"); None and "" for normal traffic. Shown instead of
            // Resolved, with its mark added there (DnsWarnShown).
            public DnsWarnKind DnsWarnKind { get; set; }
            public string DnsWarn   { get; set; } = "";
            public bool   DnsByRule { get; set; }          // outgoing DNS a switched-on rule allows
            public string RuleName  { get; set; } = "";   // inferred rule, plain (ALLOW: active; DROP: would-allow)
            public bool   IsWouldAllow { get; set; }       // true = DROP matched a DISABLED rule
            // A switched-on block rule of the app that covers this connection too: turning the
            // would-allow rule on wouldn't let it through. "" = none.
            public string StillBlockedBy { get; set; } = "";
            private string BlockNote(Func<string, string> name) =>
                StillBlockedBy.Length > 0 ? $" (a block rule still stops it: {name(StillBlockedBy)})" : "";
            // As shown: a switched-off rule that would allow it reads "⊘ Name", a name with
            // characters that hide gets a ⚠ (findings in RuleTip). RuleName stays the plain name
            // wherever it is used as data.
            public string RuleDisplay => (IsWouldAllow && RuleName.Length > 0 ? "⊘ " : "") + NameShown(RuleName) + BlockNote(NameShown);
            public string? RuleTip => NameFindings(RuleName) is { } found
                ? found + (NameFindings(StillBlockedBy) is { } blockFound ? "\n" + blockFound : "")
                : NameFindings(StillBlockedBy);
            public string RulePlain => (IsWouldAllow && RuleName.Length > 0 ? "⊘ " : "") + RuleName + BlockNote(n => n);   // copy and sort
            // Row colours come from theme tokens (looked up when the row is built).
            public Brush  RuleBrush => IsWouldAllow && StillBlockedBy.Length == 0
                ? ThemeRefs.Brush("Brush.WarnText")    // would allow if enabled
                : ThemeRefs.Brush("Brush.TextDim");    // active rule that allowed it, or one a block rule overrides
            private bool  Allowed => Action.Equals("ALLOW", StringComparison.OrdinalIgnoreCase);
            // A note, not a warning: DNS that never leaves the machine, or direct DNS a rule of
            // yours let through. Dim, no tint, never "unexpected".
            public bool   IsDnsNote => DnsWarnKind == DnsWarnKind.Loopback || (DnsWarnKind == DnsWarnKind.Direct && Allowed);
            public bool   HasDnsMark => DnsWarnKind != DnsWarnKind.None;
            // A DNS warning (amber, or red when it went through): tints the row.
            public bool   IsDnsAnomaly => HasDnsMark && !IsDnsNote;
            // Allowed traffic that should not have happened (unexpected or encrypted DNS that went
            // through): the red Action tag, red text and tint.
            public bool   IsUnexpectedAllow => Allowed && (DnsWarnKind is DnsWarnKind.Unexpected or DnsWarnKind.Encrypted);
            // The cell: the mark carries the outcome, the Action tag the word.
            public string DnsWarnShown => !HasDnsMark ? "" : IsUnexpectedAllow ? $"🚨 {DnsWarn}" : IsDnsNote ? $"ⓘ {DnsWarn}" : $"⚠ {DnsWarn}";
            // Tooltip, Copy for AI and the export: words only.
            public string DnsWarnWords => !HasDnsMark ? ""
                : DnsWarnKind == DnsWarnKind.Loopback ? "DNS note: DNS to this machine (it never leaves the machine)"
                : IsDnsNote ? "DNS note: direct DNS (sent by the program itself, so not in Windows' DNS log)"
                : $"DNS warning, {(Allowed ? "ALLOWED" : "blocked")}: {DnsWarn}";
            // Joined with Windows' DNS client log: the lookup that returned this connection's
            // address (a fact, unlike the cache snapshot or the range guess), or — while the DNS
            // log was recording — no lookup at all: the program went to a literal address.
            public int    ProcessId  { get; set; }
            public long   FilterId   { get; set; }        // Live only; 0 = not known
            // The filter's label, looked up in the filtering engine (see NameFilters); null = not
            // looked up. The grid and Copy for AI read the same label.
            private FilterLabel? _filter;
            internal FilterLabel? Filter
            {
                get => _filter;
                set
                {
                    _filter = value;
                    foreach (var name in new[] { nameof(FilterName), nameof(FilterPlain), nameof(FilterTip) })
                        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
                }
            }
            public string FilterName  => _filter?.Name ?? "";
            public string FilterPlain => _filter?.Plain ?? "";   // the stored name, for copy and sort
            public string FilterTip   => _filter?.Tip ?? "";
            public string FilterCopy  => _filter?.Copy ?? "";    // for Copy for AI: id plus name or why not
            public bool   FilterUnresolved => _filter?.Unresolved == true;
            // A line between the connections, not a connection: a firewall reload, a network
            // change or a clock change (see MarkerRows). MarkerTip says what it is.
            public bool   IsMarker   { get; set; }
            public string MarkerTip  { get; set; } = "";
            public string LookupBy   { get; set; } = "";   // program that asked, if known
            public DateTime LookupTime { get; set; }
            public bool   LookupSameProgram { get; set; }
            public bool   NoLookup   { get; set; }
            public string ResolvedSource { get; set; } = "";   // "lookup", "cache", "guess"
            public string ResolvedDisplay => HasDnsMark ? DnsWarnShown : NoLookup ? "no Windows lookup" : Resolved;
            public string? ResolvedTip => IsMarker ? MarkerTip
                : HasDnsMark ? DnsWarnWords
                : NoLookup ? "No lookup in Windows' DNS log returned this address, although the log was recording. " +
                             "The program used the address directly, asked its own resolver (e.g. a browser's secure DNS), " +
                             "or reused an answer from before the log started."
                : ResolvedSource == "lookup"
                    ? $"Looked up as {Resolved} at {LookupTime:HH:mm:ss}" +
                      (LookupBy.Length > 0 ? $" by {LookupBy}" : "") +
                      (LookupSameProgram ? " (the same program)" : "") + " — from Windows' DNS log."
                : ResolvedSource == "cache" ? $"{Resolved} — from Windows' DNS cache."
                : ResolvedSource == "guess" ? $"{Resolved} — a guess from the address range, not a lookup."
                : null;
            public Brush  ResolvedBrush => IsUnexpectedAllow
                ? ThemeRefs.Brush("Brush.ErrorText")   // allowed unexpected
                : IsDnsNote
                    ? ThemeRefs.Brush("Brush.TextDim")   // a note, not an alarm
                : IsDnsAnomaly || NoLookup
                    ? ThemeRefs.Brush("Brush.WarnText")  // dropped unexpected / no lookup behind it
                    : ThemeRefs.Brush("Brush.TextDim");  // normal resolved name
            public Brush  RowTint => IsUnexpectedAllow
                ? ThemeRefs.Brush("Brush.ErrorSoft")
                : ThemeRefs.Brush("Brush.WarnSoft");   // the row style applies it to anomalies only

            /// <summary>The theme changed (a contrast theme on or off): the colours above are read again.</summary>
            public void ThemeChanged()
            {
                foreach (var name in new[] { nameof(RuleBrush), nameof(ResolvedBrush), nameof(RowTint) })
                    PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
            }
        }

        // Loopback: DNS to this machine itself, a note only (it never leaves the machine).
        public enum DnsWarnKind { None, Unexpected, Encrypted, Direct, Loopback }

        // The Network tag's colour in this window. A talker or a lookup reaching both sides is
        // an outlier here (indigo, like "None" and rare protocols), while the rule list keeps
        // amber for a rule's Mixed scope, so the shared Tone stays as it is.
        private static string LogTone(string kind) => kind == "Mixed" ? "Rare" : NetworkLocality.Tone(kind);

        // A name from Windows or other software (rule, program, filter), as shown: hidden
        // characters made visible and a ⚠ before it when TextHygiene finds anything; the findings,
        // one per line, go in its tooltip. The stored text is never changed.
        private static string NameShown(string name)
        {
            var (shown, findings) = TextHygiene.Reveal(name);
            return findings.Count == 0 ? name : "⚠ " + shown;
        }

        private static string? NameFindings(string name)
        {
            var findings = TextHygiene.Reveal(name).Findings;
            return findings.Count == 0 ? null : string.Join("\n", findings);
        }

        // The same for Copy for AI: the name as shown, and what was found in words (hidden
        // characters and look-alike letters named apart).
        private static string ForAi(string name) => TextHygiene.ForText(name);

        private DateTime? _since          = null;
        // Time window: minutes back from now (null = All), or a fixed Clear mark that wins
        // until the slider is moved again.
        private int?      _scopeMinutes = 5;
        private DateTime? _clearMark;
        private readonly System.Windows.Threading.DispatcherTimer _scopeDebounce =
            new() { Interval = TimeSpan.FromMilliseconds(350) };
        private bool      _dropsOnly      = false;
        private bool      _allowsOnly     = false;

        // ── Noise categories (true = suppress) ────────────────────────────────
        // One switch per category in use (config.json's or the built-in ones, see BuildNoiseMenu),
        // starting as its "suppress" says: the built-in ones all suppress, so the log opens clean
        // (traffic light green). Plus one for outgoing DNS a switched-on rule of yours allows
        // (expected chatter), which no category describes.
        private const string DnsByRuleNoise = "DNS (your rules)";
        private readonly Dictionary<string, bool> _noise = new();
        // Where the categories apply: a row is hidden only when its address family is on too.
        private bool _noiseV4 = true, _noiseV6 = true;

        // ── Rule inference ────────────────────────────────────────────────────
        // The log records the packet, not which rule matched it, so the likely rule is
        // re-derived by matching (addresses, ports, proto, dir, program) against the CUSTOM_*
        // allow rules. One best match shows its name; none or a tie stays blank rather than guess.
        // The app's block rules are read too, only to say when one still stops a connection
        // that a switched-off allow rule would let through.
        private sealed class LogRule
        {
            public string Name = "";
            public bool   Block;                        // Action=Block
            public bool   DirOut;                       // true = Out, false = In
            public string? Proto;                       // protocol number ("6", "58", "0"); null = any (no field)
            public List<Ipv4Scope.Span>? Remote;        // null = any address (no RA4/RA6 at all)
            public List<Ipv4Scope.Span>? Local;         // LA4; null = any address (no LA4/LA6 at all)
            public List<(int first, int last)>? RemotePorts;   // RPort; null = any
            public List<(int first, int last)>? LocalPorts;    // LPort; null = any
            public string Program = "";                 // App=, expanded; "" = any program
            public string Service = "";                 // Svc=; "" = any service
            public bool Enabled;                        // active rule vs disabled (would-allow)
            // Holds something this reading can't check (an address or port keyword such as
            // LocalSubnet or RPC, IPv6 addresses only, a /0 Windows refuses to load): it never
            // claims a connection, rather than pass for "any".
            public bool Unmatchable;
        }
        private List<LogRule> _allowRules = new();
        private List<LogRule> _blockRules = new();
        // Switched-on policy rules made outside this app (gpedit) that allow outgoing DNS. They
        // don't count for the tripwire, only the app's own rules do; the DNS banner names them so
        // "no DNS rule of this app" isn't read as "no DNS rule at all".
        private int _gpeditDnsRules;

        private void LoadAllowRules()
        {
            var list = new List<LogRule>();
            var blocks = new List<LogRule>();
            var gpeditDns = 0;
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules");
                if (k != null)
                    foreach (var name in k.GetValueNames())
                    {
                        var raw = k.GetValue(name)?.ToString() ?? "";
                        var r = ParseLogRule(name, raw);
                        if (r == null) continue;
                        if (name.StartsWith("CUSTOM_", StringComparison.Ordinal)) (r.Block ? blocks : list).Add(r);
                        else if (!r.Block && r.Enabled && IsDnsRule(r)) gpeditDns++;
                    }
            }
            catch { }
            _allowRules = list;
            _blockRules = blocks;
            _gpeditDnsRules = gpeditDns;
        }

        // An allow rule that names DNS: outgoing, UDP/TCP/any protocol, a remote port of 53 or 853.
        // A rule without a port limit lets DNS through for its program too, but it says nothing
        // about which DNS is acceptable, so it isn't one.
        private static bool IsDnsRule(LogRule r) =>
            r.DirOut && r.Proto is (null or "6" or "17") &&
            r.RemotePorts is { } ports && ports.Any(p => (p.first <= 53 && 53 <= p.last) || (p.first <= 853 && 853 <= p.last));

        // The line for the DNS banner and Copy for AI, or null while a DNS rule of this app is on.
        private string? DnsRuleState()
        {
            var own = _allowRules.Where(IsDnsRule).ToList();
            if (own.Any(r => r.Enabled)) return null;
            var head = own.Count > 0 ? "DNS rule of this app switched off" : "No DNS rule of this app";
            var n = _gpeditDnsRules;
            var gpedit = n > 0 ? $" {n} gpedit rule{(n == 1 ? "" : "s")} allow{(n == 1 ? "s" : "")} DNS." : "";
            return $"{head}: every DNS query that leaves this machine is flagged as unexpected.{gpedit}";
        }

        private static LogRule? ParseLogRule(string regKey, string raw)
        {
            string action = "", dir = "", display = regKey, active = "TRUE";
            string? proto = null;
            string program = "", service = "";
            var remote = new List<Ipv4Scope.Span>();
            var local  = new List<Ipv4Scope.Span>();
            var rports = new List<(int, int)>();
            var lports = new List<(int, int)>();
            bool hasRemote = false, hasLocal = false, hasRPort = false, hasLPort = false, unmatchable = false;

            foreach (var part in raw.Split('|'))
            {
                var i = part.IndexOf('=');
                if (i < 0) continue;
                var key = part[..i].Trim().ToUpperInvariant();
                var v   = part[(i + 1)..].Trim();
                switch (key)
                {
                    case "NAME":     display = v; break;
                    case "ACTION":   action = v; break;
                    case "ACTIVE":   active = v; break;
                    case "DIR":      dir = v; break;
                    // By number: 0 is HOPOPT, not "any"; only a rule without the field takes any.
                    case "PROTOCOL":
                        proto = ProtoKey(v);
                        if (proto == null) unmatchable = true;
                        break;
                    // One number or one range per field; anything else (RPC, a list) can't be checked.
                    case "RPORT":
                        hasRPort = true;
                        if (PortSpan(v) is { } rp) rports.Add(rp); else unmatchable = true;
                        break;
                    case "LPORT":
                        hasLPort = true;
                        if (PortSpan(v) is { } lp) lports.Add(lp); else unmatchable = true;
                        break;
                    case "APP":      program = Environment.ExpandEnvironmentVariables(v); break;
                    case "SVC":      service = v; break;
                    case "RA4":
                        // "Any" spelled out is no limit at all, the same as no RA4.
                        if (v.Equals("Any", StringComparison.OrdinalIgnoreCase)) break;
                        hasRemote = true;
                        if (!Ipv4Scope.IsSlashZero(v) && Ipv4Scope.Parse(v, out _) is { } span) remote.Add(span);
                        else unmatchable = true;
                        break;
                    // IPv6 addresses only widen a rule that has RA4; on their own they scope it to IPv6.
                    case "RA6":
                        hasRemote = true;
                        break;
                    // This machine's side, read the same way.
                    case "LA4":
                        if (v.Equals("Any", StringComparison.OrdinalIgnoreCase)) break;
                        hasLocal = true;
                        if (!Ipv4Scope.IsSlashZero(v) && Ipv4Scope.Parse(v, out _) is { } lspan) local.Add(lspan);
                        else unmatchable = true;
                        break;
                    case "LA6":
                        hasLocal = true;
                        break;
                    default:
                        // Keyword fields: RPort2_10=IPHTTPS, RA42=…, RA62=…, LA42=….
                        if (key.StartsWith("RPORT", StringComparison.Ordinal) || key.StartsWith("LPORT", StringComparison.Ordinal) ||
                            key.StartsWith("RA4", StringComparison.Ordinal)   || key.StartsWith("RA6", StringComparison.Ordinal) ||
                            key.StartsWith("LA4", StringComparison.Ordinal)   || key.StartsWith("LA6", StringComparison.Ordinal))
                            unmatchable = true;
                        break;
                }
            }

            var block = action.Equals("Block", StringComparison.OrdinalIgnoreCase);
            if (!block && !action.Equals("Allow", StringComparison.OrdinalIgnoreCase)) return null;
            if (hasRemote && remote.Count == 0) unmatchable = true;   // IPv6 only
            if (hasLocal && local.Count == 0) unmatchable = true;

            return new LogRule
            {
                Name   = display.StartsWith("CUSTOM_", StringComparison.Ordinal)
                            ? display["CUSTOM_".Length..].Replace('_', ' ') : display,
                Block  = block,
                DirOut = !dir.Equals("In", StringComparison.OrdinalIgnoreCase),
                Proto  = proto,
                Remote      = hasRemote ? remote : null,
                Local       = hasLocal ? local : null,
                RemotePorts = hasRPort ? rports : null,
                LocalPorts  = hasLPort ? lports : null,
                Enabled = !active.Equals("FALSE", StringComparison.OrdinalIgnoreCase),
                Program = program,
                Service = service,
                Unmatchable = unmatchable
            };
        }

        // A protocol as a plain number, from a name or a number ("TCP" → "6", "058" → "58");
        // null for text the table doesn't know.
        private static string? ProtoKey(string? text) =>
            Protocols.Number(text) is { } n && int.TryParse(n, NumberStyles.None, CultureInfo.InvariantCulture, out var i)
                ? i.ToString(CultureInfo.InvariantCulture) : null;

        // "53" or "1000-2000" → (first, last); null for anything else.
        private static (int first, int last)? PortSpan(string v)
        {
            if (v.Contains(',') || Ipv4Scope.BadPorts(v) != null) return null;
            var ends = v.Split('-');
            var first = int.Parse(ends[0]);
            return (first, ends.Length == 2 ? int.Parse(ends[1]) : first);
        }

        // How narrowly a rule holds a connection (larger = narrower): an address-scoped rule beats
        // any address, a port-scoped one any port; then the smaller address span holding it (the
        // far side, then this machine's), the smaller port span, a named program, a named service.
        private readonly record struct Narrowness(int Addressed, int Ported, long AddressCount, long LocalCount,
                                                  long PortCount, int Program, int Service)
            : IComparable<Narrowness>
        {
            public int CompareTo(Narrowness o) =>
                Addressed != o.Addressed ? Addressed.CompareTo(o.Addressed)
                : Ported != o.Ported     ? Ported.CompareTo(o.Ported)
                : AddressCount != o.AddressCount ? o.AddressCount.CompareTo(AddressCount)
                : LocalCount != o.LocalCount   ? o.LocalCount.CompareTo(LocalCount)
                : PortCount != o.PortCount     ? o.PortCount.CompareTo(PortCount)
                : Program != o.Program   ? Program.CompareTo(o.Program)
                : Service.CompareTo(o.Service);
        }

        // The allow rules (switched on, or off) that would let this connection through, with how
        // narrowly each holds it. Program and service count only where the entry knows them
        // (Live); the file log has none, so there a program-scoped rule stays a candidate.
        private List<(LogRule rule, Narrowness fit)> RulesAllowing(LogEntry e, bool enabled) => RulesHolding(_allowRules, e, enabled);

        // The same over any list of rules. strict: a rule naming a program or service holds the
        // row only if the row names it too, by full path where both are full; for saying a
        // block rule stops a connection, which a guess mustn't claim.
        private static List<(LogRule rule, Narrowness fit)> RulesHolding(List<LogRule> rules, LogEntry e, bool enabled, bool strict = false)
        {
            var found = new List<(LogRule, Narrowness)>();
            bool sendDir = !e.Direction.Equals("RECEIVE", StringComparison.OrdinalIgnoreCase);
            // A rule's remote side is the far one: Dst going out, Src coming in; its local side is
            // this machine, the other one. Not IPv4: only rules without that address scope hold it.
            uint? far  = Ipv4Scope.TryAddress(sendDir ? e.DstIP : e.SrcIP, out var ip, out _) ? ip : null;
            uint? near = Ipv4Scope.TryAddress(sendDir ? e.SrcIP : e.DstIP, out var nip, out _) ? nip : null;
            int.TryParse(sendDir ? e.DstPort : e.SrcPort, out var remotePort);
            int.TryParse(sendDir ? e.SrcPort : e.DstPort, out var localPort);
            var proto = ProtoKey(e.Protocol);

            foreach (var r in rules)
            {
                if (r.Unmatchable || r.Enabled != enabled) continue;
                if (r.DirOut != sendDir) continue;
                if (r.Proto != null && r.Proto != proto) continue;
                long addressSpan = 1L << 32;
                if (r.Remote != null)
                {
                    if (far is not { } a) continue;
                    var holding = r.Remote.Where(s => s.Contains(a)).ToList();
                    if (holding.Count == 0) continue;
                    addressSpan = holding.Min(s => (long)s.Count);
                }
                long localSpan = 1L << 32;
                if (r.Local != null)
                {
                    if (near is not { } l) continue;
                    var holding = r.Local.Where(s => s.Contains(l)).ToList();
                    if (holding.Count == 0) continue;
                    localSpan = holding.Min(s => (long)s.Count);
                }
                if (!PortsHold(r.RemotePorts, remotePort, out var rSpan)) continue;
                if (!PortsHold(r.LocalPorts, localPort, out var lSpan)) continue;
                if (strict && ((r.Program.Length > 0 && e.Program.Length == 0) || (r.Service.Length > 0 && e.Services.Length == 0))) continue;
                if (r.Program.Length > 0 && e.Program.Length > 0 && !SameProgram(r.Program, e.Program, strict)) continue;
                if (r.Service.Length > 0 && e.Services.Length > 0 &&
                    !e.Services.Split(',').Any(x => x.Trim().Equals(r.Service, StringComparison.OrdinalIgnoreCase))) continue;
                found.Add((r, new Narrowness(
                    r.Remote != null || r.Local != null ? 1 : 0,
                    r.RemotePorts != null || r.LocalPorts != null ? 1 : 0,
                    addressSpan, localSpan, rSpan * lSpan,
                    r.Program.Length > 0 ? 1 : 0,
                    r.Service.Length > 0 ? 1 : 0)));
            }
            return found;
        }

        // Whether one of the port spans holds the port, and the smallest such span (65536 = any).
        private static bool PortsHold(List<(int first, int last)>? spans, int port, out long span)
        {
            span = 65536;
            if (spans == null) return true;
            var holding = spans.Where(p => port >= p.first && port <= p.last).ToList();
            if (holding.Count == 0) return false;
            span = holding.Min(p => (long)(p.last - p.first + 1));
            return true;
        }

        // Returns (name, isWouldAllow, stillBlockedBy). ALLOW entries match ENABLED rules (what let
        // them through). DROP entries match DISABLED allow rules (what WOULD let them
        // through if turned on) — turning the drop log into a preview/test surface — unless a
        // switched-on block rule of the app covers them too: that one is named with it.
        private (string name, bool wouldAllow, string stillBlockedBy) MatchRule(LogEntry e)
        {
            bool isAllow = e.Action.Equals("ALLOW", StringComparison.OrdinalIgnoreCase);
            bool isDrop  = e.Action.Equals("DROP",  StringComparison.OrdinalIgnoreCase);
            if (!isAllow && !isDrop) return ("", false, "");

            var matches = RulesAllowing(e, enabled: isAllow);
            if (matches.Count == 0) return ("", false, "");

            var top = matches.Max(m => m.fit);
            var best = matches.Where(m => m.fit.CompareTo(top) == 0).ToList();
            if (best.Count != 1) return ("", false, "");   // ambiguous → blank

            // The plain name; a DROP's switched-off rule gets its "⊘" only where it is shown.
            var block = "";
            if (isDrop && RulesHolding(_blockRules, e, enabled: true, strict: true) is { Count: > 0 } blocks)
            {
                var narrowest = blocks.Max(b => b.fit);
                block = PlainRuleName(blocks.Where(b => b.fit.CompareTo(narrowest) == 0)
                                            .Select(b => b.rule.Name).OrderBy(n => n, StringComparer.Ordinal).First());
            }
            return (PlainRuleName(best[0].rule.Name), isDrop, block);
        }

        private static string PlainRuleName(string name) =>
            name.StartsWith("CUSTOM ", StringComparison.Ordinal) ? name["CUSTOM ".Length..] : name;

        // Full paths when both are full; otherwise by file name ("firefox.exe"). strict: two full
        // paths must be the same path, not only the same file name.
        private static bool SameProgram(string rulePath, string entryPath, bool strict = false) =>
            rulePath.Equals(entryPath, StringComparison.OrdinalIgnoreCase) ||
            (!(strict && rulePath.Contains('\\') && entryPath.Contains('\\')) &&
             Path.GetFileName(rulePath).Equals(Path.GetFileName(entryPath), StringComparison.OrdinalIgnoreCase));

        // Predicate definitions (prefixes/suffixes/ports/etc.) from the effective
        // config. The _noise dict above holds the on/off switches by category name.
        private readonly List<AppConfig.NoiseCategory> _noiseDefs =
            ConfigService.Effective().Noise;

        // Local DNS-cache map (DstIP → resolved name), rebuilt each load. No egress.
        private Dictionary<string, string> _dnsMap = new();
        private bool _dnsCacheRead;            // whether the names in view could come from the cache
        private static string? _dnsCacheMissing;   // why the cache couldn't be read, shown with the count

        // Guards against CheckBox Checked events changing the view during InitializeComponent
        private bool _ready = false;

        // The rows the Log grid shows (after the talker filter), for export and the counts.
        private List<LogEntry> _currentEntries = new();

        // The toolbar on one line: its buttons' own widths (they depend on the font, the
        // display scaling and the labels), plus the window's margins and frame.
        private double ToolbarWidth()
        {
            // Common controls always; of the two source groups (Live / File) only one shows at a
            // time, so the wider of the two counts. Hidden ones are measured as if shown.
            double common = 0, live = 0, file = 0;
            foreach (UIElement child in Toolbar.Children)
            {
                var group = (child as FrameworkElement)?.Tag as string;
                var hidden = child.Visibility == Visibility.Collapsed;
                if (hidden && group == null) continue;        // hidden for other reasons: not counted
                if (hidden) child.Visibility = Visibility.Visible;
                child.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                var w = child.DesiredSize.Width;              // includes each element's margin
                if (hidden) child.Visibility = Visibility.Collapsed;
                if (group == "live") live += w; else if (group == "file") file += w; else common += w;
            }
            return common + Math.Max(live, file) + 2 * 12 + 40;   // root margin + frame and a little air
        }

        // The Action column at least as wide as its widest word (the NETWORK marker's) in the
        // tag as this machine's font draws it, plus the grid's cell padding: a fixed width cut it.
        private void FitActionColumn()
        {
            double widest = 0;
            foreach (var word in new[] { "ALLOW", "DROP", "RELOAD", "NETWORK", "CLOCK" })
            {
                var probe = new ContentControl { Content = word, Style = (Style)FindResource("Hue.Tag"),
                                                 FontFamily = (FontFamily)FindResource("Font.Ui") };
                probe.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                widest = Math.Max(widest, probe.DesiredSize.Width);
            }
            var padding = TryFindResource(typeof(DataGridCell)) is Style cell
                          && cell.Setters.OfType<Setter>().FirstOrDefault(x => x.Property == Control.PaddingProperty)?.Value is Thickness t
                ? t.Left + t.Right : 24;
            var need = Math.Ceiling(widest + padding + 2);   // + the cell's rounding
            if (need > ActionColumn.Width.Value) ActionColumn.Width = new DataGridLength(need);
        }

        // The Log grid without sideways scrolling in Live, the main view: every column, Program
        // and Filter included though File hides them, its scrollbar and border, plus the
        // window's margins and frame.
        private double GridWidth() =>
            LogGrid.Columns.Sum(c => c.Width.IsAbsolute ? c.Width.Value : c.MinWidth)
            + SystemParameters.VerticalScrollBarWidth
            + LogGrid.BorderThickness.Left + LogGrid.BorderThickness.Right
            + 2 * 12 + 40;

        public LogViewerWindow()
        {
            InitializeComponent();
            HueTitleBar.Attach(this);
            FitActionColumn();
            // Opens on the main window's screen, centred: 92% wide, 80% tall (at most
            // 1760 × 950, at least 1000 × 480), and at least as wide as the toolbar on one line
            // and the Live grid need, never wider than the screen. Narrower, the toolbar wraps
            // and the grid scrolls.
            ScreenFit.Apply(this, new ScreenFit.Sizing(0.92, 0.80, 1760, 950, 1000, 480),
                            Application.Current.MainWindow, () => Math.Max(ToolbarWidth(), GridWidth()));

            // The indigo "rare kind" tag is outside the theme, so it follows contrast themes here.
            ApplyRareHue();
            HueContrast.Changed += OnContrastChanged;
            Closed += (_, _) => HueContrast.Changed -= OnContrastChanged;
            // No switch-off question here: while the app stays open, the main window shows what
            // is recording. The one question comes when the app closes (MainWindow_Closing).
            _ready          = true;          // elements now realized; handlers may read the log
            // During a read, ReadLog only notes that another is due; that one takes _since as set here.
            _scopeDebounce.Tick += (_, _) => { _scopeDebounce.Stop(); UpdateSince(); ReadLog(); };
            // A click on the slider gives it the keys too: its own mouse handling marks the click
            // handled before it could take the focus.
            ScopeSlider.AddHandler(PreviewMouseLeftButtonDownEvent,
                new System.Windows.Input.MouseButtonEventHandler((_, _) => ScopeSlider.Focus()), handledEventsToo: true);
            _followTimer.Tick   += (_, _) => FollowTick();
            // Nothing keeps watching once the window is gone.
            Closed += (_, _) => { _closed = true; _scopeDebounce.Stop(); StopFollow(); };
            UpdateSince();
            LogPath.Text    = $"Log: {LogFile}";
            BuildNoiseMenu();
            SyncNoiseMenuChecks();
            RefreshFamilySwitches();
            RefreshNoiseLight();
            RefreshLoggingButtons();
            UpdateDnsLogButton();
            ApplySourceGroups();
            LogVersion.Text = $"version {BuildInfo.AppVersion}";
            Activated += (_, _) => { UpdateDnsLogButton(); UpdateProcStartsButton(); };   // may have changed elsewhere
            UpdateProcStartsButton();

            // Every 30 s while Live is shown: note which services run in which process, so a
            // short-lived service host (update scan, time sync) is still named after it ends.
            // Only the service list is read — no log, nothing written. Stops with the window.
            _serviceWatch.Tick += (_, _) =>
                System.Threading.Tasks.Task.Run(() => { try { LiveDropSource.ObserveServices(); } catch { } });
            Closed += (_, _) => _serviceWatch.Stop();

            // Live first. Decided once the window is on screen, because turning auditing on asks
            // with a dialog, and a dialog needs its owner window to be showing.
            ContentRendered += OpenLiveFirst;
        }

        // Auditing on: straight into Live. Off: ask to turn it on right away (one click instead
        // of two); "Cancel" leaves the file view with the note as a way back.
        private void OpenLiveFirst(object? sender, EventArgs e)
        {
            ContentRendered -= OpenLiveFirst;
            if (TryEnterLive()) return;
            LiveHint.Visibility = Visibility.Visible;
            UpdateFollowButton();
            ReadLog();
        }

        // ── Text log switches (what Windows Firewall writes to pfirewall.log, the File view) ──

        private void BtnLogDrops_Click(object s, RoutedEventArgs e) => ToggleWFLogging("droppedconnections");
        private void BtnLogAllow_Click(object s, RoutedEventArgs e) => ToggleWFLogging("allowedconnections");

        // Switching the text log on asks first: Live (the audit) records the same, better, so the
        // text log is mostly for machines where a policy keeps auditing off. Off: no question.
        private void ToggleWFLogging(string setting)
        {
            var (blocked, allowed) = FirewallTextLog.State();
            var on = setting == "droppedconnections" ? blocked == true : allowed == true;

            if (!on && !HueConfirm.Ask(this, "Turn on the firewall's text log?",
                    "Live mode already records " +
                    (setting == "droppedconnections" ? "blocked" : "allowed") +
                    " connections from the Security log: the moment they happen, with the program " +
                    "that tried. The text log is the older record: no program names, and Windows " +
                    "writes it in batches.\n\n" +
                    "It is mainly useful where a policy keeps connection auditing off. Turn it on anyway? " +
                    "It keeps running after this app closes; every close offers to switch it off.",
                    "Turn on"))
                return;

            if (FirewallTextLog.Set(setting, !on) is { } problem)
                ThemedDialog.Info(this, "The text log can't be switched", problem, danger: true);
            RefreshLoggingButtons();
            ReadLog();   // logging change affects what's captured — read again
        }

        private void RefreshLoggingButtons()
        {
            var (blocked, allowed) = FirewallTextLog.State();
            IconText.SetText(BtnLogDrops, blocked == true ? "Drops ✓" : "Drops ✗");
            IconText.SetText(BtnLogAllow, allowed == true ? "Allow ✓" : "Allow ✗");
            BtnLogDrops.Style = (Style)FindResource(blocked == true ? "FilterBtnGood" : "FilterBtn");
            BtnLogAllow.Style = (Style)FindResource(allowed == true ? "FilterBtnGood" : "FilterBtn");
        }

        // One toggle, two sets of controls: Live shows what feeds Live (allowed connections,
        // DNS lookups), File shows the text-log switches. Keeps the toolbar on one line.
        private void ApplySourceGroups()
        {
            foreach (UIElement child in Toolbar.Children)
            {
                if (child is not FrameworkElement fe || fe.Tag is not string group) continue;
                if (group == "live") fe.Visibility = _live ? Visibility.Visible : Visibility.Collapsed;
                if (group == "file") fe.Visibility = _live ? Visibility.Collapsed : Visibility.Visible;
            }
        }

        // ── Scope (mutually exclusive) ────────────────────────────────────────

        // Slider moves: new window, Clear mark released. Debounced so dragging doesn't reload
        // the log (or query the Security log) on every step.
        private void ScopeSlider_ValueChanged(object s, RoutedPropertyChangedEventArgs<double> e)
        {
            var v = (int)Math.Round(e.NewValue);
            _scopeMinutes = v >= 31 ? null : v;
            _clearMark    = null;
            if (ScopeLabel != null) ScopeLabel.Text = _scopeMinutes is int m ? $"{m} min" : "All";
            if (BtnClear != null)   BtnClear.Styled("FilterBtn");
            if (!_ready) return;
            _scopeDebounce.Stop();
            _scopeDebounce.Start();
        }

        // The window is measured back from the moment of loading, so Refresh moves it along;
        // a Clear mark stays where it was set.
        private void UpdateSince() =>
            _since = _clearMark ?? (_scopeMinutes is int m ? DateTime.Now.AddMinutes(-m) : null);
        // A fixed mark, not a window: only entries stamped after the click. Unlike 5/30 min it
        // doesn't move on Refresh; click Clear again to set a new mark. Not stored anywhere.
        private void BtnClear_Click(object s, RoutedEventArgs e)
        {
            _clearMark = DateTime.Now;
            BtnClear.Styled("FilterBtnActive");
            UpdateSince();
            ReadLog();
        }


        // ── Content filters (independent toggles) ────────────────────────────

        private void BtnDropsOnly_Click(object s, RoutedEventArgs e)
        {
            _dropsOnly = !_dropsOnly;
            if (_dropsOnly) _allowsOnly = false;   // mutually exclusive
            RefreshActionFilterStyles();
            ApplyView();
        }

        private void BtnAllowsOnly_Click(object s, RoutedEventArgs e)
        {
            _allowsOnly = !_allowsOnly;
            if (_allowsOnly) _dropsOnly = false;    // mutually exclusive
            RefreshActionFilterStyles();
            ApplyView();
        }

        private void RefreshActionFilterStyles()
        {
            BtnDropsOnly.Style  = _dropsOnly  ? (Style)Resources["FilterBtnWarn"] : (Style)Resources["FilterBtn"];
            BtnAllowsOnly.Style = _allowsOnly ? (Style)Resources["FilterBtnGood"] : (Style)Resources["FilterBtn"];
        }

        // ── Noise filter: traffic-light master + per-category surgical menu ────
        // Green = suppress all (clean) · Yellow = suppress some · Red = suppress none (raw)

        // All on means both families too, so one click always gets back to a clean (green) view.
        private void BtnNoiseMaster_Click(object s, RoutedEventArgs e)
        {
            var allSuppressed = AllNoiseSuppressed();
            foreach (var key in _noise.Keys.ToList()) _noise[key] = !allSuppressed;
            if (!allSuppressed) _noiseV4 = _noiseV6 = true;
            SyncNoiseMenuChecks();
            RefreshNoiseLight();
            ApplyView();
        }

        private bool AllNoiseSuppressed() => _noise.Values.All(v => v) && _noiseV4 && _noiseV6;

        private void NoiseFamily_Toggled(object sender, RoutedEventArgs e)
        {
            if (!_ready) return;   // ignore Checked events fired during InitializeComponent
            _noiseV4 = NoiseIPv4.IsChecked == true;
            _noiseV6 = NoiseIPv6.IsChecked == true;
            RefreshNoiseLight();
            ApplyView();
        }

        // A family this machine has no address of: dimmed, still clickable. "unknown" (no
        // interface up, or unreadable) says nothing, so it isn't dimmed.
        private void RefreshFamilySwitches()
        {
            foreach (var (cb, family, name) in new[]
                     {
                         (NoiseIPv4, System.Net.Sockets.AddressFamily.InterNetwork, "IPv4"),
                         (NoiseIPv6, System.Net.Sockets.AddressFamily.InterNetworkV6, "IPv6"),
                     })
            {
                if (NetworkLocality.FamilyState(family) == "off")
                {
                    cb.SetResourceReference(ForegroundProperty, "Brush.TextMuted");
                    cb.ToolTip = $"{name} is off on this machine: no {name} traffic to filter.";
                }
                else
                {
                    cb.ClearValue(ForegroundProperty);
                    cb.ClearValue(ToolTipProperty);
                }
            }
        }

        // The families the noise filter works on, for the counts line, the export and Copy for
        // AI: "" for both, "IPv4 only" / "IPv6 only", or "no family".
        private string NoiseFamilies() =>
            _noiseV4 && _noiseV6 ? "" : _noiseV4 ? "IPv4 only" : _noiseV6 ? "IPv6 only" : "no family";

        private void NoiseCategory_Toggled(object sender, RoutedEventArgs e)
        {
            if (!_ready) return;   // ignore Checked events fired during InitializeComponent
            if (sender is CheckBox cb && cb.Tag is string cat && _noise.ContainsKey(cat))
            {
                _noise[cat] = cb.IsChecked == true;   // checked = suppress
                RefreshNoiseLight();
                ApplyView();
            }
        }

        // A switch per category, named with its note, in the config's order; the DNS switch
        // stays last. Two categories with one name share its switch.
        private void BuildNoiseMenu()
        {
            var at = NoiseMenuPanel.Children.IndexOf(NoiseDnsByRule);
            foreach (var c in _noiseDefs)
            {
                if (string.IsNullOrEmpty(c.Name) || c.Name == DnsByRuleNoise || _noise.ContainsKey(c.Name)) continue;
                _noise[c.Name] = c.Suppress;

                var label = new TextBlock();
                label.Inlines.Add(new Run(c.Name));
                if (!string.IsNullOrEmpty(c.Note))
                {
                    var note = new Run("  " + c.Note);
                    note.SetResourceReference(TextElement.ForegroundProperty, "Brush.TextMuted");
                    label.Inlines.Add(note);
                }
                var cb = new CheckBox { Content = label, Tag = c.Name, IsChecked = c.Suppress, Margin = new Thickness(0, 2, 0, 2) };
                if (c.LocalBroadcast)
                    cb.ToolTip = "255.255.255.255 and the broadcast address of each network this machine is on. " +
                                 "Any other address ending in .255 is a host and shows.";
                cb.Checked   += NoiseCategory_Toggled;
                cb.Unchecked += NoiseCategory_Toggled;
                NoiseMenuPanel.Children.Insert(at++, cb);
            }
            _noise[DnsByRuleNoise] = true;
        }

        private void SyncNoiseMenuChecks()
        {
            foreach (var child in NoiseMenuPanel.Children)
                if (child is CheckBox cb && cb.Tag is string cat && _noise.ContainsKey(cat))
                    cb.IsChecked = _noise[cat];
            NoiseIPv4.IsChecked = _noiseV4;
            NoiseIPv6.IsChecked = _noiseV6;
        }

        private void RefreshNoiseLight()
        {
            var on  = _noise.Values.Count(v => v);
            var tot = _noise.Count;
            // green = all suppressed · amber = some · red = none (dot and word in the same colour);
            // a family switched off leaves its noise in view, so it counts as "some".
            var color = AllNoiseSuppressed()        ? "Brush.OkText"
                      : on == 0 || !(_noiseV4 || _noiseV6) ? "Brush.ErrorText"
                                                    : "Brush.WarnText";
            NoiseLight.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, color);
            NoiseLabel.SetResourceReference(TextBlock.ForegroundProperty, color);
        }

        private void OnContrastChanged(object? sender, EventArgs e)
        {
            ApplyRareHue();
            // The rows' own colours (rule, resolved name, DNS tint) are looked up from the theme
            // when a row is drawn: rows on screen look them up again now, not at the next read.
            foreach (var row in _gridRows) row.ThemeChanged();
        }

        // Deliberate exception (see LogViewerWindow.xaml): indigo normally, the system's own
        // colours while Windows has a contrast theme on — the same hand-over HueContrast does.
        private void ApplyRareHue()
        {
            if (HueContrast.IsActive)
            {
                Resources["Rare.Text"] = SystemColors.WindowTextBrush;
                Resources["Rare.Soft"] = SystemColors.WindowBrush;
                Resources["Rare.Edge"] = SystemColors.WindowTextBrush;
            }
            else
            {
                Resources["Rare.Text"] = Resources["Rare.Text.Hue"];
                Resources["Rare.Soft"] = Resources["Rare.Soft.Hue"];
                Resources["Rare.Edge"] = Resources["Rare.Edge.Hue"];
            }
        }

        private void BtnNoiseArrow_Click(object s, RoutedEventArgs e)
        {
            if (!NoisePopup.IsOpen) RefreshFamilySwitches();   // adapters come and go
            NoisePopup.IsOpen = !NoisePopup.IsOpen;
        }

        private void BtnRefreshLog_Click(object s, RoutedEventArgs e)
        {
            UpdateSince();   // re-anchor the window (a Clear mark stays put)
            ReadLog();
        }

        // ── Export ────────────────────────────────────────────────────────────

        private void BtnExport_Click(object s, RoutedEventArgs e)
        {
            if (_currentEntries.Count == 0)
            {
                LogCount.Text = "Nothing to export.";
                return;
            }

            var dlg = new SaveFileDialog
            {
                Title      = "Export Log",
                Filter     = "Text file (*.txt)|*.txt|CSV (*.csv)|*.csv",
                FileName   = $"firewall-log-{DateTime.Now:yyyyMMdd-HHmm}.txt",
                DefaultExt = ".txt"
            };

            if (dlg.ShowDialog() != true) return;

            try
            {
                var sb  = new StringBuilder();
                var csv = dlg.FileName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase);
                var sep = csv ? "," : "\t";
                // Every line is composed here, so each cell gets the same guard, then the quoting.
                string Line(params object[] fields) => string.Join(sep, fields.Select(f =>
                {
                    var cell = FormulaGuard(Convert.ToString(f, CultureInfo.InvariantCulture) ?? "");
                    return csv ? "\"" + cell.Replace("\"", "\"\"") + "\"" : cell;
                }));

                sb.AppendLine(Line($"Connection Log Export — {DateTime.Now:yyyy-MM-dd HH:mm} — Firewall Rule Manager {BuildInfo.AppVersion}"));
                var releasedCats = _noise.Where(kv => !kv.Value).Select(kv => kv.Key);
                var noiseDesc    = (_noise.Values.All(v => v) ? "all suppressed"
                                 : _noise.Values.All(v => !v) ? "none suppressed"
                                 : $"released: {string.Join("+", releasedCats)}")
                                 + (NoiseFamilies() is { Length: > 0 } fam ? $", {fam}" : "");
                sb.AppendLine(Line($"Filters: scope={(_since.HasValue ? $"from {_since:HH:mm}" : "All")}  drops={_dropsOnly}  allows={_allowsOnly}  noise=[{noiseDesc}]"));
                if (_talkerFilter != null) sb.AppendLine(Line($"Talker: {TalkerFilterLabel()}"));
                sb.AppendLine(Line("Cells starting with = + - @, TAB or CR are prefixed with ' (spreadsheet formula guard)."));
                sb.AppendLine();

                // Talkers first: the short list of decisions, then the rows behind it.
                sb.AppendLine(Line("TALKERS (ranked by outgoing drops; quiet = seen earlier, not in this scope)"));
                sb.AppendLine(Line("Talker", "State", "Last seen", "Origin", "Out drops", "In drops", "Allows", "Destinations", "Top destinations", "Ports", "Rule"));
                foreach (var t in _talkers)
                    sb.AppendLine(Line(t.Key, t.IsQuiet ? "quiet" : "active", t.LastSeenText, t.Origin,
                        t.OutDrops, t.InDrops, t.Allows, t.Destinations, t.TopDest, t.Ports, t.RuleWords(n => n)));
                sb.AppendLine();
                sb.AppendLine(Line("ENTRIES"));
                sb.AppendLine(Line("Time", "Action", "Proto", "Src IP", "Dst IP", "Resolved", "Src Port", "Dst Port", "Direction", "Program", "Warning"));

                foreach (var e2 in _currentEntries)
                    sb.AppendLine(Line(e2.Time, e2.Action, e2.Protocol,
                        e2.SrcIP, e2.DstIP, e2.Resolved, e2.SrcPort, e2.DstPort, e2.Direction,
                        string.IsNullOrEmpty(e2.Services) ? e2.Program : $"{e2.Program} ({e2.Services})",
                        e2.DnsWarnWords));

                File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
                LogCount.Text = $"Exported {_currentEntries.Count} entries → {Path.GetFileName(dlg.FileName)}";
            }
            catch (Exception ex)
            {
                LogCount.Text = $"Export error: {ex.Message}";
            }
        }

        // Spreadsheets run a cell starting with = + - @ (TAB, CR) as a formula, also on a text
        // import; a leading ' makes it text. One that already has 's before it gets one more, so
        // taking one off gives any cell back exactly. "-" alone is the file log's empty value.
        private static string FormulaGuard(string cell) =>
            cell != "-" && Regex.IsMatch(cell, @"^'*[=+\-@\t\r]") ? "'" + cell : cell;

        // ── Log loading ───────────────────────────────────────────────────────

        // Source: the log file (pfirewall.log, written late by Windows, no program) or Live
        // (Security log events 5157 blocked / 5156 allowed, written at once, names the program).
        private bool _live              = false;
        private readonly System.Windows.Threading.DispatcherTimer _serviceWatch =
            new() { Interval = TimeSpan.FromSeconds(30) };

        // ── Reading, then following ──────────────────────────────────────────
        // A full read (Refresh, scope, source, recording switches, Clear) runs off the window's
        // thread and judges every row afresh: rules, DNS cache, networks. The view filters
        // (Drops/Allows only, noise, talker) then work on what was read, at once. Following adds
        // what Windows records afterwards, without reading again.

        private const int MaxRows = LiveDropSource.MaxEntries;   // newest kept; the oldest drop off

        // Clock changes as last read, and when (background work only, under _workGate).
        private List<ClockChanges.Change> _clockChanges = new();
        // Measured on the tick count, not the clock: a clock set back mustn't stop the reading.
        private long _clockChangesTick;

        private List<LogEntry> _readEntries = new();   // read, enriched and in scope, newest first
        private bool      _reading;
        private bool      _readAgain;                  // asked for while reading: once more after
        private int       _readGen;                    // a newer read makes older results stale
        private DateTime? _readAt;                     // when the last full read finished
        private DateTime? _readStart;                  // when it began: following shows every line after it
        private bool      _capped;                     // the row cap left older rows out
        private bool?     _allowsRecorded;             // Live: allowed connections recorded, as read
        private bool      _closed;

        // Reading, following and the Lookups tab share the caches below: one at a time.
        private readonly object _workGate = new();

        private sealed class ReadResult
        {
            public List<LogEntry> Entries = new();
            public List<FirewallReloads.Reload> Reloads = new();
            public List<NetworkChanges.Change> Networks = new();
            public List<ClockChanges.Change> Clocks = new();
            public string? Problem;                    // instead of rows: why there are none
            public bool Capped;
            public bool? AllowsRecorded;
            public long LastRecordId;
            public LogCursor? LiveCursor;
            public long FilePos;
            public byte[] FileHead = Array.Empty<byte>();
        }

        private async void ReadLog()
        {
            if (LogGrid == null || _closed) return;   // not yet realized (early event during init)
            if (_reading) { _readAgain = true; return; }
            _reading = true;
            var gen = ++_readGen;
            StopFollow();
            SetReadControls(false);
            LogCount.Text = "Reading…";
            if (LookupsTab.IsSelected) LoadLookups();   // same scope and Refresh; its own source

            var live = _live;
            var since = _since;
            // Subscribed before the read, so nothing written in between is missed; what both
            // see is told apart by its event number.
            if (live && _follow) StartWatcher(gen);
            var ok = false;
            var readStart = DateTime.Now;
            try
            {
                var r = await Task.Run(() => { lock (_workGate) return ReadAll(live, since); });
                if (_closed) return;
                if (r.Problem != null)
                {
                    _readEntries = new();
                    _scopedEntries = new();
                    _currentEntries = new();
                    _reloads = new();
                    _networks = new();
                    _clocks = new();
                    _gridRows = new();
                    LogGrid.ItemsSource = _gridRows;
                    LogCount.Text = r.Problem;
                }
                else
                {
                    _readEntries    = r.Entries;
                    _reloads        = r.Reloads;
                    _networks       = r.Networks;
                    _clocks         = r.Clocks;
                    _capped         = r.Capped;
                    _allowsRecorded = r.AllowsRecorded;
                    _lastRecordId   = r.LastRecordId;
                    _liveCursor     = r.LiveCursor;
                    _filePos        = r.FilePos;
                    _fileHead       = r.FileHead;
                    _followProblem  = null;
                    _readAt         = DateTime.Now;
                    _readStart      = readStart;
                    ok = true;
                    _reading = false;                    // the counts line may show again
                    ApplyView();
                }
            }
            catch (UnauthorizedAccessException)
            {
                LogCount.Text = "Reading the Security log needs administrator rights.";
            }
            catch (Exception ex)
            {
                LogCount.Text = $"Error: {ex.Message}";
            }
            finally
            {
                _reading = false;
                if (!_closed) SetReadControls(true);
            }
            if (_closed) { StopFollow(); return; }
            if (ok && _follow) StartFollow(gen); else StopFollow();
            if (_readAgain) { _readAgain = false; ReadLog(); }
        }

        // Controls that start a full read wait while one runs. Not the scope slider: it keeps the
        // keyboard focus, and its newest value is read once the running read ends (_readAgain).
        private void SetReadControls(bool enabled)
        {
            foreach (var c in new Control[] { BtnRefreshLog, BtnSourceFile, BtnSourceLive, BtnLiveHint,
                                              BtnClear, BtnLiveAllows, BtnLogDrops, BtnLogAllow })
                c.IsEnabled = enabled;
        }

        // Off the window's thread: everything a row is judged by, then the rows.
        private ReadResult ReadAll(bool live, DateTime? since)
        {
            var r = new ReadResult();
            if (!live && !File.Exists(LogFile))
            {
                r.Problem = "Log file not found — enable logging first.";
                return r;
            }

            Starts(fresh: true);            // process starts: rows, lookups and "started just before"
            // With Windows' DNS log on, the lookup that returned an address names it; a cache
            // name has no time or program and would pass for that fact.
            _dnsCacheRead = DnsClientLog.IsOn() != true;
            _dnsMap = _dnsCacheRead ? BuildDnsCacheMap() : new();
            BuildLookupJoin(since);         // Windows' DNS log: lookups by the address they returned
            NetworkLocality.Refresh();      // this machine's networks, for the Network column
            _localityCache.Clear();
            LoadAllowRules();               // CUSTOM_* allow and block rules: rule names and the DNS tripwire
            _orgTags = ConfigService.Effective().OrgTags;

            List<LogEntry> raw;
            if (live)
            {
                r.LiveCursor = new LogCursor("Security");   // before the read: reading on starts here
                raw = ToEntries(LiveDropSource.Read(since, out r.LastRecordId));
                r.Capped = LiveDropSource.LastReadTruncated;
                r.AllowsRecorded = LiveDropSource.AllowAuditingOn();
                ApplyProcessStarts(raw, fresh: false);  // command lines, and services of ended hosts
                NameFilters(raw);                       // which filter decided, where its ID still holds
            }
            else raw = ReadFileEntries(since, r);

            r.Entries = raw
                .Select(Enrich)
                .Where(e => !since.HasValue || e.Ts >= since.Value)
                .OrderByDescending(e => e.Time)
                .ToList();
            // Only reloads, network and clock changes among the connections read: older ones say
            // nothing about them.
            var oldest = raw.Where(e => e.Ts != default).Select(e => e.Ts).DefaultIfEmpty(DateTime.Now).Min();
            // Each log's newest event before it is read: anything written meanwhile reads as new.
            _reloadsLogId  = LogCursor.NewestId(FirewallLogName);
            _networkLogId  = LogCursor.NewestId(NetworkLogName);
            _securityLogId = LogCursor.NewestId("Security");
            _markersSince  = since;
            _reloadsRead   = FirewallReloads.Read(since);
            _networksRead  = NetworkChanges.Read(since);
            r.Reloads  = _reloadsRead.Where(x => x.Time >= oldest).ToList();
            r.Networks = _networksRead.Where(x => x.Time >= oldest).ToList();
            _clockChanges   = ClockChanges.Read(since);
            _clockChangesTick = Environment.TickCount64;
            r.Clocks   = _clockChanges.Where(x => x.Time >= oldest).ToList();
            return r;
        }

        // The logs FirewallReloads and NetworkChanges read, asked only whether they grew.
        private const string FirewallLogName = FirewallReloads.LogName;
        private const string NetworkLogName  = NetworkChanges.LogName;

        // Marker lines as last read, and each log's newest event then (background work only,
        // under _workGate). Following reads a log again only once something was written to it.
        private List<FirewallReloads.Reload> _reloadsRead = new();
        private List<NetworkChanges.Change> _networksRead = new();
        private long _reloadsLogId = -1, _networkLogId = -1, _securityLogId = -1;
        private DateTime? _markersSince;

        // Whether a log was written to since its newest event was noted (an unreadable log counts
        // as written: its reader says so itself), and the new mark.
        private static bool Grew(string log, ref long mark)
        {
            var now = LogCursor.NewestId(log);
            if (now >= 0 && now == mark) return false;
            mark = now;
            return true;
        }

        // ── Following ─────────────────────────────────────────────────────────

        private bool _follow;                          // on by default in Live (SetSource)
        private readonly System.Windows.Threading.DispatcherTimer _followTimer =
            new() { Interval = TimeSpan.FromSeconds(2) };
        private bool _followBusy;
        private string? _followProblem;
        // Live: Windows pushes each new event (EventLogWatcher); if it can't, or the subscription
        // breaks, the cursor reads on from the full read every few seconds instead.
        private EventLogWatcher? _watcher;
        private volatile bool _watchBroken;
        private bool _catchUp;                         // following was off: read on from the cursor once
        private readonly ConcurrentQueue<(int Gen, LiveDropSource.LiveEvent Ev)> _pushed = new();
        private LogCursor? _liveCursor;
        private long _lastRecordId;                    // newest connection event in view
        // File: read on from the last full line; another file (shrunk, or rotated to .old) is
        // told by its size and first bytes.
        private long _filePos;
        private byte[] _fileHead = Array.Empty<byte>();

        private void StartFollow(int gen)
        {
            if (_live && _watcher == null && !_watchBroken)
            {
                StartWatcher(gen);
                _catchUp = true;   // subscribed after the read: what came in between is read on once
            }
            _followTimer.Start();
        }

        private void StopFollow()
        {
            _followTimer.Stop();
            DisposeWatcher();
            while (_pushed.TryDequeue(out _)) { }
        }

        private void StartWatcher(int gen)
        {
            DisposeWatcher();
            _watchBroken = false;
            _watcher = LiveDropSource.Watch(ev => _pushed.Enqueue((gen, ev)), () => _watchBroken = true);
            if (_watcher == null) _watchBroken = true;
        }

        private void DisposeWatcher()
        {
            var w = _watcher;
            _watcher = null;
            if (w == null) return;
            try { w.Enabled = false; w.Dispose(); } catch { /* already broken */ }
        }

        private void BtnFollow_Click(object s, RoutedEventArgs e)
        {
            _follow = !_follow;
            UpdateFollowButton();
            if (_follow && !_reading && _readAt != null) StartFollow(_readGen);
            else if (!_follow) StopFollow();
            UpdateCounts();
        }

        private void UpdateFollowButton()
        {
            BtnFollow.Styled(_follow ? "FilterBtnActive" : "FilterBtn");
            IconText.SetText(BtnFollow, _follow ? "Follow ✓" : "Follow ✗");
        }

        private sealed class FollowBatch
        {
            public List<LogEntry> Entries = new();
            public List<FirewallReloads.Reload> Reloads = new();
            public List<NetworkChanges.Change> Networks = new();
            public List<ClockChanges.Change> Clocks = new();
            public List<(LogEntry Entry, FilterLabel Label)> Relabels = new();
        }

        private async void FollowTick()
        {
            if (!_follow || _reading || _followBusy || _closed || _readAt == null) return;
            if (_watchBroken && _watcher != null) DisposeWatcher();   // read on from the cursor now

            var gen = _readGen;
            var live = _live;
            var since = _since;
            var shown = _readEntries;                          // not changed in place, only replaced
            var pushed = new List<LiveDropSource.LiveEvent>();
            while (_pushed.TryDequeue(out var p)) if (p.Gen == gen) pushed.Add(p.Ev);
            // With no new connection there may still be a reload, network or clock line to show.
            var readOn = !live || _watcher == null || _catchUp;

            _followBusy = true;
            try
            {
                var batch = await Task.Run(() => { lock (_workGate) return gen == _readGen ? ReadNew(live, since, pushed, readOn, shown) : null; });
                if (batch == null || gen != _readGen || _reading || _closed) return;
                _catchUp = false;                              // only once it was read on: a failed read tries again
                var hadProblem = _followProblem != null;
                _followProblem = null;
                if (!Merge(batch) && hadProblem) UpdateCounts();
            }
            catch (Exception ex)
            {
                _followProblem = ex.Message;
                UpdateCounts();
            }
            finally { _followBusy = false; }
        }

        // Off the window's thread: what was written since, judged like the rows already read.
        private FollowBatch ReadNew(bool live, DateTime? since, List<LiveDropSource.LiveEvent> pushed, bool readOn,
                                    List<LogEntry> shown)
        {
            var b = new FollowBatch();
            var raw = new List<LogEntry>();
            if (live)
            {
                var events = pushed.Count > 0 ? LiveDropSource.NameServices(pushed) : new List<LiveDropSource.LiveEvent>();
                if (readOn && _liveCursor != null) events.AddRange(LiveDropSource.ReadOn(_liveCursor));
                var fresh = events.Where(ev => ev.RecordId > _lastRecordId)
                                  .GroupBy(ev => ev.RecordId).Select(g => g.First())
                                  .OrderByDescending(ev => ev.RecordId).Take(MaxRows).ToList();
                if (fresh.Count > 0)
                {
                    _lastRecordId = fresh[0].RecordId;
                    raw = ToEntries(fresh);
                    ApplyProcessStarts(raw, fresh: false);
                    NameFilters(raw);
                }
            }
            else raw = ReadFileOnward();
            // After the new rows: their unknown IDs may just have refreshed the filter list.
            if (live) b.Relabels = RelabelFilters(shown);

            if (raw.Count > 0)
            {
                JoinNewLookups(since);
                _orgTags = ConfigService.Effective().OrgTags;
                b.Entries = raw
                    .Select(Enrich)
                    .Where(e => !since.HasValue || e.Ts >= since.Value)
                    .OrderByDescending(e => e.Time)
                    .Take(MaxRows)
                    .ToList();
            }
            // The lines between the connections can come without one: each tick asks every log
            // whether it grew, and reads only the one that did.
            if (since != _markersSince)
            {
                (_reloadsLogId, _networkLogId, _markersSince) = (-1, -1, since);
            }
            if (Grew(FirewallLogName, ref _reloadsLogId)) _reloadsRead  = FirewallReloads.Read(since);
            if (Grew(NetworkLogName,  ref _networkLogId)) _networksRead = NetworkChanges.Read(since);
            b.Reloads  = _reloadsRead;
            b.Networks = _networksRead;
            // Clock changes are in the Security log, which can be large: every half minute at
            // most, and only when it grew, what was written since the last read (a minute's
            // margin), added to what was read.
            var sinceRead = Environment.TickCount64 - _clockChangesTick;
            if (sinceRead > 30_000 && Grew("Security", ref _securityLogId))
            {
                var from = DateTime.Now.AddMilliseconds(-sinceRead).AddMinutes(-1);
                var known = _clockChanges.Select(c => c.Time).ToHashSet();
                _clockChanges = ClockChanges.Read(from).Where(c => !known.Contains(c.Time))
                    .Concat(_clockChanges)
                    .OrderByDescending(c => c.Time).ToList();
                _clockChangesTick = Environment.TickCount64;
            }
            b.Clocks = _clockChanges;
            return b;
        }

        // New rows join the ones read; the newest MaxRows stay. The grid takes them in place, so
        // a selected row stays selected and the view stays where it was. New marker lines, or
        // rows that regroup them, build the grid again from memory. False: nothing changed.
        private bool Merge(FollowBatch b)
        {
            foreach (var (e, label) in b.Relabels) e.Filter = label;   // the grid shows it at once
            var dropped = new List<LogEntry>();
            if (b.Entries.Count > 0)
            {
                var all = b.Entries.Concat(_readEntries).OrderByDescending(e => e.Time).ToList();
                if (all.Count > MaxRows)
                {
                    dropped = all.GetRange(MaxRows, all.Count - MaxRows);
                    all.RemoveRange(MaxRows, dropped.Count);
                    _capped = true;
                }
                _readEntries = all;
            }

            // Lines among the rows, as the full read shows them, and every line since that read
            // began, rows or not: on a quiet view, a reload or network drop is the news.
            var oldest = _readEntries.Where(e => e.Ts != default).Select(e => e.Ts).DefaultIfEmpty(DateTime.Now).Min();
            if (_readStart is { } began && began < oldest) oldest = began;
            var reloads  = b.Reloads.Where(r => r.Time >= oldest).ToList();
            var networks = b.Networks.Where(n => n.Time >= oldest).ToList();
            var clocks   = b.Clocks.Where(c => c.Time >= oldest).ToList();
            var markersChanged = !reloads.SequenceEqual(_reloads) || !networks.SequenceEqual(_networks) || !clocks.SequenceEqual(_clocks);
            _reloads  = reloads;
            _networks = networks;
            _clocks   = clocks;

            if (b.Entries.Count == 0)
            {
                if (!markersChanged) return false;
                ShowScoped(keepScroll: true);
                return true;
            }

            _scopedEntries = _readEntries.Where(InView).ToList();
            if (markersChanged || (_talkerFilter != null && !_scopedEntries.Any(e => TalkerKey(e) == _talkerFilter)))
            {
                ShowScoped(keepScroll: true);                  // markers or the talker filter changed
                return true;
            }
            var current = _talkerFilter == null
                ? _scopedEntries
                : _scopedEntries.Where(e => TalkerKey(e) == _talkerFilter).ToList();
            // A row that lands between network changes shown as one line splits that line (and a
            // row that drops off can join two): the marker lines are grouped again.
            if (!RunSizes(current).SequenceEqual(RunSizes(_currentEntries)))
            {
                ShowScoped(keepScroll: true);
                return true;
            }
            try
            {
                RebuildTalkers();
                _currentEntries = current;
                var shown = new HashSet<LogEntry>(_currentEntries);
                foreach (var e in dropped) _gridRows.Remove(e);
                var i = 0;
                foreach (var e in b.Entries.Where(shown.Contains).OrderByDescending(e => e.Ts))
                {
                    while (i < _gridRows.Count && _gridRows[i].Ts > e.Ts) i++;
                    _gridRows.Insert(i++, e);
                }
                LoadVerdicts();
                UpdateCounts();
            }
            catch (Exception ex)
            {
                LogCount.Text = $"Error: {ex.Message}";
            }
            return true;
        }

        // How the network changes fall into lines for these rows: the size of each run, newest
        // first. The same sizes over the same changes are the same lines.
        private List<int> RunSizes(List<LogEntry> rows) =>
            _networks.Count < 2 ? new List<int>() : NetworkRuns(rows, _networks).Select(r => r.Count).ToList();

        // ── Viewing: filters on what was read ─────────────────────────────────

        private bool InView(LogEntry e) =>
            (!_dropsOnly  || e.Action == "DROP") &&
            (!_allowsOnly || e.Action == "ALLOW") &&
            !IsSuppressedNoise(e);

        private void ApplyView()
        {
            if (LogGrid == null) return;
            _scopedEntries = _readEntries.Where(InView).ToList();
            ShowScoped();
        }

        // Firewall reloads, network changes and clock changes in scope, newest first: shown between
        // the rows, never counted as connections. Only reloads say anything about filter IDs.
        private List<FirewallReloads.Reload> _reloads = new();
        private List<NetworkChanges.Change> _networks = new();
        private List<ClockChanges.Change> _clocks = new();

        // One line between the connections: in the grid (Shown, Tip) and in Copy for AI (Words).
        private sealed record Marker(DateTime Time, string Action, string Shown, string Tip, string Words, string Rule);

        private const string ReloadTip =
            "The firewall dropped and re-read all its rules here. Windows renumbers the filters behind the " +
            "rules at that moment, so a filter ID from before this row means something else after it.";

        private const int MaxRunTimes = 20;   // times listed in a collapsed network line's tooltip

        // The lines for these rows, newest first. Network changes with no row between them (a
        // spotty Wi-Fi) collapse into one line.
        private List<Marker> Markers(List<LogEntry> rows)
        {
            var list = new List<Marker>();
            foreach (var r in _reloads)
                list.Add(new Marker(r.Time, "RELOAD", "⟳ rules reloaded", ReloadTip,
                    FirewallReloads.Text(r) + (_live ? "; filter IDs above this line are not those below it" : ""),
                    r.AfterGroupPolicy ? "Group Policy change" : ""));
            foreach (var run in NetworkRuns(rows, _networks))
            {
                var last = run[0];
                if (run.Count == 1)
                {
                    var text = NetworkChanges.Text(last.Connected);
                    list.Add(new Marker(last.Time, "NETWORK", "⇄ " + text,
                        $"The {text} here (Windows' network list log).", text, ""));
                    continue;
                }
                var words = $"network changed {run.Count}× ({run[^1].Time:HH:mm:ss}–{last.Time:HH:mm:ss}), " +
                            $"last: {(last.Connected ? "connected" : "disconnected")}";
                var times = string.Join("\n", run.Take(MaxRunTimes).Select(c => $"{c.Time:HH:mm:ss}  {(c.Connected ? "connected" : "disconnected")}"))
                          + (run.Count > MaxRunTimes ? $"\n+{run.Count - MaxRunTimes} more" : "");
                list.Add(new Marker(last.Time, "NETWORK", "⇄ " + words,
                    $"The network changed {run.Count} times here, with no connection in between (Windows' network list log):\n{times}",
                    words, ""));
            }
            foreach (var c in _clocks)
                list.Add(new Marker(c.Time, "CLOCK", "⏱ " + ClockChanges.Text(c),
                    $"The system clock was set here, from {c.Before:HH:mm:ss} to {c.After:HH:mm:ss} (Security log, event 4616).",
                    ClockChanges.Text(c), ""));
            return list.OrderByDescending(m => m.Time).ToList();
        }

        // Network changes in runs, each newest first: a run ends where a row lies between two
        // changes. A row with the same time as a change is shown above it, as in the grid.
        private static List<List<NetworkChanges.Change>> NetworkRuns(List<LogEntry> rows, List<NetworkChanges.Change> changes)
        {
            var times = rows.Select(e => e.Ts).OrderByDescending(t => t).ToList();
            var runs = new List<List<NetworkChanges.Change>>();
            int above = 0, runAbove = -1;
            foreach (var c in changes.OrderByDescending(c => c.Time))
            {
                while (above < times.Count && times[above] >= c.Time) above++;
                if (above != runAbove) { runs.Add(new()); runAbove = above; }
                runs[^1].Add(c);
            }
            return runs;
        }

        private IEnumerable<LogEntry> WithMarkerRows(List<LogEntry> entries) =>
            entries.Concat(Markers(entries).Select(m => new LogEntry
            {
                Time      = m.Time.ToString("yyyy-MM-dd HH:mm:ss"),
                Action    = m.Action,
                Resolved  = m.Shown,
                RuleName  = m.Rule,
                IsMarker  = true,
                // The column may cut the line short ("…"): the tooltip starts with it in full.
                MarkerTip = $"{m.Shown}\n\n{m.Tip}",
                Ts        = m.Time,
            })).OrderByDescending(e => e.Ts);

        // A filter's label: as shown (Name, Tip), the stored name (Plain, for copy and sort) and
        // Copy for AI's words. Unresolved: no live filter had the ID, or the engine couldn't be
        // read, when it was labelled; following asks again (RelabelFilters), since a filter can be
        // back under the same ID a moment later (measured around network changes).
        internal sealed record FilterLabel(string Name, string Plain, string Tip, string Copy, bool Unresolved);

        // The filter behind each connection, by the ID in its event. IDs hold only until the
        // firewall reloads its rules or the machine restarts, when Windows renumbers them, so
        // connections from before that are marked instead of being given today's filter of
        // that number. Off the window's thread: the rows aren't shown yet.
        private void NameFilters(List<LogEntry> entries)
        {
            foreach (var (e, label) in FilterLabels(entries, fresh: true)) e.Filter = label;
        }

        // Following: the shown rows whose filter wasn't found, asked again. Off the window's
        // thread; only labels that change come back, applied on the window's thread (Merge).
        private List<(LogEntry Entry, FilterLabel Label)> RelabelFilters(List<LogEntry> rows)
        {
            var open = rows.Where(e => e.FilterUnresolved).ToList();
            return open.Count == 0 ? new()
                : FilterLabels(open, fresh: false).Where(x => x.Label != x.Entry.Filter).ToList();
        }

        private List<(LogEntry Entry, FilterLabel Label)> FilterLabels(List<LogEntry> entries, bool fresh)
        {
            var rows = entries.Where(e => e.FilterId > 0).ToList();
            if (rows.Count == 0) return new();
            var bootUtc = ProcessStartLog.BootUtc();
            var reload = LatestReload();
            // The engine is read again after a reload or half a minute (following asks every few
            // seconds, and a machine can hold tens of thousands of filters), and after five
            // seconds when a new row has an ID it doesn't list: the filters changed meanwhile.
            var age = DateTime.Now - _filterMapAt;
            var unknownId = fresh && _filterMap != null && rows.Any(e => !_filterMap.ContainsKey((ulong)e.FilterId));
            // An engine that couldn't be read is asked again at the same pace, not on every tick.
            if ((_filterMap == null && (_filterMapAt == default || age > TimeSpan.FromSeconds(30)))
                || _filterMapReload != reload || age > TimeSpan.FromSeconds(30)
                || (unknownId && age > TimeSpan.FromSeconds(5)))
            {
                var (read, readProblem) = WfpFilters.Read();
                _filterMap = read?.GroupBy(f => f.Id).ToDictionary(g => g.Key, g => g.First());
                _filterProblem = readProblem;
                _filterMapAt = DateTime.Now;
                _filterMapReload = reload;
            }
            var filters = _filterMap;
            var problem = _filterProblem;
            var byId = filters ?? new();
            // Compared in UTC: in local time a clock change in between would move the line by an hour.
            var reloadUtc = reload?.ToUniversalTime();
            var sinceUtc = reloadUtc > bootUtc ? reloadUtc.Value : bootUtc;
            var cause = reloadUtc > bootUtc ? $"the firewall reloaded its rules at {reload:HH:mm:ss}"
                                            : $"the machine started at {bootUtc.ToLocalTime():HH:mm:ss}";

            FilterLabel LabelOf(LogEntry e)
            {
                var id = (ulong)e.FilterId;
                if (filters == null)
                    return new($"#{id}", $"#{id}",
                        $"Filter {id}. The filtering engine couldn't be read ({problem}), so its name is unknown.",
                        $"filter {id}", Unresolved: true);
                if (e.Ts.ToUniversalTime() < sinceUtc)
                    return new($"#{id} (renumbered)", $"#{id} (renumbered)",
                        $"Filter {id}. Since this connection, {cause} and Windows renumbered its filters: " +
                        $"today's filter {id} may be a different one, so it isn't named.",
                        $"filter {id} (renumbered since, not named)", Unresolved: false);
                if (byId.TryGetValue(id, out var f))
                {
                    var name = f.Name.Length > 0 ? f.Name : "(no name)";
                    return new(NameShown(name), name,
                        $"Filter {f.Describe}.\nThe filter that decided this connection, as Windows lists it now." +
                        (NameFindings(name) is { } found ? "\n\n" + found : ""),
                        $"filter {id} \"{ForAi(name)}\" ({(f.IsHard ? "HARD " : "")}{(f.IsPermit ? "permit" : f.IsBlock ? "block" : "other")}, " +
                        $"provider {(f.Provider.Length > 0 ? f.Provider : "none")}, sublayer {f.SubLayerName})",
                        Unresolved: false);
                }
                return new($"#{id} (gone)", $"#{id} (gone)",
                    $"No live filter has ID {id} now: it was removed or replaced since this connection.",
                    $"filter {id} (no live filter with this ID now)", Unresolved: true);
            }
            return rows.Select(e => (e, LabelOf(e))).ToList();
        }

        // The firewall's latest reload, read again only once its log was written to.
        private DateTime? _latestReload;
        private long _latestReloadLogId = -2;

        private DateTime? LatestReload()
        {
            if (Grew(FirewallLogName, ref _latestReloadLogId))
                _latestReload = FirewallReloads.Read(null).Select(r => (DateTime?)r.Time).FirstOrDefault();
            return _latestReload;
        }

        private Dictionary<ulong, WfpFilters.Filter>? _filterMap;
        private string? _filterProblem;
        private DateTime _filterMapAt;
        private DateTime? _filterMapReload;

        // Everything in scope, before the talker filter: the Talkers tab summarises this.
        private List<LogEntry> _scopedEntries = new();
        private string? _talkerFilter;             // Id (TalkerKey) of the one talker the Log tab shows, or null

        // The rows the Log grid shows, markers included. Following inserts into it in place.
        private ObservableCollection<LogEntry> _gridRows = new();

        // Talker summary from the scoped list, then the Log grid (filtered to one talker if set)
        // and the counts line. Cheap: no log reading, so switching talkers is instant.
        // keepScroll: following, so the grid stays where the user is reading.
        private void ShowScoped(bool keepScroll = false)
        {
            try
            {
                RebuildTalkers();

                if (_talkerFilter != null && !_scopedEntries.Any(e => TalkerKey(e) == _talkerFilter))
                    _talkerFilter = null;   // that talker went quiet in this scope
                _currentEntries = _talkerFilter == null
                    ? _scopedEntries
                    : _scopedEntries.Where(e => TalkerKey(e) == _talkerFilter).ToList();
                BtnTalkerFilter.Visibility = _talkerFilter == null ? Visibility.Collapsed : Visibility.Visible;
                if (_talkerFilter != null) BtnTalkerFilter.Content = $"✕  {NameShown(TalkerFilterLabel())}";

                _gridRows = new ObservableCollection<LogEntry>(WithMarkerRows(_currentEntries));
                SetRows(LogGrid, _gridRows, keepScroll);
                LoadVerdicts();
                UpdateCounts();
            }
            catch (Exception ex)
            {
                LogCount.Text = $"Error: {ex.Message}";
            }
        }

        // New rows for a grid, keeping the user's column sort, and with keepScroll how far down
        // it was scrolled: replacing the rows otherwise resets both.
        private static void SetRows(DataGrid grid, System.Collections.IEnumerable rows, bool keepScroll)
        {
            var sorts = grid.Items.SortDescriptions.ToList();
            var directions = grid.Columns.Select(c => c.SortDirection).ToList();
            var scroller = keepScroll ? FindScrollViewer(grid) : null;
            var (down, across) = (scroller?.VerticalOffset ?? 0, scroller?.HorizontalOffset ?? 0);

            grid.ItemsSource = rows;

            if (sorts.Count > 0)
                using (grid.Items.DeferRefresh())
                {
                    grid.Items.SortDescriptions.Clear();
                    foreach (var d in sorts) grid.Items.SortDescriptions.Add(d);
                }
            for (var i = 0; i < grid.Columns.Count && i < directions.Count; i++)
                grid.Columns[i].SortDirection = directions[i];
            if (scroller != null && (down > 0 || across > 0))
                grid.Dispatcher.InvokeAsync(() =>
                {
                    scroller.ScrollToVerticalOffset(down);
                    scroller.ScrollToHorizontalOffset(across);
                }, System.Windows.Threading.DispatcherPriority.Loaded);
        }

        private static ScrollViewer? FindScrollViewer(DependencyObject parent)
        {
            for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is ScrollViewer sv) return sv;
                if (FindScrollViewer(child) is { } found) return found;
            }
            return null;
        }

        private void UpdateCounts()
        {
            if (_reading) return;   // "Reading…" stays until the read is in
            var filters = new List<string>();
            if (_live)              filters.Add(_allowsRecorded == true ? "live, blocked + allowed" : "live, blocked only");
            if (_capped)            filters.Add($"newest {MaxRows:N0} only: older ones left out, narrow the scope");
            if (_clearMark.HasValue)       filters.Add($"new since {_clearMark.Value:HH:mm:ss}");
            else if (_follow)              filters.Add(_since is { } from ? $"since {from:HH:mm}" : "all");   // rows keep arriving
            else if (_scopeMinutes is int sm) filters.Add($"last {sm} min");
            if (_readAt is { } at)  filters.Add($"read {at:HH:mm:ss}");
            if (_follow)            filters.Add(_live && _watcher == null
                                        ? $"following (read on every {_followTimer.Interval.TotalSeconds:0} s)"
                                        : "following");
            if (_dropsOnly)         filters.Add("DROPs only");
            if (_allowsOnly)        filters.Add("ALLOWs only");
            var released = _noise.Where(kv => !kv.Value).Select(kv => kv.Key).ToList();
            if (released.Count > 0) filters.Add($"noise: {string.Join("+", released)}");
            if (_noise.Values.Any(v => v) && NoiseFamilies() is { Length: > 0 } families)
                filters.Add(families == "no family" ? "noise hidden: none (IPv4 and IPv6 off)" : $"noise hidden: {families}");
            if (_talkerFilter != null) filters.Add($"talker: {NameShown(TalkerFilterLabel())}");
            var label = filters.Count > 0 ? $" — {string.Join(", ", filters)}" : "";

            var drops  = _currentEntries.Count(e => e.Action == "DROP");
            var allows = _currentEntries.Count(e => e.Action == "ALLOW");
            var rules         = _allowRules.Concat(_blockRules).ToList();
            var enabledRules  = rules.Count(r => r.Enabled);
            var disabledRules = rules.Count(r => !r.Enabled);
            var unmatchable   = rules.Count(r => r.Unmatchable);
            var allowMatched  = _currentEntries.Count(e => !string.IsNullOrEmpty(e.RuleName) && !e.IsWouldAllow);
            var wouldMatched  = _currentEntries.Count(e => e.IsWouldAllow && e.StillBlockedBy.Length == 0);
            LogCount.Text = $"{drops} DROPs / {allows} ALLOWs / {_currentEntries.Count} entries{label}"
                          + $"  ·  rules: {enabledRules} on / {disabledRules} off"
                          + (unmatchable > 0 ? $" ({unmatchable} of your rules can't be matched: a keyword, IPv6-only or /0 scope)" : "")
                          + $"  ·  matched: {allowMatched} allow / {wouldMatched} would-allow"
                          + (_dnsCacheRead && _dnsCacheMissing != null ? $" · {_dnsCacheMissing}" : "")
                          + (_followProblem != null ? $" · reading on failed: {_followProblem}" : "");

            // Updated with the counts: it follows the same rules the red flags were judged by.
            var dns = DnsRuleState();
            DnsBannerText.Text    = dns != null ? "ⓘ  " + dns : "";
            DnsBanner.Visibility  = dns != null ? Visibility.Visible : Visibility.Collapsed;
        }

        // ── Talkers ────────────────────────────────────────────────────────────

        public sealed record TalkerRow
        {
            public string Id           { get; init; } = "";   // which talker it is (TalkerKey); never shown
            public string Program      { get; init; } = "";   // full path; "" in File mode
            public string Key          { get; init; } = "";   // plain: what the talker is known by
            public string Name         { get; init; } = "";   // as shown (NameShown)
            public string Tip          { get; init; } = "";
            // What the program file is (ProgramTrust), as known when the row was built.
            public ProgramVerdict? Verdict { get; init; }
            public ProgramTone ProgramTone => Verdict?.Tone ?? ProgramTone.None;
            public string FullTip => Verdict?.Tip is { Length: > 0 } known ? $"{Tip}\n\n{known}" : Tip;
            public string Origin       { get; init; } = "";
            public string OriginTip => Origin switch
            {
                "Microsoft"        => "The file's version information names Microsoft Corporation as its maker.\nA label for sorting, not proof: the digital signature is not checked.",
                "Windows service"  => "Runs inside a Windows service host (svchost.exe) from the Windows folder.",
                "Windows"          => "A program in the Windows folder.",
                "Windows (kernel)" => "Traffic from the Windows kernel itself (the System process).",
                "Store app"        => "Installed from the Microsoft Store (WindowsApps folder).",
                "Application"      => "Installed software from any other maker.",
                _                  => "",
            };
            public int    OutDrops     { get; init; }
            public int    InDrops      { get; init; }
            public int    Allows       { get; init; }
            public int    Destinations { get; init; }
            public string TopDest      { get; init; } = "";
            public string Ports        { get; init; } = "";
            // The rules behind its rows, plain: active ones that allowed, else switched-off ones
            // that would allow; Dropped = it was blocked somewhere.
            public IReadOnlyList<string> AllowedBy { get; init; } = Array.Empty<string>();
            public IReadOnlyList<string> WouldBy   { get; init; } = Array.Empty<string>();
            public bool   Dropped      { get; init; }
            public string RuleStatus   => AllowedBy.Count > 0 ? "allowed by " + string.Join(", ", AllowedBy.Select(NameShown))
                                        : WouldBy.Count > 0 ? string.Join(", ", WouldBy.Select(n => "⊘ " + NameShown(n)))
                                        : Dropped ? "no rule" : "";
            public string RulePlain    => AllowedBy.Count > 0 ? "allowed by " + string.Join(", ", AllowedBy)   // copy and sort
                                        : WouldBy.Count > 0 ? string.Join(", ", WouldBy.Select(n => "⊘ " + n))
                                        : Dropped ? "no rule" : "";
            public string RuleTip      => string.Join("\n\n", new[] { RuleStatus }
                                              .Concat(AllowedBy.Concat(WouldBy).Select(NameFindings).OfType<string>()));
            /// <summary>The same in words (Copy for AI, export), each name written by <paramref name="name"/>.</summary>
            public string RuleWords(Func<string, string> name) =>
                AllowedBy.Count > 0 ? "allowed by " + string.Join(", ", AllowedBy.Select(name))
                : WouldBy.Count > 0 ? $"would be allowed by the switched-off rule{(WouldBy.Count > 1 ? "s" : "")} " + string.Join(", ", WouldBy.Select(name))
                : Dropped ? "no rule" : "";
            // Where it talked, summed over its rows: Local, Remote or Mixed (local green, remote
            // amber, mixed indigo).
            public string Locality     { get; init; } = "";
            public string LocalityTip  { get; init; } = "";
            public string LocalityTone => LogTone(Locality);
            public DateTime LastSeen   { get; init; }
            public string LastSeenText => LastSeen == default ? "" : LastSeen.ToString("HH:mm:ss");
            // Quiet: seen earlier while this window was open, but not in the current scope.
            public bool   IsQuiet      { get; init; }
            public bool   HasOutDrops  => OutDrops > 0 && !IsQuiet;
        }

        private List<TalkerRow> _talkers = new();

        // Which talker a row belongs to. Live: the program by its full path, with its service
        // (svchost.exe (CryptSvc)), ignoring case: two programs of one name in different folders
        // are two talkers. File: no program is known, so the far side's name or address stands in.
        private static string TalkerKey(LogEntry e) =>
            !string.IsNullOrEmpty(e.Program) ? $"{e.Program}\n{e.ProgramName}".ToUpperInvariant() : FarLabel(e);

        // The talker the Log tab is filtered to, as it is named in the list.
        private string TalkerFilterLabel() =>
            _talkers.FirstOrDefault(t => t.Id == _talkerFilter)?.Key ?? _talkerFilter ?? "";

        private static string FarIp(LogEntry e) => e.Direction == "RECEIVE" ? e.SrcIP : e.DstIP;

        // One name behind several addresses (a CDN) reads as the name once, with its addresses:
        // "bg.microsoft.map.fastly.net (199.232.210.172, 199.232.214.172)". Most-seen first.
        private static List<string> FarHosts(IEnumerable<LogEntry> rows) =>
            rows.GroupBy(e =>
                {
                    var name = e.HasDnsMark ? "" : e.Resolved;
                    return string.IsNullOrWhiteSpace(name) ? FarIp(e) : name;
                })
                .OrderByDescending(g => g.Count())
                .Select(g =>
                {
                    var ips = g.Select(FarIp).Distinct().ToList();
                    if (g.All(x => x.NoLookup)) return $"{string.Join(", ", ips.Take(3))}{(ips.Count > 3 ? $" +{ips.Count - 3}" : "")} (no Windows lookup)";
                    if (ips.Count == 1 && ips[0] == g.Key) return g.Key;          // no name, just the address
                    var shown = string.Join(", ", ips.Take(3)) + (ips.Count > 3 ? $" +{ips.Count - 3}" : "");
                    return $"{g.Key} ({shown})";
                })
                .ToList();

        private static string FarLabel(LogEntry e)
        {
            var ip = FarIp(e);
            var name = e.HasDnsMark ? "" : e.Resolved;
            return string.IsNullOrWhiteSpace(name) ? ip : $"{name} ({ip})";
        }

        // Where a program comes from, for sorting: Windows itself, one of its services, another
        // Microsoft component (Edge, WebView2, Defender, Office…), a Store app, or something
        // installed. File mode has no program, so there it's the network kind instead.
        private static string OriginOf(LogEntry e)
        {
            if (string.IsNullOrEmpty(e.Program)) return e.Locality;
            var p = e.Program;
            if (p.Equals("System", StringComparison.OrdinalIgnoreCase)) return "Windows (kernel)";
            if (p.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase)) return "Store app";
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (p.StartsWith(win + @"\", StringComparison.OrdinalIgnoreCase))
                return string.IsNullOrEmpty(e.Services) && !e.ServiceUnknown ? "Windows" : "Windows service";
            return IsMicrosoftFile(p) ? "Microsoft" : "Application";
        }

        // The company name from the file's version information. A label for sorting, not proof:
        // any exe can claim "Microsoft Corporation"; only its digital signature would prove it.
        // Cached per path, since the same few programs repeat on every row.
        private static readonly Dictionary<string, bool> _microsoftFile = new(StringComparer.OrdinalIgnoreCase);

        private static bool IsMicrosoftFile(string path)
        {
            if (_microsoftFile.TryGetValue(path, out var known)) return known;
            var result = false;
            try
            {
                if (File.Exists(path))
                    result = FileVersionInfo.GetVersionInfo(path).CompanyName?.Trim()
                                 .Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase) == true;
            }
            catch { /* unreadable: stays "Application" */ }
            _microsoftFile[path] = result;
            return result;
        }

        // One talker's rows, summed: all on this network → that kind (usually Local; Multicast
        // or Broadcast when that's all it did), all elsewhere → Remote, both → Mixed. The tooltip
        // counts rows per kind; for Mixed first the destinations on each side.
        private static NetworkLocality.Result SumLocality(IEnumerable<LogEntry> rows)
        {
            var kinds = rows.Where(e => e.Locality.Length > 0)
                            .GroupBy(e => e.Locality).OrderByDescending(k => k.Count()).ToList();
            if (kinds.Count == 0) return new NetworkLocality.Result("", "");
            var tip = string.Join("  ·  ", kinds.Select(k => $"{k.Key} ×{k.Count()}"));
            var local  = kinds.Where(k => NetworkLocality.Tone(k.Key) == "Safe").ToList();
            var remote = kinds.Count - local.Count;
            var kind = remote == 0 ? (local.Count == 1 ? local[0].Key : "Local")
                     : local.Count == 0 ? "Remote"
                     : "Mixed";
            if (kind == "Mixed")
            {
                var near = local.SelectMany(k => k).Select(FarIp).Distinct().Count();
                var far  = kinds.Except(local).SelectMany(k => k).Select(FarIp).Distinct().Count();
                tip = $"Mixed: {near} local and {far} remote destinations.\nConnections: {tip}";
            }
            return new NetworkLocality.Result(kind, tip);
        }

        // Rows kept per quiet talker (newest first), for "Allow…" and "Copy for AI". Plenty for
        // a program's pattern; bounded so a window left open for days doesn't grow without end.
        private const int MaxRememberedRows = 5000;

        private void RebuildTalkers()
        {
            var live = _scopedEntries.Any(e => !string.IsNullOrEmpty(e.Program));
            var byTalker = _scopedEntries.GroupBy(TalkerKey).ToList();
            var active = byTalker
                .Select(g =>
                {
                    var first = g.First();
                    var dests = g.GroupBy(FarLabel).OrderByDescending(d => d.Count()).ToList();
                    var ports = g.Select(e => e.DstPort).Where(x => x.Length > 0)
                                 .GroupBy(x => x).OrderByDescending(x => x.Count()).Select(x => x.Key).ToList();
                    var allowedBy = g.Where(e => e.RuleName.Length > 0 && !e.IsWouldAllow).Select(e => e.RuleName).Distinct().ToList();
                    // A would-allow rule a block rule overrides carries that with it, so neither the
                    // list nor Copy for AI says "would be allowed" alone.
                    var wouldBy   = g.Where(e => e.IsWouldAllow && e.RuleName.Length > 0)
                                     .Select(e => e.RuleName + (e.StillBlockedBy.Length > 0 ? $" (a block rule still stops it: {e.StillBlockedBy})" : ""))
                                     .Distinct().ToList();
                    var program = !string.IsNullOrEmpty(first.Program);
                    var tip = program ? first.ProgramTip : FarLabel(first);
                    var where = SumLocality(g);
                    return new TalkerRow
                    {
                        Id           = g.Key,
                        Program      = first.Program,
                        Key          = program ? first.ProgramName : g.Key,
                        Name         = program ? first.ProgramShown : g.Key,
                        Tip          = tip,
                        Verdict      = program ? ProgramTrust.For(first.Program) : null,
                        Origin       = OriginOf(first),
                        OutDrops     = g.Count(e => e.Action == "DROP" && e.Direction != "RECEIVE"),
                        InDrops      = g.Count(e => e.Action == "DROP" && e.Direction == "RECEIVE"),
                        Allows       = g.Count(e => e.Action == "ALLOW"),
                        Destinations = dests.Count,
                        TopDest      = string.Join("  ·  ", dests.Take(3).Select(d => $"{d.Key} ×{d.Count()}"))
                                       + (dests.Count > 3 ? $"  ·  +{dests.Count - 3} more" : ""),
                        Ports        = string.Join(", ", ports.Take(4)) + (ports.Count > 4 ? ", …" : ""),
                        AllowedBy    = allowedBy,
                        WouldBy      = allowedBy.Count > 0 ? Array.Empty<string>() : wouldBy,
                        Dropped      = g.Any(e => e.Action == "DROP"),
                        Locality     = where.Kind,
                        LocalityTip  = where.Tip,
                        LastSeen     = g.Max(e => e.Ts),
                    };
                })
                .OrderByDescending(t => t.OutDrops)
                .ThenByDescending(t => t.InDrops)
                .ThenByDescending(t => t.Allows)
                .ToList();

            // Remember every talker seen while this window is open (in memory only), with its
            // rows, so one that drops out of scope stays visible and "Allow…" still works for it.
            var rowsOf = byTalker.ToDictionary(g => g.Key, g => g);
            foreach (var t in active)
                _talkerMemory[t.Id] = (t, rowsOf[t.Id].Take(MaxRememberedRows).ToList());
            var activeIds = active.Select(a => a.Id).ToHashSet();
            var quiet = _talkerMemory.Values
                .Where(m => !activeIds.Contains(m.Row.Id))
                .Select(m => m.Row with { IsQuiet = true })
                .OrderByDescending(t => t.LastSeen)
                .ToList();
            _talkers = WithFolders(active.Concat(quiet).ToList());

            var selected = (TalkerGrid.SelectedItem as TalkerRow)?.Id;
            SetRows(TalkerGrid, _talkers, keepScroll: true);
            if (selected != null) TalkerGrid.SelectedItem = _talkers.FirstOrDefault(t => t.Id == selected);

            var outTalkers = active.Count(t => t.OutDrops > 0);
            TalkerSummary.Text = active.Count == 0 && quiet.Count == 0
                ? "Nothing in this scope."
                : (live ? $"{active.Count} programs" : $"{active.Count} addresses (the log file has no program names — Live mode groups by program)")
                  + $"  ·  {outTalkers} still trying to get out"
                  + (quiet.Count > 0 ? $"  ·  {quiet.Count} quiet (seen earlier, not in this scope)" : "")
                  + "  ·  ranked by outgoing drops; click a header to sort";
            ((TabItem)ViewTabs.Items[1]).Header = active.Count > 0 ? $"Talkers ({active.Count})" : "Talkers";
            BtnForgetQuiet.Visibility = quiet.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        // Talkers whose programs share a file name but sit in different folders are told apart
        // by the folder: "app.exe (C:\Tools)" / "app.exe (D:\Portable)".
        // ── Program colours ────────────────────────────────────────────────────
        // Signatures, look-alikes and pins (ProgramTrust), as in the rules list: what is known
        // shows at once, the rest is looked up per program in the background, then shown.

        private void LoadVerdicts()
        {
            ShowVerdicts();
            var programs = _gridRows.Select(r => r.Program).Concat(_talkers.Select(t => t.Program))
                                    .Where(p => p.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            ProgramTrust.Load(programs, () =>
            {
                if (_closed) return;
                ShowVerdicts();
                RebuildTalkers();   // its rows take the verdict when built
            });
        }

        private void ShowVerdicts()
        {
            var known = new Dictionary<string, ProgramVerdict?>(StringComparer.OrdinalIgnoreCase);
            foreach (var row in _gridRows)
            {
                if (row.IsMarker || row.Program.Length == 0) continue;
                if (!known.TryGetValue(row.Program, out var verdict)) known[row.Program] = verdict = ProgramTrust.For(row.Program);
                row.SetVerdict(verdict);
            }
        }

        private static List<TalkerRow> WithFolders(List<TalkerRow> talkers)
        {
            var clash = talkers.Where(t => t.Program.Length > 0)
                .GroupBy(t => LiveDropSource.ShortProgram(t.Program), StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Select(t => t.Program).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
                .SelectMany(g => g.Select(t => t.Id))
                .ToHashSet();
            return talkers.Select(t =>
            {
                if (!clash.Contains(t.Id) || Path.GetDirectoryName(t.Program) is not { Length: > 0 } folder) return t;
                return t with { Key = $"{t.Key} ({folder})", Name = $"{t.Name} ({TextHygiene.Reveal(folder).Shown})" };
            }).ToList();
        }

        // Talkers seen while this window is open. Memory only: gone when the window closes,
        // cleared when the source switches (File groups by address, Live by program).
        private readonly Dictionary<string, (TalkerRow Row, List<LogEntry> Entries)> _talkerMemory = new();

        // ── Lookups (Windows' DNS client log) ─────────────────────────────────

        public sealed record LookupRow
        {
            public string   Name          { get; init; } = "";
            public string   NameTip       { get; init; } = "";
            public int      Asked         { get; init; }
            public string   Programs      { get; init; } = "";
            public string   ProgramsTip   { get; init; } = "";
            public string   ProgramsAi    { get; init; } = "";   // for Copy for AI (ForAi)
            public string   ProgramsPlain { get; init; } = "";   // stored names, for copy and sort
            /// <summary>For a lookup Dnscache made on someone's behalf: what started just before.</summary>
            public string   StartedBefore    { get; init; } = "";
            public string   StartedBeforeTip { get; init; } = "";
            public string   ProgramsToolTip  => StartedBeforeTip.Length > 0 ? ProgramsTip + "\n\n" + StartedBeforeTip : ProgramsTip;
            public string   Result        { get; init; } = "";
            public bool     Failed        { get; init; }
            public string   Answer        { get; init; } = "";
            public string   AnswerTip     { get; init; } = "";
            public string   Locality      { get; init; } = "";
            public string   LocalityTip   { get; init; } = "";
            public string   LocalityTone  => LogTone(Locality);
            public DateTime LastAsked     { get; init; }
            public string   LastAskedText => LastAsked.ToString("HH:mm:ss");
            public IReadOnlyList<string> Aliases { get; init; } = Array.Empty<string>();
            public string   Flag          { get; init; } = "";
            public string?  FlagTip       { get; init; }
            public bool     Flagged       => Flag.Length > 0;
        }

        private List<LookupRow> _lookups = new();
        private int _lookupCount;

        private static string Plural(int n, string word) => $"{n} {word}{(n == 1 ? "" : "s")}";

        // A Mixed answer: how many of its addresses are on this machine's networks, how many not.
        private static string MixedAnswer(List<string> addresses)
        {
            var kinds = addresses.Select(a => NetworkLocality.Classify(a).Kind).Where(k => k.Length > 0).ToList();
            var near  = kinds.Count(k => NetworkLocality.Tone(k) == "Safe");
            return $"Mixed: {near} local and {kinds.Count - near} remote addresses in the answer.";
        }

        // Many different names under one domain, each asked once or twice, is how DNS tunnels
        // look (data in the names). Counted over the whole list; 20+ gets flagged.
        private const int ManyNamesPerDomain = 20;

        private static string TypeName(int t) => t switch
        {
            1 => "A", 28 => "AAAA", 5 => "CNAME", 16 => "TXT", 12 => "PTR", 33 => "SRV",
            65 => "HTTPS", 64 => "SVCB", 15 => "MX", 6 => "SOA", 2 => "NS", 10 => "NULL", 255 => "ANY",
            _ => $"type {t}",
        };

        // One row per name: how often, who asked, what came back; flagged first, then most asked.
        // startedBefore: for lookups Windows' DNS client made itself (svchost.exe (Dnscache)), the
        // programs started shortly before, one of which may be the real asker.
        private static List<LookupRow> BuildLookupRows(IEnumerable<DnsClientLog.Lookup> source,
                                                       Func<DateTime, (string Tip, string Compact)?>? startedBefore = null)
        {
            var all = source.ToList();
            var namesPerDomain = all.Select(l => l.Name).Distinct(StringComparer.OrdinalIgnoreCase)
                .GroupBy(DnsBypass.ParentDomain, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

            return all
                .GroupBy(l => l.Name, StringComparer.OrdinalIgnoreCase)
                .Select(g =>
                {
                    var latest  = g.First();                                  // newest first
                    var answered = g.Where(l => l.Status == 0 && l.Addresses.Count > 0).ToList();
                    var addresses = answered.SelectMany(l => l.Addresses).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    var aliases = g.Select(l => l.Aliases).FirstOrDefault(a => a.Count > 0) ?? Array.Empty<string>();

                    string Who(DnsClientLog.Lookup l) =>
                        l.Program.Length == 0 ? $"PID {l.ProcessId} (ended)"
                        : l.Services.Length > 0 ? $"{l.Program} ({l.Services})" : l.Program;
                    var programs = g.GroupBy(Who).OrderByDescending(p => p.Count()).ToList();
                    static string As(DnsClientLog.Lookup l) => l.Account.Length > 0 ? $" — as {l.Account}" : "";

                    var kinds = addresses.Select(a => NetworkLocality.Classify(a).Kind).Where(k => k.Length > 0).Distinct().ToList();
                    var local = kinds.Where(k => NetworkLocality.Tone(k) == "Safe").ToList();
                    var locality = addresses.Count == 0 ? "No address"
                                 : kinds.Count == 0 ? ""
                                 : local.Count == kinds.Count ? (local.Count == 1 ? local[0] : "Local")
                                 : local.Count == 0 ? "Remote" : "Mixed";

                    var result = answered.Count > 0 ? "answered" : DnsClientLog.StatusText(latest.Status);

                    // Flags: resolving around your resolver, or names shaped like carried data.
                    var flags = new List<(string Short, string Long)>();
                    if (DnsBypass.ServerByName(g.Key) is { } doh)
                        flags.Add(("encrypted DNS", $"A known encrypted-DNS server ({doh}): whoever looks this up is about to resolve around your resolver."));
                    if (DnsBypass.SuspiciousName(g.Key) is { } why)
                        flags.Add(("odd name", $"The name has {why}: the shape data takes when it is smuggled out in DNS names."));
                    if (DnsBypass.ProbeName(g.Key, answered.Count > 0))
                        flags.Add(("probe name", "A random single word that got no answer: the shape Edge and Chrome use to test " +
                                   "whether the network answers names that don't exist (they run it at start, on network changes, " +
                                   "and hidden when Edge starts in the background). A name without a dot is handled by Windows' " +
                                   "DNS client service itself, so the program behind it shows as svchost.exe (Dnscache). " +
                                   "If it failed locally (\"invalid name\"), nothing left the machine."));
                    var parent = DnsBypass.ParentDomain(g.Key);
                    if (namesPerDomain.TryGetValue(parent, out var siblings) && siblings >= ManyNamesPerDomain)
                        flags.Add(("many names", $"{siblings} different names under {parent} in this list: how DNS tunnels look."));
                    var unusual = g.Select(l => DnsBypass.UnusualType(l.Type)).Where(t => t != null).Distinct().ToList();
                    if (unusual.Count > 0)
                        flags.Add((string.Join("/", unusual), $"{string.Join("/", unusual)} lookups: they bring text or raw data back, not an address."));
                    var types = string.Join(", ", g.Select(l => TypeName(l.Type)).Distinct());

                    var viaDnscache = g.Any(l => l.Services.IndexOf("Dnscache", StringComparison.OrdinalIgnoreCase) >= 0);
                    var before = viaDnscache && startedBefore != null ? startedBefore(latest.Time) : null;

                    return new LookupRow
                    {
                        Name        = g.Key,
                        NameTip     = (aliases.Count > 0 ? $"{g.Key}\n→ {string.Join("\n→ ", aliases)}" : g.Key) + $"\n\nAsked as: {types}",
                        Flag        = flags.Count == 0 ? "" : flags[0].Short + (flags.Count > 1 ? $" +{flags.Count - 1}" : ""),
                        FlagTip     = flags.Count == 0 ? null : string.Join("\n\n", flags.Select(f => f.Long)),
                        Asked       = g.Count(),
                        Programs    = string.Join(", ", programs.Select(p => NameShown(p.Key))),
                        ProgramsTip = string.Join("\n", programs.Select(p => $"{NameShown(p.Key)} ×{p.Count()}{As(p.First())}")) +
                                      (programs.Select(p => NameFindings(p.Key)).OfType<string>().Distinct().ToList() is { Count: > 0 } found
                                          ? "\n\n" + string.Join("\n", found) : ""),
                        ProgramsAi  = string.Join("; ", programs.Select(p => $"{ForAi(p.Key)} ×{p.Count()}{As(p.First())}")),
                        ProgramsPlain = string.Join(", ", programs.Select(p => p.Key)),
                        StartedBefore    = before?.Compact ?? "",
                        StartedBeforeTip = before?.Tip ?? "",
                        Result      = result,
                        Failed      = answered.Count == 0,
                        Answer      = string.Join(", ", addresses.Take(4)) + (addresses.Count > 4 ? $"  +{addresses.Count - 4}" : ""),
                        AnswerTip   = addresses.Count > 0 ? string.Join("\n", addresses) : result,
                        Locality    = locality,
                        LocalityTip = addresses.Count == 0
                                      ? $"The lookup returned no address ({result}), so nothing could be contacted with it."
                                      : (locality == "Mixed" ? MixedAnswer(addresses) + "\n" : "") +
                                        string.Join("  ·  ", addresses.Take(6).Select(a => $"{a}: {NetworkLocality.Classify(a).Kind}")),
                        LastAsked   = latest.Time,
                        Aliases     = aliases,
                    };
                })
                .OrderByDescending(r => r.Flag.Length > 0).ThenByDescending(r => r.Asked).ThenByDescending(r => r.LastAsked)
                .ToList();
        }

        private void ViewTabs_SelectionChanged(object s, SelectionChangedEventArgs e)
        {
            if (e.Source != ViewTabs || !_ready) return;   // the grids' own selection bubbles up here too
            if (LookupsTab.IsSelected) LoadLookups();
        }

        // One row per name for the current scope: how often, who asked, what came back. Read
        // off the window's thread; a newer request makes an older answer stale.
        private int _lookupGen;

        private async void LoadLookups()
        {
            var gen = ++_lookupGen;
            var since = _since;
            LookupSummary.Text = "Reading…";
            try
            {
                var r = await Task.Run(() => { lock (_workGate) return ReadLookups(since); });
                if (gen != _lookupGen || _closed) return;
                ShowLookups(r.Rows, r.Count, r.Truncated, r.On, since);
            }
            catch (UnauthorizedAccessException)
            {
                if (gen == _lookupGen) LookupSummary.Text = "Reading the DNS client log needs administrator rights.";
            }
            catch (Exception ex)
            {
                if (gen == _lookupGen) LookupSummary.Text = $"Error: {ex.Message}";
            }
        }

        private (List<LookupRow> Rows, int Count, bool Truncated, bool? On) ReadLookups(DateTime? since)
        {
            Starts();                                   // "started just before" reads the starts as they are now
            var all = NameEndedLookups(DnsClientLog.Read(since));
            var truncated = DnsClientLog.LastReadTruncated;
            NetworkLocality.Refresh();
            return (BuildLookupRows(all, StartedBefore), all.Count, truncated, DnsClientLog.IsOn());
        }

        private void ShowLookups(List<LookupRow> rows, int count, bool truncated, bool? on, DateTime? since)
        {
            _lookupCount = count;
            _lookups = rows;
            _lookupsTruncated = truncated;

            SetRows(LookupGrid, _lookups, keepScroll: false);
            LookupsTab.Header = _lookups.Count > 0 ? $"Lookups ({_lookups.Count})" : "Lookups";

            var flagged = _lookups.Count(r => r.Flagged);
            var parts = new List<string>
            {
                $"{_lookups.Count} name{(_lookups.Count == 1 ? "" : "s")}" + (flagged > 0 ? $" ({flagged} flagged, shown first)" : ""),
                $"{_lookupCount} lookup{(_lookupCount == 1 ? "" : "s")}",
                since.HasValue ? $"since {since:HH:mm}" : "everything in the DNS log",
            };
            if (truncated) parts.Add($"newest {DnsClientLog.MaxEntries:N0} only: narrow the scope for older ones");
            parts.Add(on == true ? "DNS log on" : on == false ? "DNS log off: nothing new is recorded (switch it on in Live)" : "DNS log state unknown");
            parts.Add("most asked first; programs with their own resolver don't appear");
            LookupSummary.Text = string.Join("  ·  ", parts);
        }

        private bool _lookupsTruncated;

        // The lookups as text for an AI: context, then one short block per name.
        private void BtnCopyLookups_Click(object s, RoutedEventArgs e)
        {
            if (_lookups.Count == 0) { LookupSummary.Text = "No lookups to copy."; return; }
            var os = OsInfo.Describe();
            var sb = new StringBuilder();
            sb.AppendLine($"# DNS lookups — {DateTime.Now:yyyy-MM-dd HH:mm}");
            sb.AppendLine();
            sb.AppendLine("Context for the reader:");
            sb.AppendLine($"- Recorded with: Firewall Rule Manager {BuildInfo.AppVersion}.");
            sb.AppendLine($"- Machine: {os.Title}, {os.Detail}. Windows Firewall blocks outbound by default here.");
            sb.AppendLine("- Source: Windows' DNS client log (event 3008): every name lookup made through Windows, with the program that asked. Programs with their own resolver (e.g. a browser's secure DNS) don't appear.");
            sb.AppendLine($"- Scope: {(_since.HasValue ? $"since {_since:HH:mm}" : "everything in the DNS log")}; {Plural(_lookupCount, "lookup")} of {Plural(_lookups.Count, "name")}. Windows asking about itself is left out.");
            if (_lookupsTruncated)
                sb.AppendLine($"- Incomplete: only the newest {DnsClientLog.MaxEntries} lookups were read.");
            sb.AppendLine("- Network: Local = on this machine's own network; Remote = anywhere else.");
            sb.AppendLine("- Flags (\"Flag:\" lines) are the app's own hints, not verdicts: a known encrypted-DNS server name, or a name shaped like carried data (long/random labels, many names per domain, TXT lookups).");
            sb.AppendLine();
            sb.AppendLine("Please say for each name what it is, which program feature most likely asks for it, and how to stop that lookup at the source if it isn't needed. For flagged names, say whether the flag is a real concern.");
            sb.AppendLine();
            foreach (var r in _lookups)
            {
                sb.AppendLine($"## {r.Name}");
                sb.AppendLine($"- Asked {r.Asked}× · last {r.LastAskedText} · by: {r.ProgramsAi}");
                if (r.StartedBefore.Length > 0)
                    sb.AppendLine($"- Asked through Windows' DNS client, which hides the program; started in the {StartWindowSeconds} s before: {r.StartedBefore}");
                if (r.Aliases.Count > 0) sb.AppendLine($"- Via: {string.Join(" → ", r.Aliases)}");
                sb.AppendLine(r.Failed
                    ? $"- Result: {r.Result}"
                    : $"- Answer: {r.AnswerTip.Replace("\n", ", ")}{(r.Locality.Length > 0 ? $" [{r.Locality}]" : "")}");
                if (r.FlagTip != null) sb.AppendLine($"- Flag: {r.FlagTip.Replace("\n\n", " ")}");
                sb.AppendLine();
            }
            try
            {
                Clipboard.SetText(sb.ToString());
                LookupSummary.Text = $"Copied {_lookups.Count} name{(_lookups.Count == 1 ? "" : "s")} for pasting into an AI chat.";
            }
            catch (Exception ex) { LookupSummary.Text = $"Couldn't copy: {ex.Message} Try again."; }
        }

        // ── Copy the log for AI ──────────────────────────────────────────────
        // The rows in view, identical ones grouped (same action, direction, far side, port,
        // program and rule), newest first. Grouping keeps a chatty minute readable; the cap keeps
        // the paste within what a chat takes.
        private const int MaxCopyGroups = 300;

        // What the DNS marks in Copy for AI mean ("DNS warning, ALLOWED: …" / "DNS warning, blocked: …" / "DNS note: …").
        private const string DnsWarningLegend =
            "- DNS warnings, written \"DNS warning, ALLOWED: …\" or \"DNS warning, blocked: …\": " +
            "\"unexpected DNS\" = outgoing DNS that none of the active custom rules allows (a mark only; nothing is blocked or changed); " +
            "\"encrypted DNS\" = HTTPS/TLS to a known DNS-over-HTTPS server; " +
            "\"direct DNS\" = DNS a rule allows, sent by a program itself rather than Windows' DNS client service, through a rule " +
            "that doesn't name that program (so it never shows in the DNS log). " +
            "\"DNS note: …\" is information, not a warning: direct DNS that was allowed, or DNS to this machine's own loopback address (it never leaves the machine).";

        private void BtnCopyLog_Click(object s, RoutedEventArgs e)
        {
            if (_currentEntries.Count == 0) { LogCount.Text = "No connections in view to copy."; return; }

            static string Far(LogEntry x) => x.Direction == "RECEIVE" ? x.SrcIP : x.DstIP;
            // Grouped within one reload period only: the same filter number can mean another
            // filter after a reload, and a group must not straddle the line that says so.
            int Period(LogEntry x) => _reloads.Count(r => r.Time > x.Ts);

            // Each run of a program (its process: ID and, where recorded, its start) apart. A
            // program that ran more than once in this copy gets "#1", "#2"… in the order its
            // runs began, in the Programs section and on its connection lines.
            // A program is its full path with its services (ignoring case), so two app.exe in
            // different folders are two programs, not two runs of one.
            static string ProgramOf(LogEntry x) => $"{x.Program}\n{x.ProgramName}".ToUpperInvariant();
            static (int Pid, DateTime? Start) RunOf(LogEntry x) => (x.ProcessId, x.StartTime);
            var programs = _currentEntries.Where(x => x.Program.Length > 0)
                .GroupBy(ProgramOf)
                .Select(p => (Id: p.Key, Name: p.First().ProgramName, Runs: p.GroupBy(RunOf).OrderBy(r => r.Min(x => x.Ts)).ToList()))
                .ToList();
            var runNumber = new Dictionary<(string Id, int Pid, DateTime? Start), int>();
            foreach (var p in programs.Where(p => p.Runs.Count > 1))
                for (var i = 0; i < p.Runs.Count; i++)
                    runNumber[(p.Id, p.Runs[i].Key.Pid, p.Runs[i].Key.Start)] = i + 1;
            string RunTag(LogEntry x) =>
                runNumber.TryGetValue((ProgramOf(x), x.ProcessId, x.StartTime), out var n) ? $" #{n}" : "";

            var groups = _currentEntries
                .GroupBy(x => (x.Action, x.Protocol, x.Direction, Far: Far(x), x.DstPort, x.ProgramName, Run: RunTag(x),
                               x.RuleName, x.IsWouldAllow, x.StillBlockedBy, x.DnsWarn, x.Resolved, x.Locality, x.FilterId, Period: Period(x)))
                .Select(g => (Key: g.Key, Count: g.Count(), First: g.Min(x => x.Ts), Last: g.Max(x => x.Ts), Sample: g.First()))
                .OrderByDescending(g => g.Last)
                .ToList();

            var filters = new List<string> { _live ? "Live (Security log)" : "File (pfirewall.log)" };
            if (_clearMark.HasValue)          filters.Add($"new since {_clearMark.Value:HH:mm:ss}");
            else if (_follow && _since.HasValue) filters.Add($"since {_since:HH:mm}");   // rows keep arriving
            else if (_scopeMinutes is int sm) filters.Add($"last {sm} min");
            else                              filters.Add("everything in the log");
            if (_dropsOnly)  filters.Add("blocked only");
            if (_allowsOnly) filters.Add("allowed only");
            if (_talkerFilter != null) filters.Add($"talker: {ForAi(TalkerFilterLabel())}");
            var hidden   = _noise.Where(kv => kv.Value).Select(kv => kv.Key).ToList();
            var families = NoiseFamilies();
            if (families == "no family") hidden.Clear();   // nothing is hidden anywhere

            var os = OsInfo.Describe();
            var sb = new StringBuilder();
            sb.AppendLine($"# Firewall connection log — {DateTime.Now:yyyy-MM-dd HH:mm}");
            sb.AppendLine();
            sb.AppendLine("Context for the reader:");
            sb.AppendLine($"- Recorded with: Firewall Rule Manager {BuildInfo.AppVersion}.");
            sb.AppendLine($"- Machine: {os.Title}, {os.Detail}. Windows Firewall blocks inbound and outbound by default here; only explicit Allow rules let traffic through.");
            // What the noise filter took out of this same view is counted too: "0 allowed" would
            // otherwise read as "nothing was allowed" when it was only hidden.
            var noiseHidden = _readEntries.Where(x =>
                    (!_dropsOnly  || x.Action == "DROP") &&
                    (!_allowsOnly || x.Action == "ALLOW") &&
                    (_talkerFilter == null || TalkerKey(x) == _talkerFilter) &&
                    IsSuppressedNoise(x))
                .ToList();
            var hiddenCount = noiseHidden.Count > 0
                ? $" (plus {noiseHidden.Count(x => x.Action == "DROP")} blocked and {noiseHidden.Count(x => x.Action == "ALLOW")} allowed hidden as noise)"
                : "";
            sb.AppendLine($"- View: {string.Join(", ", filters)}. {_currentEntries.Count(x => x.Action == "DROP")} blocked and {_currentEntries.Count(x => x.Action == "ALLOW")} allowed connections shown{hiddenCount}, " +
                          $"from {_currentEntries.Min(x => x.Ts):yyyy-MM-dd HH:mm:ss} to {_currentEntries.Max(x => x.Ts):HH:mm:ss}.");
            if (_capped)
                sb.AppendLine($"- Incomplete: only the newest {MaxRows} connections are kept; older ones are left out.");
            if (_live && LiveDropSource.AllowAuditingOn() != true)
                sb.AppendLine("- Allowed connections are not being recorded, so only blocked ones appear.");
            sb.AppendLine(hidden.Count > 0
                ? $"- Hidden as background noise (not listed): {string.Join(", ", hidden)}{(families.Length > 0 ? $" ({families})" : "")}."
                : "- Nothing is hidden as noise.");
            if (DnsRuleState() is { } dnsState)
                sb.AppendLine($"- {dnsState}");
            sb.AppendLine("- Each line: count × time range · action · protocol, direction and far side [network] · program · rule, and a DNS warning or note where there is one. Identical connections are grouped.");
            sb.AppendLine("- Network: Local = on this machine's own network; Link-local / Multicast / Loopback as named; Remote = anywhere else.");
            sb.AppendLine("- Rule: the custom rule that allowed the connection, or the switched-off one that would allow it; \"no rule\" = none covers it.");
            if (_currentEntries.Any(x => x.HasDnsMark))
                sb.AppendLine(DnsWarningLegend);
            var markers = new Queue<Marker>(Markers(_currentEntries));
            if (markers.Any(m => m.Action is "NETWORK" or "CLOCK"))
                sb.AppendLine("- Context lines between the connections: \"network connected/disconnected/changed\" from Windows' network list log; " +
                              "\"clock changed\" = the system clock was set by more than a minute (Security log).");
            if (_live)
                sb.AppendLine("- Filter: the Windows filter that decided, by the ID in the event and, where it still holds, its name, provider and sublayer as Windows lists them now. " +
                              "Windows renumbers filters every time the firewall reloads its rules (the \"Firewall reloaded all rules\" lines), at every restart and at some network changes; an ID from before the last reload or restart is marked " +
                              "\"renumbered\" and not named: today's filter with that number may be a different one. The firewall's default blocks are typically named \"Default Outbound\"/\"Default Inbound\" (possibly translated).");
            sb.AppendLine();
            sb.AppendLine("Please explain what each group is (protocol, the Windows feature or program behind it), whether this machine needs it, and for blocked ones whether to allow it or stop it at the source.");
            sb.AppendLine();

            sb.AppendLine("## Connections (newest first)");
            void MarkersAfter(DateTime t)
            {
                while (markers.Count > 0 && markers.Peek().Time > t)
                {
                    var m = markers.Dequeue();
                    sb.AppendLine($"- {m.Time:HH:mm:ss} · {m.Words}");
                }
            }
            foreach (var g in groups.Take(MaxCopyGroups))
            {
                MarkersAfter(g.Last);
                var x = g.Sample;
                var inbound = x.Direction == "RECEIVE";
                var name = x.Resolved.Length > 0 && !x.HasDnsMark ? $" ({x.Resolved})" : "";
                var where = inbound
                    ? $"in from {g.Key.Far}{name}{(x.DstPort.Length > 0 ? $" to port {x.DstPort}" : "")}"
                    : $"out to {g.Key.Far}{(x.DstPort.Length > 0 ? $":{x.DstPort}" : "")}{name}";
                var net  = x.Locality.Length > 0 ? $" [{x.Locality}]" : "";
                var prog = x.ProgramName.Length > 0 ? $" · {ForAi(x.ProgramName)}{g.Key.Run}" : "";
                var rule = x.RuleName.Length == 0 ? "no rule"
                         : x.IsWouldAllow ? $"would be allowed by the switched-off rule {ForAi(x.RuleName)}" +
                                            (x.StillBlockedBy.Length > 0 ? $" (a block rule still stops it: {ForAi(x.StillBlockedBy)})" : "")
                         : $"allowed by {ForAi(x.RuleName)}";
                var time = g.First == g.Last ? $"{g.Last:HH:mm:ss}" : $"{g.First:HH:mm:ss}–{g.Last:HH:mm:ss}";
                var warn = x.HasDnsMark ? $" · {x.DnsWarnWords}" : "";
                var filter = x.FilterCopy.Length > 0 ? $" · {x.FilterCopy}" : x.FilterId > 0 ? $" · filter {x.FilterId}" : "";
                sb.AppendLine($"- {g.Count}× {time} · {x.Action} · {x.Protocol} {where}{net}{prog} · {rule}{filter}{warn}");
            }
            if (groups.Count > MaxCopyGroups)
                sb.AppendLine($"- … and {groups.Count - MaxCopyGroups} older groups (narrow the scope or filter to see them).");
            else
                MarkersAfter(DateTime.MinValue);

            // Each run of each program, with what identifies it: path, services, how it was
            // started; with more than one run, which process and when.
            if (programs.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("## Programs");
                foreach (var (_, name, runs) in programs)
                    for (var i = 0; i < runs.Count; i++)
                    {
                        var p = runs[i].First();
                        var several = runs.Count > 1;
                        sb.AppendLine($"- {ForAi(name)}{(several ? $" #{i + 1}" : "")}: {ForAi(p.Program)}");
                        if (several)
                        {
                            var (from, to) = (runs[i].Min(x => x.Ts), runs[i].Max(x => x.Ts));
                            var seen = from == to ? $"{from:HH:mm:ss}" : $"{from:HH:mm:ss}–{to:HH:mm:ss}";
                            sb.AppendLine(p.ProcessId > 0 ? $"  Process {p.ProcessId}, connections {seen}" : $"  Connections {seen}");
                        }
                        if (p.ServicesLong.Length > 0)
                            sb.AppendLine($"  Services in this process: {p.ServicesLong.Replace(Environment.NewLine, "; ").Replace("\n", "; ")}");
                        if (p.CommandLine.Length > 0)
                            sb.AppendLine($"  Started{(several && p.StartTime is { } st ? $" {st:HH:mm:ss}" : "")} as: {p.CommandLine}" +
                                          (p.ParentProgram.Length > 0 ? $" (by {ForAi(p.ParentProgram)})" : ""));
                    }
            }

            try
            {
                Clipboard.SetText(sb.ToString());
                LogCount.Text = $"Copied {Math.Min(groups.Count, MaxCopyGroups)} groups ({_currentEntries.Count} connections) for pasting into an AI chat.";
            }
            catch (Exception ex) { LogCount.Text = $"Couldn't copy: {ex.Message} Try again."; }
        }

        // ── Copy for AI ──────────────────────────────────────────────────────
        // Every talker as plain text for an AI chat to identify: a context block (this firewall's
        // defaults, what the terms mean), then one section per talker with path, services and
        // traffic grouped by outcome. Only the far side of each connection is listed.
        private void BtnCopyTalkers_Click(object s, RoutedEventArgs e)
        {
            if (_talkers.Count == 0) { LogCount.Text = "No talkers to copy."; return; }

            var sb = new StringBuilder();
            var os = OsInfo.Describe();
            sb.AppendLine($"# Firewall talkers — {DateTime.Now:yyyy-MM-dd HH:mm}");
            sb.AppendLine();
            sb.AppendLine("Context for the reader:");
            sb.AppendLine($"- Recorded with: Firewall Rule Manager {BuildInfo.AppVersion}.");
            sb.AppendLine($"- Machine: {os.Title}, {os.Detail}.");
            sb.AppendLine("- Windows Firewall blocks outbound by default here; only explicit Allow rules let traffic out, and inbound is blocked too.");
            sb.AppendLine(_live
                ? "- Source: the Security event log (5157 = blocked, 5156 = allowed), which names the program and, for svchost.exe, its services."
                : "- Source: the firewall log file, which has no program names; talkers are destinations instead.");
            sb.AppendLine($"- Scope: {(_since.HasValue ? $"since {_since:HH:mm}" : "everything in the log")}. \"Quiet\" talkers were seen earlier while the window was open, not in this scope.");
            if (_capped)
                sb.AppendLine($"- Incomplete: only the newest {MaxRows} connections are kept; older ones are missing, so counts are low and early talkers may be absent.");
            sb.AppendLine("- Rule: the custom rule that allowed its connections, or the switched-off one that would allow them; \"no rule\" = none covers them.");
            sb.AppendLine("- Network: Local = on this machine's own network; Remote = anywhere else.");
            if (_dnsCoverFrom.HasValue)
            {
                sb.AppendLine("- Names: from Windows' DNS client log where a lookup returned that address (exact), " +
                          (_dnsCacheRead ? "else from the DNS cache (read only while that log is off), " : "") +
                          "else a guess from the address range (marked \"?\").");
                sb.AppendLine($"- \"no Windows lookup\" = from {_dnsCoverFrom:HH:mm} on the DNS log was recording, yet no lookup returned that address: the program used the address directly, its own resolver, or an older answer.");
            }
            if (_talkers.Any(t => TalkerEntries(t).Any(x => x.CommandLine.Length > 0)))
                sb.AppendLine("- \"Started as\": the process's recorded start (Security event 4688) with its command line; service hosts that had ended are named from it.");
            sb.AppendLine(DnsWarningLegend);
            sb.AppendLine();
            sb.AppendLine("Please identify each program, say what it is most likely doing on the network, and whether it needs access (and to what), or can stay blocked.");
            sb.AppendLine();

            foreach (var t in _talkers)
            {
                var rows = TalkerEntries(t);
                var first = rows.FirstOrDefault();
                sb.AppendLine($"## {ForAi(t.Key)}");
                sb.AppendLine($"- Kind: {t.Origin}{(t.IsQuiet ? " · quiet" : "")} · last seen {t.LastSeenText}");
                if (first != null && first.Program.Length > 0)
                    sb.AppendLine($"- Path: {ForAi(first.Program)}");
                if (first != null && first.ServicesLong.Length > 0)
                    sb.AppendLine($"- Services in this process: {first.ServicesLong.Replace(Environment.NewLine, "; ").Replace("\n", "; ")}");
                if (first != null && first.ServiceUnknown)
                    sb.AppendLine(first.ServiceGroup.Length > 0
                        ? $"- Service: one of the \"{first.ServiceGroup}\" group (services share hosts on this machine; the recorded start names only the group)."
                        : "- Service: unknown. This service host had ended before it could be looked up (the log names only the program), so this row may combine several different services.");
                foreach (var cmd in rows.Where(x => x.CommandLine.Length > 0).Select(x => (x.CommandLine, x.ParentProgram)).Distinct().Take(3))
                    sb.AppendLine($"- Started as: {cmd.CommandLine}{(cmd.ParentProgram.Length > 0 ? $"  (by {ForAi(cmd.ParentProgram)})" : "")}");
                var total = t.OutDrops + t.InDrops + t.Allows;
                sb.AppendLine($"- Counts: {t.OutDrops} outbound blocked, {t.InDrops} inbound blocked, {t.Allows} allowed");
                if (rows.Count < total)
                    sb.AppendLine($"- The lines below cover the newest {rows.Count} of these {total} connections.");
                if (t.RuleWords(ForAi) is { Length: > 0 } ruleWords) sb.AppendLine($"- Rule: {ruleWords}");

                // What happened, grouped: action, direction, protocol and port, then where to.
                var groups = rows
                    .GroupBy(x => (x.Action, In: x.Direction == "RECEIVE", x.Protocol, x.DstPort))
                    .OrderByDescending(g => g.Count());
                foreach (var g in groups)
                {
                    var what  = g.Key.Action == "DROP" ? "blocked" : "allowed";
                    var dir   = g.Key.In ? "in from" : "out to";
                    var port  = g.Key.DstPort.Length > 0 ? $" {g.Key.DstPort}" : "";
                    var hosts = FarHosts(g);
                    var where = string.Join(", ", hosts.Take(8)) + (hosts.Count > 8 ? $" and {hosts.Count - 8} more" : "");
                    var nets  = string.Join("/", g.Select(x => x.Locality).Where(l => l.Length > 0).Distinct());
                    sb.AppendLine($"- {g.Count()}× {what} {g.Key.Protocol}{port} {dir} {where}{(nets.Length > 0 ? $" [{nets}]" : "")}");
                }
                foreach (var warn in rows.Where(x => x.HasDnsMark).Select(x => x.DnsWarnWords).Distinct())
                    sb.AppendLine($"- {warn}");
                var noLookup = rows.Count(x => x.NoLookup);
                if (noLookup > 0)
                    sb.AppendLine($"- No Windows lookup behind {noLookup} of these connections (the DNS log was recording).");
                sb.AppendLine();
            }

            // The other half: what was looked up in the same scope, and by whom.
            var lookupRows = BuildLookupRows(_joinLookups, StartedBefore);
            if (lookupRows.Count > 0)
            {
                sb.AppendLine($"# DNS lookups in the same scope ({Plural(_joinLookups.Count, "lookup")} of {Plural(lookupRows.Count, "name")}, from Windows' DNS client log)");
                sb.AppendLine();
                foreach (var r in lookupRows.Take(150))
                {
                    var by = r.ProgramsAi;
                    var flag = (r.FlagTip != null ? $"  Flag: {r.FlagTip.Replace("\n\n", " ")}" : "")
                             + (r.StartedBefore.Length > 0 ? $"  (started in the {StartWindowSeconds} s before: {r.StartedBefore})" : "");
                    sb.AppendLine(r.Failed
                        ? $"- {r.Name} — {r.Asked}× by {by} — {r.Result}{flag}"
                        : $"- {r.Name} — {r.Asked}× by {by} → {r.AnswerTip.Replace("\n", ", ")}{(r.Locality.Length > 0 ? $" [{r.Locality}]" : "")}{flag}");
                }
                if (lookupRows.Count > 150) sb.AppendLine($"- … and {lookupRows.Count - 150} more names (the Lookups tab has them all).");
                sb.AppendLine();
            }

            try
            {
                Clipboard.SetText(sb.ToString());
                LogCount.Text = $"Copied {_talkers.Count} talker{(_talkers.Count == 1 ? "" : "s")} for pasting into an AI chat.";
            }
            catch (Exception ex)
            {
                // The clipboard can be held open by another program for a moment.
                LogCount.Text = $"Couldn't copy: {ex.Message} Try again.";
            }
        }

        private void BtnForgetQuiet_Click(object s, RoutedEventArgs e)
        {
            foreach (var key in _talkerMemory.Keys.Where(k => !_scopedEntries.Any(x => TalkerKey(x) == k)).ToList())
                _talkerMemory.Remove(key);
            RebuildTalkers();
        }

        // The rows behind a talker: from the current scope, or remembered if it went quiet.
        private List<LogEntry> TalkerEntries(TalkerRow t) =>
            t.IsQuiet && _talkerMemory.TryGetValue(t.Id, out var m)
                ? m.Entries
                : _scopedEntries.Where(x => TalkerKey(x) == t.Id).ToList();

        private void TalkerGrid_SelectionChanged(object s, SelectionChangedEventArgs e)
        {
            var t = TalkerGrid.SelectedItem as TalkerRow;
            // A quiet talker has no rows in the current scope to show; its remembered rows still
            // feed "Allow…".
            BtnShowTalker.IsEnabled = t != null && !t.IsQuiet;
            BtnShowTalker.ToolTip = t is { IsQuiet: true }
                ? $"Not in the current scope (last seen {t.LastSeenText}). Widen the scope to see its rows."
                : null;
            ToolTipService.SetShowOnDisabled(BtnShowTalker, true);
            var hasProgram = t != null && TalkerEntries(t).Any(x => x.Program.Length > 0);
            BtnAllowTalker.IsEnabled = hasProgram;
            BtnAllowTalker.ToolTip = t != null && !hasProgram
                ? "Live mode only: the log file doesn't say which program it was."
                : "Open a rule for this talker, filled in from what it tried. Nothing is saved until you save it.";
        }

        // ── "Allow…": a rule proposal from what one talker tried ──────────────
        // Scoped as the evidence allows: this program (and its one service), the direction and
        // protocol it used most, the ports it asked for, any destination (trust on the program).
        // If a script rule for the same program already exists, that rule opens with the ports
        // added instead, so one program keeps one rule.

        private void BtnAllowTalker_Click(object s, RoutedEventArgs e)
        {
            if (TalkerGrid.SelectedItem is not TalkerRow t) return;
            var rows = TalkerEntries(t).Where(x => x.Program.Length > 0).ToList();
            if (rows.Count == 0) return;

            // What it tried and was refused, if anything; otherwise all it did.
            var basis = rows.Where(x => x.Action == "DROP").ToList();
            if (basis.Count == 0) basis = rows;

            var outCount  = basis.Count(x => x.Direction != "RECEIVE");
            var direction = outCount >= basis.Count - outCount ? "Out" : "In";
            var dirRows   = basis.Where(x => (x.Direction != "RECEIVE") == (direction == "Out")).ToList();

            var protoGroups = dirRows.GroupBy(x => x.Protocol).OrderByDescending(g => g.Count()).ToList();
            var proto = protoGroups[0].Key;
            // What was seen, where the editor writes it. Anything else starts with no protocol
            // (Save waits for a choice): Any would allow more than was seen.
            var ruleProto = proto is "TCP" or "UDP" or "ICMP" or "ICMPv6" ? proto : "";
            var protoNote = ruleProto.Length > 0 ? null
                : $"Seen: {(proto.Length > 0 ? proto : "no protocol")}. The editor writes TCP, UDP, ICMP, ICMPv6 or Any; Any would allow every protocol.";
            var protoRows = protoGroups[0].ToList();

            // The local port for inbound, the remote port for outbound: both are Dst Port here.
            // Only TCP and UDP have ports.
            var ports = ruleProto is not ("TCP" or "UDP") ? new List<string>()
                      : protoRows.Select(x => x.DstPort).Where(p => p.Length > 0).Distinct()
                                 .OrderBy(p => int.TryParse(p, out var n) ? n : int.MaxValue).ToList();

            var first    = rows[0];
            var services = first.Services.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var service  = services.Length == 1 ? services[0] : "";
            var baseName = service.Length > 0 ? service
                         : first.Program.Equals("System", StringComparison.OrdinalIgnoreCase) ? "System"
                         : Path.GetFileNameWithoutExtension(first.Program);

            var ipCount = protoRows.Select(FarIp).Distinct().Count();
            var hosts   = FarHosts(protoRows);
            var others  = protoGroups.Skip(1).Select(g => $"{g.Key} ({g.Count()}×)").ToList();
            var detail = $"Seen {protoRows.Count}× {direction.ToLowerInvariant()}bound over {proto}"
                       + $" to {ipCount} destination{(ipCount == 1 ? "" : "s")}: "
                       + string.Join(", ", hosts.Take(3))
                       + (hosts.Count > 3 ? $" and {hosts.Count - 3} more" : "") + "."
                       + (others.Count > 0 ? $" It also used {string.Join(", ", others)}; that needs a rule of its own if it matters." : "")
                       + (services.Length > 1 ? $" This process hosts several services ({first.Services}): pick the one that needs access." : "");

            // System is the kernel: trust on the program would be trust on everything Windows
            // sends, so a new rule gets the destinations seen. The address limit holds IPv4 only.
            var kernel = first.Program.Equals("System", StringComparison.OrdinalIgnoreCase);
            var seenV4 = new List<uint>();
            var seenV6 = 0;
            if (kernel)
                foreach (var ip in protoRows.Select(FarIp).Distinct())
                    if (Ipv4Scope.TryAddress(ip, out var v4, out _)) seenV4.Add(v4); else seenV6++;
            var remote = string.Join(",", seenV4.Distinct().OrderBy(a => a).Select(Ipv4Scope.Text));

            var main  = Application.Current.MainWindow as MainWindow;
            var owner = (Window)this;
            // Lock down or Purge Local is running in the main window: no rule is written under it.
            if (main?.RefuseWhileBusy() == true)
            {
                ThemedDialog.Info(this, "Wait", "A task is running in the main window (Lock down or Purge Local). Allow… works again once it is done.");
                return;
            }
            // A protocol the editor doesn't write is covered only by the program's Any rule.
            var matchProto = ruleProto.Length > 0 ? ruleProto : "Any";
            var existing = main?.FindRuleToExtend(first.Program, service, direction, matchProto);
            // Only a new rule takes the destinations: an extended rule keeps its own.
            if (existing != null) remote = "";
            // Inbound, the far side is where it came from: the editor calls those sources.
            var far = direction == "In" ? "source" : "destination";
            detail += remote.Length > 0
                ? $" System is Windows itself; the {far}s seen are filled in rather than Any." +
                  (seenV6 > 0 ? $" {Plural(seenV6, $"IPv6 {far}")} {(seenV6 == 1 ? "isn't" : "aren't")} included: the address limit holds IPv4 addresses only." : "")
                : kernel && existing == null && seenV6 > 0
                ? $" Only IPv6 {far}s were seen; the address limit holds IPv4 only, so it is left at Any."
                : " Destination is left at Any, with trust declared on the program; restrict it if the destinations are fixed.";

            var observed = new RuleEditWindow.Observed(
                Name:      $"{AsRuleName(baseName)} {direction}".Trim(),
                Direction: direction,
                Protocol:  ruleProto,
                Ports:     string.Join(",", ports),
                Program:   first.Program,
                Service:   service,
                Title:     $"Filled in from what {t.Name} tried",
                Detail:    detail,
                Remote:    remote);
            // A matching rule the editor can't change (settings it doesn't offer) isn't extended:
            // a new rule starts, and the editor says why.
            var readOnly = existing == null ? main?.ReadOnlyMatch(first.Program, service, direction, matchProto) : null;
            var readOnlyNote = readOnly != null ? $"{readOnly.NameDisplay} has settings the editor doesn't offer, so a new rule was started." : null;
            var notes = new[] { readOnlyNote, protoNote }.OfType<string>().ToList();
            var saved = existing != null
                ? RuleEditWindow.OpenExtending(existing, observed, owner)
                : RuleEditWindow.OpenFromObserved(observed, owner, notes.Count > 0 ? string.Join(" ", notes) : null);

            if (!saved) return;
            main?.RefreshRules();
            ReadLog();   // the Rule column follows the new rule: rows are judged afresh
        }

        // A service or file name as a rule name: "_" stands for a space in a rule's registry key,
        // so it becomes one (CDPUserSvc_4a5b3 → "CDPUserSvc 4a5b3"). Any other character a name
        // can't hold becomes its closest plain form ("ü" → "u", "’" → "'"), or is left out if it
        // has none. Only a proposal: the editor shows it before anything is saved.
        private static string AsRuleName(string text)
        {
            var sb = new StringBuilder();
            void Add(int cp)
            {
                if (!TextHygiene.IsNameChar(cp)) return;
                if (cp == ' ' && (sb.Length == 0 || sb[^1] == ' ')) return;
                sb.Append((char)cp);
            }
            foreach (var r in text.Replace('_', ' ').EnumerateRunes())
            {
                if (TextHygiene.IsNameChar(r.Value)) Add(r.Value);
                else if (TextHygiene.Alternatives(r) is { Count: > 0 } plain)
                    foreach (var c in plain[0]) Add(c);
            }
            return sb.ToString().TrimEnd();
        }

        private void TalkerGrid_MouseDoubleClick(object s, System.Windows.Input.MouseButtonEventArgs e) => ShowTalkerInLog();
        private void BtnShowTalker_Click(object s, RoutedEventArgs e) => ShowTalkerInLog();

        private void ShowTalkerInLog()
        {
            if (TalkerGrid.SelectedItem is not TalkerRow t || t.IsQuiet) return;
            _talkerFilter = t.Id;
            ViewTabs.SelectedIndex = 0;
            ShowScoped();
        }

        private void BtnTalkerFilter_Click(object s, RoutedEventArgs e)
        {
            _talkerFilter = null;
            ShowScoped();
        }

        // The whole file: its last MaxRows lines. Capped when a line left out is still in scope.
        private static List<LogEntry> ReadFileEntries(DateTime? since, ReadResult r)
        {
            var (lines, end, head, _) = ReadFileOn(LogFile, 0, Array.Empty<byte>());
            r.FilePos  = end;
            r.FileHead = head;
            var data = lines.Where(l => !l.StartsWith("#") && !string.IsNullOrWhiteSpace(l)).ToList();
            var kept = data.Count > MaxRows ? data.GetRange(data.Count - MaxRows, MaxRows) : data;
            if (data.Count > kept.Count && ParseFileLine(data[data.Count - kept.Count - 1]) is { } before
                && (!since.HasValue || before.Ts >= since.Value))
                r.Capped = true;
            return kept.Select(ParseFileLine).Where(e => e != null).Select(e => e!).ToList();
        }

        // Following the file: the lines written since the last read. Windows renames a full log
        // to .old and starts a new one; the rest of the old one is read first, then the new one
        // from its start.
        private List<LogEntry> ReadFileOnward()
        {
            if (!File.Exists(LogFile)) return new();
            var lines = new List<string>();
            var (now, end, head, otherFile) = ReadFileOn(LogFile, _filePos, _fileHead);
            if (otherFile && File.Exists(LogFile + ".old"))
            {
                // The .old one is the file read so far only if it starts the same and reaches as far.
                var (rest, _, _, notIt) = ReadFileOn(LogFile + ".old", _filePos, _fileHead);
                if (!notIt) lines.AddRange(rest);
            }
            lines.AddRange(now);
            _filePos  = end;
            _fileHead = head;
            return lines.Where(l => !l.StartsWith("#") && !string.IsNullOrWhiteSpace(l))
                        .TakeLast(MaxRows)
                        .Select(ParseFileLine).Where(e => e != null).Select(e => e!).ToList();
        }

        private const int HeadBytes = 512;

        // Reads a log file on from a byte position: the full lines after it, where the next read
        // starts, and the file's first bytes. A file shorter than the position, or starting
        // differently from knownHead, is another file (OtherFile): it is read from its start.
        private static (List<string> Lines, long End, byte[] Head, bool OtherFile) ReadFileOn(string path, long pos, byte[] knownHead)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var head = ReadBytes(fs, 0, HeadBytes);
            var other = pos > 0 && (fs.Length < pos || !SameStart(head, knownHead));
            if (other) pos = 0;
            var rest = ReadBytes(fs, pos, fs.Length - pos);
            var last = Array.LastIndexOf(rest, (byte)'\n');           // a line still being written waits
            if (last < 0) return (new List<string>(), pos, head, other);
            var text = Encoding.UTF8.GetString(rest, 0, last + 1);
            return (text.Split('\n').ToList(), pos + last + 1, head, other);
        }

        // Whether two files start the same, as far as both reach.
        private static bool SameStart(byte[] a, byte[] b)
        {
            var n = Math.Min(a.Length, b.Length);
            return a.AsSpan(0, n).SequenceEqual(b.AsSpan(0, n));
        }

        private static byte[] ReadBytes(FileStream fs, long from, long count)
        {
            fs.Position = from;
            var size = (int)Math.Clamp(Math.Min(count, fs.Length - from), 0, int.MaxValue);
            var buffer = new byte[size];
            var got = 0;
            while (got < size)
            {
                var n = fs.Read(buffer, got, size - got);
                if (n == 0) break;
                got += n;
            }
            return got == size ? buffer : buffer[..got];
        }

        private static LogEntry? ParseFileLine(string line)
        {
            var p = line.Trim().Split(' ');
            if (p.Length < 9) return null;
            // Written the same on every machine, whatever its language: never the machine's culture.
            DateTime.TryParseExact($"{p[0]} {p[1]}", "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var ts);
            return new LogEntry
            {
                Time      = $"{p[0]} {p[1]}",
                Action    = p[2],
                // Named by the same table as Live and the rule list ("2" → IGMP); text the table
                // doesn't know stays as written.
                Protocol  = Protocols.Number(p[3]) is { } number ? Protocols.Name(number) : p[3],
                SrcIP     = p[4],
                DstIP     = p[5],
                SrcPort   = p[6] == "-" ? "" : p[6],
                DstPort   = p[7] == "-" ? "" : p[7],
                Direction = p.Length > 16 ? p[16] : "",
                Ts        = ts
            };
        }

        private static List<LogEntry> ToEntries(IEnumerable<LiveDropSource.LiveEvent> events) =>
            events.Select(ev => new LogEntry
            {
                Time      = ev.Time.ToString("yyyy-MM-dd HH:mm:ss"),
                Action    = ev.Action,
                Protocol  = ev.Protocol,
                SrcIP     = ev.SrcIP,
                DstIP     = ev.DstIP,
                SrcPort   = ev.SrcPort,
                DstPort   = ev.DstPort,
                Direction = ev.Direction,
                Program   = ev.Program,
                Services  = ev.Services,
                ServicesLong = ev.ServicesLong,
                ProcessId = ev.ProcessId,
                FilterId  = ev.FilterId,
                Ts        = ev.Time
            }).ToList();

        private readonly Dictionary<string, NetworkLocality.Result> _localityCache = new();

        // Same for both sources: resolved name, network, DNS tripwire, rule inference.
        private LogEntry Enrich(LogEntry entry)
        {
            var outbound = entry.Direction != "RECEIVE";
            var far = outbound ? entry.DstIP : entry.SrcIP;

            // The far side's name: the lookup that returned this address (a fact; outgoing only,
            // a lookup is what precedes connecting out), else the DNS cache, else a guess from
            // the address range (marked "?").
            if (outbound && _lookupsByAddress.TryGetValue(far, out var lookups)
                && lookups.FirstOrDefault(l => l.Time <= entry.Ts.AddSeconds(2)) is { } hit)
            {
                entry.Resolved          = hit.Name;
                entry.ResolvedSource    = "lookup";
                entry.LookupTime        = hit.Time;
                entry.LookupBy          = hit.Program.Length == 0 ? "" : hit.Services.Length > 0 ? $"{hit.Program} ({hit.Services})" : hit.Program;
                entry.LookupSameProgram = entry.ProcessId > 0 && hit.ProcessId == entry.ProcessId;
            }
            else if (_dnsMap.TryGetValue(far, out var cached))
            {
                entry.Resolved = cached;
                entry.ResolvedSource = "cache";
            }
            else
            {
                entry.Resolved = OrgTag(far);
                entry.ResolvedSource = entry.Resolved.Length > 0 ? "guess" : "";
            }

            if (!_localityCache.TryGetValue(far, out var where))
                _localityCache[far] = where = NetworkLocality.Classify(far);
            entry.Locality    = where.Kind;
            entry.LocalityTip = where.Tip;
            // DNS tripwire, outgoing only (DNS this machine answers is an ordinary connection):
            // expected when a switched-on rule of yours allows exactly this connection, flagged
            // otherwise. The DNS servers in Windows' network settings don't count: they aren't
            // firewall rules. Until a rule says which DNS is acceptable, all DNS is unexpected.
            // A rule that lets a program do its own DNS is your call, so that DNS isn't flagged.
            // An indicator only: it marks the row and never acts (no rules, no blocks), so a
            // misjudged flag costs a look, never a rule. DNS sent to a loopback address never
            // leaves the machine: a note only, and loopback noise like any loopback row.
            var ownDnsRule = false;
            var dnsPort = outbound && entry.DstPort is ("53" or "853");
            if (dnsPort && where.Kind == "Loopback")
                (entry.DnsWarnKind, entry.DnsWarn) = (DnsWarnKind.Loopback, "DNS to this machine");
            else if (dnsPort)
            {
                var allowing = RulesAllowing(entry, enabled: true);
                entry.DnsByRule = allowing.Count > 0;
                // A rule naming this very program (or service) allows its own DNS on purpose.
                ownDnsRule = allowing.Any(m =>
                    (m.rule.Program.Length > 0 && entry.Program.Length > 0) ||
                    (m.rule.Service.Length > 0 && entry.Services.Length > 0));
                if (!entry.DnsByRule)
                    (entry.DnsWarnKind, entry.DnsWarn) = (DnsWarnKind.Unexpected, "unexpected DNS");
            }

            // Encrypted DNS: HTTPS or DNS-over-TLS to a known encrypted-DNS server, by address or
            // by the name that was looked up. Resolving around your resolver, invisible to port 53.
            if (entry.DnsWarnKind == DnsWarnKind.None && outbound && entry.DstPort is ("443" or "853")
                && (DnsBypass.ServerByAddress(entry.DstIP)
                    ?? ((entry.ResolvedSource is "lookup" or "cache") ? DnsBypass.ServerByName(entry.Resolved) : null))
                   is { } doh)
            {
                (entry.DnsWarnKind, entry.DnsWarn) = (DnsWarnKind.Encrypted, $"encrypted DNS ({doh})");
            }

            // Direct DNS: DNS a rule allows, but not from Windows' DNS client service (svchost.exe
            // with Dnscache), and that rule doesn't name the program. A program sending its own
            // DNS packets: it passes a rule meant for others, yet its lookups never reach the DNS
            // log. Live only (needs the program).
            if (entry.DnsWarnKind == DnsWarnKind.None && dnsPort
                && !ownDnsRule
                && entry.Program.Length > 0 && !entry.ServiceUnknown
                && !(LiveDropSource.ShortProgram(entry.Program).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
                     && entry.Services.Split(',').Any(x => x.Trim().Equals("Dnscache", StringComparison.OrdinalIgnoreCase))))
            {
                (entry.DnsWarnKind, entry.DnsWarn) = (DnsWarnKind.Direct, "direct DNS (not via Windows)");
            }
            // While the DNS log was recording, an outbound connection to an address on another
            // network that no lookup (and no cache entry) explains: the program went straight
            // to the address. DNS itself is left out (it is the lookup).
            entry.NoLookup = outbound
                && entry.ResolvedSource is not ("lookup" or "cache")
                && _dnsCoverFrom.HasValue && entry.Ts >= _dnsCoverFrom.Value
                && (!_dnsCoverTo.HasValue || entry.Ts <= _dnsCoverTo.Value)
                && entry.Locality == "Remote"
                && entry.Protocol is ("TCP" or "UDP")
                && entry.DstPort is not ("53" or "853")
                && !entry.HasDnsMark;

            var (rn, wa, blocked) = MatchRule(entry);
            entry.RuleName = rn;
            entry.IsWouldAllow = wa;
            entry.StillBlockedBy = blocked;
            return entry;
        }

        // ── Process starts (event 4688) ────────────────────────────────────────

        // Starts since the current boot by process ID: read in full with each full read, then
        // read on from where that stopped. Changed only by background work (one at a time);
        // the lock is for the window's thread reading it meanwhile.
        private readonly object _startsGate = new();
        private Dictionary<int, List<ProcessStartLog.Start>> _starts = new();
        private LogCursor? _startsCursor;
        private int _startsVersion;

        private Dictionary<int, List<ProcessStartLog.Start>> Starts(bool fresh = false)
        {
            if (fresh || _startsCursor == null)
            {
                var index = ProcessStartLog.ReadIndex(out var cursor);
                lock (_startsGate) { _starts = index; _startsCursor = cursor; _startsVersion++; }
            }
            else
            {
                var added = ProcessStartLog.ReadOn(_startsCursor);
                if (added.Count > 0)
                    lock (_startsGate) { ProcessStartLog.AddTo(_starts, added); _startsVersion++; }
            }
            return _starts;
        }

        // All starts in time order (for "what started just before"), rebuilt when the index changes.
        private List<ProcessStartLog.Start> _startsFlat = new();
        private int _startsFlatFor = -1;

        // Never reads: the window's thread may ask (Copy for AI), and reading is background work.
        private List<ProcessStartLog.Start> StartsFlat()
        {
            lock (_startsGate)
            {
                if (_startsFlatFor != _startsVersion)
                {
                    _startsFlat = _starts.Values.SelectMany(l => l).OrderBy(x => x.Time).ToList();
                    _startsFlatFor = _startsVersion;
                }
                return _startsFlat;
            }
        }

        private const int StartWindowSeconds = 60;

        // A name without a dot (or any lookup Windows' DNS client makes itself) shows as
        // svchost.exe (Dnscache): the program that asked is hidden. What started in the minute
        // before is the best lead there is.
        private (string Tip, string Compact)? StartedBefore(DateTime time)
        {
            var starts = StartsFlat();
            var boot = ProcessStartLog.BootUtc();
            if (time.ToUniversalTime() < boot)
                return ($"This lookup is from before the machine last started ({boot.ToLocalTime():HH:mm:ss}); only process starts since then are used.", "");
            if (starts.Count == 0)
                return ProcessStartLog.IsOn() == true
                    ? ("No process starts recorded since the machine started, so the program behind Dnscache can't be narrowed down.", "")
                    : ("Process starts aren't recorded (switch them on in Live), so the program behind Dnscache can't be narrowed down.", "");
            if (time < starts[0].Time)
                return ($"The recorded process starts begin at {starts[0].Time:HH:mm:ss}, after this lookup, so they can't say what started before it.", "");

            var from = time.AddSeconds(-StartWindowSeconds);
            var hits = starts.Where(x => x.Time >= from && x.Time <= time.AddSeconds(1))
                             .OrderByDescending(x => x.Time).ToList();
            if (hits.Count == 0)
                return ($"Nothing started in the {StartWindowSeconds} s before the last lookup ({time:HH:mm:ss}): the asker was already running.",
                        "nothing (the asker was already running)");

            // The tooltip shows the names, the compact form goes into Copy for AI.
            static string Who(ProcessStartLog.Start x, Func<string, string> written)
            {
                var file = System.IO.Path.GetFileName(x.Image);
                return written(x.Service.Length > 0 ? $"{file} ({x.Service})"
                             : x.Group.Length > 0 ? $"{file} ({x.Group} group)"
                             : file);
            }
            const int Max = 10;
            var lines = hits.Take(Max).Select(x => $"{x.Time:HH:mm:ss}  {Who(x, NameShown)}").ToList();
            var more = hits.Count > Max ? $"+{hits.Count - Max} more" : "";
            var tip = $"Asked through Windows' DNS client, which hides the program that asked. " +
                      $"Started in the {StartWindowSeconds} s before the last lookup ({time:HH:mm:ss}); the asker may be among them:\n" +
                      string.Join("\n", lines) + (more.Length > 0 ? $"\n{more}" : "");
            var compact = string.Join(", ", hits.Take(Max).Select(x => $"{Who(x, ForAi)} {x.Time:HH:mm:ss}")) + (more.Length > 0 ? $", {more}" : "");
            return (tip, compact);
        }

        // Each connection's process, as it was started: the command line and parent, and for a
        // service host whose service couldn't be looked up live, the service ("-s") or group ("-k").
        // Only a start that surely is this process names it (see ProcessStartLog.At); without
        // one the row says nothing rather than guess.
        private void ApplyProcessStarts(List<LogEntry> entries, bool fresh)
        {
            var index = Starts(fresh);
            if (index.Count == 0) return;
            foreach (var e in entries) ApplyProcessStart(index, e);
        }

        private static void ApplyProcessStart(Dictionary<int, List<ProcessStartLog.Start>> index, LogEntry e)
        {
            if (ProcessStartLog.At(index, e.ProcessId, e.Ts) is not { } st) return;
            // Same program as the connection names, or the ID belonged to another process.
            if (!System.IO.Path.GetFileName(st.Image).Equals(System.IO.Path.GetFileName(e.Program), StringComparison.OrdinalIgnoreCase))
                return;
            e.CommandLine   = st.CommandLine;
            e.ParentProgram = st.Parent;
            e.StartTime     = st.Time;
            if (e.ServiceUnknown)
            {
                if (st.Service.Length > 0)
                {
                    e.Services     = st.Service;
                    e.ServicesLong = $"{st.Service} (from its recorded start at {st.Time:HH:mm:ss})";
                }
                else e.ServiceGroup = st.Group;
            }
        }

        // A lookup whose program had ended: name it from its recorded start, if there is one.
        private List<DnsClientLog.Lookup> NameEndedLookups(List<DnsClientLog.Lookup> lookups)
        {
            if (!lookups.Any(l => l.Program.Length == 0)) return lookups;
            var index = Starts();
            if (index.Count == 0) return lookups;
            return lookups.Select(l =>
                l.Program.Length == 0 && ProcessStartLog.At(index, l.ProcessId, l.Time) is { } st
                    ? l with { Program = System.IO.Path.GetFileName(st.Image), Services = st.Service }
                    : l).ToList();
        }

        // ── Join with Windows' DNS client log ──────────────────────────────────

        private readonly Dictionary<string, List<DnsClientLog.Lookup>> _lookupsByAddress = new(StringComparer.OrdinalIgnoreCase);
        private List<DnsClientLog.Lookup> _joinLookups = new();
        private DateTime? _dnsCoverFrom, _dnsCoverTo;
        private static readonly TimeSpan LookupGrace = TimeSpan.FromMinutes(5);

        // Lookups from a while before the scope (a program connects some time after it looked
        // up), indexed by every address they returned, newest first. "No lookup" is only said
        // for connections the log covers: from its oldest lookup read (plus a grace period, for
        // answers cached just before it started) to now if it is on, else its newest lookup.
        private void BuildLookupJoin(DateTime? since)
        {
            _lookupsByAddress.Clear();
            _joinLookups = new();
            _dnsCoverFrom = _dnsCoverTo = null;
            _dnsCursor = DnsClientLog.Cursor();                        // before the read: following starts here
            _dnsLastId = 0;

            var (oldest, newest) = DnsClientLog.Coverage();
            if (oldest == null) return;                                // empty, or can't be read

            var from = since?.AddHours(-6);
            List<DnsClientLog.Lookup> list;
            try { list = NameEndedLookups(DnsClientLog.Read(from, out _dnsLastId)); } catch { return; }

            foreach (var l in list)
            {
                if (l.Status != 0) continue;
                foreach (var a in l.Addresses)
                {
                    if (!_lookupsByAddress.TryGetValue(a, out var bucket)) _lookupsByAddress[a] = bucket = new();
                    bucket.Add(l);                                     // stays newest first
                }
            }
            _joinLookups = since.HasValue ? list.Where(l => l.Time >= since.Value).ToList() : list;

            var start = oldest.Value;
            if (from.HasValue && from.Value > start) start = from.Value;              // older ones not read
            if (DnsClientLog.LastReadTruncated && list.Count > 0 && list[^1].Time > start) start = list[^1].Time;
            _dnsCoverFrom = start + LookupGrace;
            _dnsCoverTo   = DnsClientLog.IsOn() == true ? DateTime.Now.AddMinutes(1) : newest?.AddMinutes(1);
        }

        // Following: lookups written since, joined like the ones read, before the new rows are
        // named (a program looks up first, then connects).
        private LogCursor? _dnsCursor;
        private long _dnsLastId;

        private void JoinNewLookups(DateTime? since)
        {
            if (_dnsCursor == null) return;
            List<DnsClientLog.Lookup> fresh;
            try { fresh = NameEndedLookups(DnsClientLog.ReadOn(_dnsCursor)).Where(l => l.RecordId > _dnsLastId).ToList(); }
            catch { return; }
            if (fresh.Count == 0) return;
            _dnsLastId = fresh.Max(l => l.RecordId);

            foreach (var l in Enumerable.Reverse(fresh))                // oldest first: each bucket stays newest first
            {
                if (l.Status != 0) continue;
                foreach (var a in l.Addresses)
                {
                    if (!_lookupsByAddress.TryGetValue(a, out var bucket)) _lookupsByAddress[a] = bucket = new();
                    bucket.Insert(0, l);
                }
            }
            _joinLookups = fresh.Where(l => !since.HasValue || l.Time >= since.Value).Concat(_joinLookups).ToList();
            if (_dnsCoverFrom.HasValue && DnsClientLog.IsOn() == true) _dnsCoverTo = DateTime.Now.AddMinutes(1);
        }

        // ── Source switch ─────────────────────────────────────────────────────

        private void BtnSourceFile_Click(object s, RoutedEventArgs e)
        {
            if (!_live) return;
            SetSource(live: false);
            LiveHint.Visibility = LiveDropSource.DropAuditingOn() == true ? Visibility.Collapsed : Visibility.Visible;
        }

        private void BtnSourceLive_Click(object s, RoutedEventArgs e) => TryEnterLive();

        // Switches to Live if drop auditing is on or the user agrees to turn it on.
        private bool TryEnterLive()
        {
            if (_live) return true;

            var state = LiveDropSource.DropAuditingOn();
            if (state != true)
            {
                var ask = HueConfirm.Ask(this, "Turn on drop auditing?",
                    "Live mode reads blocked connections from the Security log, the moment they happen, " +
                    "with the program that tried. Windows only records them while the " +
                    "\"Filtering Platform Connection\" failure audit is on — a system-wide setting.\n\n" +
                    "Only blocked connections are recorded, not allowed ones. It keeps recording after the " +
                    "app closes; closing the app asks whether to switch it off again.",
                    "Turn on");
                if (!ask) return false;

                if (!LiveDropSource.SetDropAuditing(true))
                {
                    ThemedDialog.Info(this, "Could not turn on auditing",
                        (LiveDropSource.AuditpolMissing ?? "auditpol refused the change.") + " Live mode needs the \"Filtering Platform Connection\" " +
                        "failure audit.", danger: true);
                    return false;
                }
                // Re-read: a Group Policy audit setting can override the local one.
                if (state == false && LiveDropSource.DropAuditingOn() == false)
                {
                    ThemedDialog.Info(this, "Auditing stays off",
                        "Windows kept the audit off after the change, so a Group Policy audit setting is " +
                        "probably overriding the local one. Live mode would stay empty until that policy " +
                        "audits \"Filtering Platform Connection\" failures.", danger: true);
                    return false;
                }
            }

            SetSource(live: true);
            return true;
        }

        // Live mode only: record allowed connections too (the "success" half of the audit).
        private void BtnLiveAllows_Click(object s, RoutedEventArgs e)
        {
            if (LiveDropSource.AllowAuditingOn() == true)
            {
                LiveDropSource.SetAllowAuditing(false);   // switching off is always safe: no question
            }
            else
            {
                if (!HueConfirm.Ask(this, "Record allowed connections too?",
                        "Windows will write an event for every connection this machine is allowed to make — " +
                        "every browser request, update check and background service. The Security log fills " +
                        "quickly, and older security events roll out sooner.\n\n" +
                        "Switch it off again when you're done; closing the app will also offer to.",
                        "Record allows"))
                    return;
                if (!LiveDropSource.SetAllowAuditing(true))
                {
                    ThemedDialog.Info(this, "Could not turn on auditing",
                        LiveDropSource.AuditpolMissing ?? "auditpol refused the change.", danger: true);
                    return;
                }
            }
            UpdateLiveAllowsButton();
            ReadLog();
        }

        // ── DNS log (on demand, offered off on every close) ──────────────────

        private void BtnDnsLog_Click(object s, RoutedEventArgs e)
        {
            var on = DnsClientLog.IsOn();
            if (on == true)
            {
                DnsClientLog.Set(false);                   // switching off is always safe: no question
            }
            else
            {
                var size = DnsClientLog.SizeText();
                if (!HueConfirm.Ask(this, "Record DNS lookups?",
                        "Windows will write an event for every name lookup this machine makes, with the " +
                        "name, the answers and the program that asked. It keeps recording after this app " +
                        "is closed and across restarts, so it can run for a long observation." +
                        (size.Length > 0 ? $" The log keeps about {size}, then overwrites its oldest lookups." : "") +
                        "\n\nEvery close of the app offers to switch it off again.",
                        "Record lookups"))
                    return;
                if (!DnsClientLog.Set(true))
                {
                    ThemedDialog.Info(this, "Could not turn on the DNS log",
                        "Windows refused to enable the DNS client log.", danger: true);
                    return;
                }
            }
            UpdateDnsLogButton();
        }

        // ── Process starts (on demand, offered off on every close) ─────────────

        private void BtnProcStarts_Click(object s, RoutedEventArgs e)
        {
            if (ProcessStartLog.IsOn() == true)
            {
                ProcessStartLog.Disable();                  // switching off is always safe: no question
            }
            else
            {
                var (mem, threshold, split) = ProcessStartLog.SplitInfo();
                var names = split
                    ? $"This PC: {mem:0.#} GB, split threshold {threshold:0.#} GB → each service runs in its own host: service names will be exact."
                    : $"This PC: {mem:0.#} GB, split threshold {threshold:0.#} GB → services share hosts: only the service group can be named.";
                if (!HueConfirm.Ask(this, "Record process starts?",
                        "Windows will write an event for every program that starts, with its command line, so a " +
                        "service host that has already ended can still be named — also the ones started at boot.\n\n" +
                        names + "\n\n" +
                        "Cost: every program's command line lands in the Security log, readable by administrators, " +
                        "including anything a script passes as an argument.\n\n" +
                        "It keeps recording after the app closes and across restarts: arm it before a reboot to record " +
                        "the start of Windows. Closing the app asks whether to switch it off.",
                        "Record starts"))
                    return;
                if (!ProcessStartLog.Enable())
                {
                    ThemedDialog.Info(this, "Could not turn on process starts",
                        LiveDropSource.AuditpolMissing ?? "Windows refused the change (auditpol or the command-line setting).", danger: true);
                }
                else if (ProcessStartLog.IsOn() == false)
                {
                    ThemedDialog.Info(this, "Process starts stay off",
                        "Windows kept the audit off after the change, so a Group Policy audit setting is probably " +
                        "overriding the local one.", danger: true);
                }
            }
            UpdateProcStartsButton();
        }

        private void UpdateProcStartsButton()
        {
            var on = ProcessStartLog.IsOn();
            BtnProcStarts.Styled(on == true ? "FilterBtnActive" : "FilterBtn");
            BtnProcStarts.Content = on == true ? "Process starts ✓" : on == null ? "Process starts ?" : "Process starts ✗";
        }

        private void UpdateDnsLogButton()
        {
            var on = DnsClientLog.IsOn();
            BtnDnsLog.Styled(on == true ? "FilterBtnActive" : "FilterBtn");
            BtnDnsLog.Content = on == true ? "DNS log ✓" : on == null ? "DNS log ?" : "DNS log ✗";
        }

        private void UpdateLiveAllowsButton()
        {
            if (!_live) return;
            var on = LiveDropSource.AllowAuditingOn() == true;
            BtnLiveAllows.Styled(on ? "FilterBtnActive" : "FilterBtn");
            IconText.SetText(BtnLiveAllows, on ? "Allows ✓" : "Allows ✗");
        }

        private void SetSource(bool live)
        {
            if (_live != live)
            {
                _talkerMemory.Clear();   // File groups by address, Live by program
                _follow = live;          // Windows writes the file late, in batches: following it is a choice
            }
            _live = live;
            UpdateFollowButton();
            ApplySourceGroups();
            if (live) _serviceWatch.Start(); else _serviceWatch.Stop();
            if (live) LiveHint.Visibility = Visibility.Collapsed;
            UpdateLiveAllowsButton();
            BtnSourceFile.Styled(live ? "FilterBtn" : "FilterBtnActive");
            BtnSourceLive.Styled(live ? "FilterBtnActive" : "FilterBtn");
            ProgramColumn.Visibility = live ? Visibility.Visible : Visibility.Collapsed;
            FilterColumn.Visibility  = live ? Visibility.Visible : Visibility.Collapsed;
            LogPath.Text = live
                ? "Live: Security log — 5157 blocked, 5156 allowed (when recorded) — written the moment they happen"
                : $"Log: {LogFile}";
            ReadLog();
        }

        /// <summary>
        /// The one switch-off question when the app closes, covering whichever of connection
        /// auditing (with process starts), the DNS log and the firewall's text log is asked for
        /// and may be on. An unreadable state counts as on, since switching off what is already
        /// off does no harm.
        /// </summary>
        internal static void OfferLoggingOff(Window owner, bool audit, bool dns, bool textLog)
        {
            bool? success = false, failure = false, dnsOn = false, textBlocked = false, textAllowed = false;
            if (audit)   (success, failure) = LiveDropSource.AuditState();
            if (dns)     dnsOn = DnsClientLog.IsOn();
            if (textLog) (textBlocked, textAllowed) = FirewallTextLog.State();
            var startsOn = audit ? ProcessStartLog.IsOn() : false;     // asked together with the audit

            var askAudit  = audit && !(success == false && failure == false);
            var askDns    = dns && dnsOn != false;
            var askText   = textLog && !(textBlocked == false && textAllowed == false);
            var askStarts = audit && startsOn != false;
            if (!askAudit && !askDns && !askText && !askStarts) return;

            var lines = new System.Collections.Generic.List<string>();
            if (askAudit)
                lines.Add(success == null || failure == null
                    ? "• Connection auditing may be on (its state couldn't be read)."
                    : success == true && failure == true ? "• Connection auditing is on: blocked and allowed connections."
                    : success == true                    ? "• Connection auditing is on: allowed connections."
                                                         : "• Connection auditing is on: blocked connections.");
            if (askDns)
                lines.Add(dnsOn == null
                    ? "• The DNS log may be on (its state couldn't be read)."
                    : "• The DNS log is on: every name lookup.");
            if (askStarts)
                lines.Add(startsOn == null
                    ? "• Process starts may be recorded (the state couldn't be read)."
                    : "• Process starts are recorded, with command lines. Keep it on to record the next start of Windows.");
            if (askText)
                lines.Add(textBlocked == null || textAllowed == null
                    ? "• The firewall's text log may be on (its state couldn't be read)."
                    : "• The firewall's text log is on: " +
                      (textBlocked == true && textAllowed == true ? "blocked and allowed connections."
                       : textBlocked == true ? "blocked connections." : "allowed connections.") +
                      " Live records the same with program names.");

            var count = (askAudit ? 1 : 0) + (askDns ? 1 : 0) + (askText ? 1 : 0) + (askStarts ? 1 : 0);
            var title = count > 1  ? "Switch logging off?"
                      : askAudit   ? "Switch connection auditing off?"
                      : askDns     ? "Switch DNS logging off?"
                      : askStarts  ? "Switch process starts off?"
                                   : "Switch the firewall's text log off?";
            if (ThemedDialog.Confirm(owner, title,
                    string.Join("\n", lines) + "\n\n" +
                    "Windows keeps recording this after the app is closed, and across restarts.\n\n" +
                    "Switch it off now? Keep it on to go on observing (a long watch catches the talkers " +
                    "that only show up now and then), or if something else on this machine relies on it.",
                    "Switch off"))
            {
                if (askAudit && failure != false) LiveDropSource.SetDropAuditing(false);
                if (askAudit && success != false) LiveDropSource.SetAllowAuditing(false);
                if (askDns) DnsClientLog.Set(false);
                if (askStarts) ProcessStartLog.Disable();
                if (askText && textBlocked != false) FirewallTextLog.Set("droppedconnections", false);
                if (askText && textAllowed != false) FirewallTextLog.Set("allowedconnections", false);
            }
        }

        // ── Noise classification (per category; suppress if its category is enabled) ──
        // Predicates come from the effective config (ConfigService); the popup
        // switches (_noise) decide which categories are active. A category without a
        // name has no switch and keeps its own Suppress.

        private bool IsSuppressedNoise(LogEntry e)
        {
            // A DNS warning is an alarm, not noise, and direct DNS a note worth seeing: they
            // always show. DNS to this machine is loopback like any other loopback row.
            if (e.DnsWarnKind is not (DnsWarnKind.None or DnsWarnKind.Loopback)) return false;

            // The categories apply only where the row's address family is switched on.
            var v6 = IsV6(e.DstIP) || IsV6(e.SrcIP);
            if (!(v6 ? _noiseV6 : _noiseV4)) return false;

            // Outgoing DNS that a switched-on rule of yours allows is expected chatter.
            if (_noise.TryGetValue(DnsByRuleNoise, out var dnsOn) && dnsOn && e.DnsByRule)
                return true;

            var ip   = e.DstIP;
            var port = e.DstPort;
            var dst6 = v6 ? V6(ip) : null;
            var src6 = v6 ? V6(e.SrcIP) : null;

            foreach (var c in _noiseDefs)
            {
                bool enabled = !string.IsNullOrEmpty(c.Name) && _noise.TryGetValue(c.Name, out var on) ? on : c.Suppress;
                if (!enabled) continue;

                foreach (var pt in c.Ports) if (port == pt) return true;
                if (v6)
                {
                    // IPv6 entries a category spells out itself ("ff05:") hold as written.
                    if (HoldsV4(c, ip, prefixesOnly: false)) return true;
                    if (c.MatchSource && HoldsV4(c, e.SrcIP, prefixesOnly: true)) return true;
                    if (dst6 != null && HoldsV6(c, dst6, prefixesOnly: false)) return true;
                    if (c.MatchSource && src6 != null && HoldsV6(c, src6, prefixesOnly: true)) return true;
                    continue;   // Broadcast is IPv4 only
                }
                if (HoldsV4(c, ip, prefixesOnly: false)) return true;
                if (c.LocalBroadcast && NetworkLocality.IsBroadcast(ip)) return true;
                if (c.MatchSource && HoldsV4(c, e.SrcIP, prefixesOnly: true)) return true;
            }
            return false;
        }

        // A category's address lists as written (IPv4, or IPv6 spelled out); compared as plain characters.
        private static bool HoldsV4(AppConfig.NoiseCategory c, string ip, bool prefixesOnly)
        {
            foreach (var p in c.IpPrefixes) if (!string.IsNullOrEmpty(p) && ip.StartsWith(p, StringComparison.Ordinal)) return true;
            if (prefixesOnly) return false;
            foreach (var sfx in c.IpSuffixes) if (!string.IsNullOrEmpty(sfx) && ip.EndsWith(sfx, StringComparison.Ordinal)) return true;
            foreach (var ex in c.IpExact)    if (ip == ex) return true;
            return false;
        }

        // IPv6 addresses that play the part of an IPv4 one a category may name.
        private static readonly Dictionary<string, string> V6Groups = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ff02::fb"]  = "224.0.0.251",       // mDNS
            ["ff02::1:3"] = "224.0.0.252",       // LLMNR
            ["ff02::c"]   = "239.255.255.250",   // SSDP and WSD
        };

        // An IPv6 address against a category written in IPv4 terms: ::1 where it holds 127.0.0.1,
        // link-local (fe80::/10) and multicast (ff00::/8) where it holds the whole IPv4 range of
        // that kind, and the three well-known groups where it holds their IPv4 address.
        private static bool HoldsV6(AppConfig.NoiseCategory c, IPAddress a, bool prefixesOnly)
        {
            bool Holds(string v4) => HoldsV4(c, v4, prefixesOnly);
            if (a.Equals(IPAddress.IPv6Loopback)) return Holds("127.0.0.1");
            if (a.IsIPv6LinkLocal) return Holds("169.254.0.0") && Holds("169.254.255.255");
            if (a.IsIPv6Multicast)
                return (Holds("224.0.0.0") && Holds("239.255.255.255"))
                    || (V6Groups.TryGetValue(a.ToString(), out var group) && Holds(group));
            return false;
        }

        private static bool IsV6(string ip) => ip.Contains(':');

        // Without a zone ("fe80::1%12"), so it compares as the address alone.
        private static IPAddress? V6(string ip) =>
            IPAddress.TryParse(ip, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? new IPAddress(a.GetAddressBytes()) : null;

        // ── Local DNS cache resolution (ipconfig /displaydns) — no network egress ──
        //
        // Read by position, not by label: ipconfig prints its labels in the Windows language
        // ("Record Name" / "Eintragsname"), but every record has the same fields in the same
        // order: name, type (a number), time to live, data length, section, data. A blank line
        // ends a record. Aliases (type 5, CNAME) are followed back, so an address is named by
        // what was asked for (api.msn.com), not by the CDN host at the end of the chain.

        private static Dictionary<string, string> BuildDnsCacheMap()
        {
            _dnsCacheMissing = null;
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!WindowsTools.Exists(WindowsTools.Tool.Ipconfig))
                {
                    _dnsCacheMissing = WindowsTools.NotFound(WindowsTools.Tool.Ipconfig, "the DNS cache isn't read");
                    return map;
                }
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.Ipconfig), Arguments = "/displaydns",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                };
                var proc = System.Diagnostics.Process.Start(psi);
                var outp = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(4000);

                var aliasOf = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);   // target → name
                var fields  = new List<string>();

                void Flush()
                {
                    if (fields.Count >= 3 && int.TryParse(fields[1], out var type))
                    {
                        var name = fields[0].TrimEnd('.');
                        var data = fields[^1].Trim().TrimEnd('.');
                        if (type == 5 && data.Length > 0 && !aliasOf.ContainsKey(data))
                            aliasOf[data] = name;
                        else if ((type == 1 || type == 28) && System.Net.IPAddress.TryParse(data, out _)
                                 && !map.ContainsKey(data))
                            map[data] = name;
                    }
                    fields.Clear();
                }

                foreach (var raw in outp.Split('\n'))
                {
                    var line = raw.Trim();
                    var sep = line.IndexOf(" : ", StringComparison.Ordinal);
                    if (sep >= 0) { fields.Add(line[(sep + 3)..].Trim()); continue; }
                    Flush();                                   // blank line, heading or dashes
                }
                Flush();

                // Back through the aliases to the name that was asked for.
                foreach (var ip in map.Keys.ToList())
                {
                    var name = map[ip];
                    for (var hop = 0; hop < 10 && aliasOf.TryGetValue(name, out var asked); hop++) name = asked;
                    map[ip] = name;
                }
            }
            catch { /* cache unavailable (e.g. Dnscache disabled) → empty map, fall back */ }
            return map;
        }

        // ── "Who owns this connection?" — live process attribution via Get-NetTCPConnection ──
        // No age gate: pfirewall.log flushes on an uncontrollable delay, so the row timestamp is
        // not a reliable proxy for whether the connection is still live. The TCP table itself is
        // the arbiter — the query returns the owner if a connection exists, or "nothing live".
        // Asked about the far side, like the rest of the window.

        private const int OwnerTimeoutMs = 6000;
        private bool _ownerLookup;                 // one at a time

        private void LogContextMenu_Opened(object sender, RoutedEventArgs e)
        {
            var entry = LogGrid.CurrentItem as LogEntry;
            if (entry == null || entry.IsMarker)
            {
                MnuWhoOwns.IsEnabled = false;
                MnuWhoOwns.Header    = "Who owns this connection?";
                return;
            }

            if (_ownerLookup)
            {
                MnuWhoOwns.IsEnabled = false;
                MnuWhoOwns.Header    = "Looking up a connection's owner…";
            }
            else if (!string.Equals(entry.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
            {
                MnuWhoOwns.IsEnabled = false;
                MnuWhoOwns.Header    = "Who owns this? (only TCP connections have an owner to look up)";
            }
            else
            {
                MnuWhoOwns.IsEnabled = true;
                MnuWhoOwns.Header    = $"Who owns {FarIp(entry)}?";
            }
        }

        private async void MnuWhoOwns_Click(object sender, RoutedEventArgs e)
        {
            if (_ownerLookup || LogGrid.CurrentItem is not LogEntry { IsMarker: false } entry) return;
            var ip = FarIp(entry);

            // Only a real address goes into the script, and only as data: IPv4 as four plain
            // decimal parts (IPAddress also takes "1.2" or "0x7f.1"), IPv6 in plain ASCII.
            string? address = null;
            if (Ipv4Scope.TryAddress(ip, out var v4, out _))
                address = Ipv4Scope.Text(v4);
            else if (ip.All(c => TextHygiene.IsPlainAscii(c)) && IPAddress.TryParse(ip, out var parsed)
                     && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                address = parsed.ToString();
            if (address == null)
            {
                ThemedDialog.Info(this, "Connection owner", $"Not an IP address, so nothing was looked up:\n{ip}", danger: true);
                return;
            }

            var script =
                $"$address = {PsData.One(address)}\n" +
                "$found = @(Get-NetTCPConnection -RemoteAddress $address -ErrorAction SilentlyContinue)\n" +
                "$found | Select-Object RemoteAddress,RemotePort,State,OwningProcess," +
                "@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}," +
                "@{N='Path';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} | Format-List";

            _ownerLookup = true;
            try
            {
                var clock = Stopwatch.StartNew();
                var (ok, output) = await Task.Run(() => PolicyApply.RunPowerShell(script, OwnerTimeoutMs));
                if (_closed) return;
                if (!ok && clock.ElapsedMilliseconds >= OwnerTimeoutMs)
                {
                    ThemedDialog.Info(this, $"Connection owner — {ip}", "No answer within 6 seconds.", danger: true);
                    return;
                }
                if (!ok)
                {
                    ThemedDialog.Info(this, $"Connection owner — {ip}",
                        output.Trim().Length > 0 ? $"Lookup failed: {output.Trim()}" : "Lookup failed; PowerShell gave no reason.", danger: true);
                    return;
                }

                var body = string.IsNullOrWhiteSpace(output)
                    ? $"No live TCP connection to {ip} right now.\n\n" +
                      "It may have already closed, or (if this was a DROP) was blocked before it connected."
                    : output.Trim();
                ThemedDialog.Info(this, $"Connection owner — {ip}", body, monospace: true);
            }
            catch (Exception ex)
            {
                ThemedDialog.Info(this, "Connection owner", $"Lookup failed: {ex.Message}", danger: true);
            }
            finally { _ownerLookup = false; }
        }

        // Coarse org tag by address range, from config; the tags end in '?' because a range is a guess.
        // The config is looked up once per read (ReadAll, ReadNew), not for every row.
        private List<AppConfig.OrgTag> _orgTags = new();

        private string OrgTag(string ip)
        {
            foreach (var t in _orgTags)
                foreach (var p in t.Prefixes)
                    if (!string.IsNullOrEmpty(p) && ip.StartsWith(p, StringComparison.Ordinal))
                        return t.Tag;
            return "";
        }
    }
}
