using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using BusyOverlayKit;
using HueThemeKit;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>What the session guard did. See <see cref="MergeOffGuard.RunAsync(Window, BusyOverlay, Action{bool}, GuardChange, IReadOnlyList{ProfileAfter}, Action)"/> for what the caller does next.</summary>
    internal enum MergeOffResult
    {
        /// <summary>The change can't cut a Remote Desktop session (see RunAsync): the caller writes it as usual.</summary>
        NotNeeded,
        /// <summary>The operator states direct access to the machine: the caller writes as usual, no rule, no failsafe.</summary>
        WithoutRule,
        /// <summary>The rule is written, the change is written and applied, Keep was clicked. Nothing left to write.</summary>
        Kept,
        /// <summary>The saved state was put back (no Keep, Keep too late, a refused rule, or a failure part way): all as it was.</summary>
        PutBack,
        /// <summary>Cancelled by the operator: nothing was changed.</summary>
        Cancelled,
        /// <summary>Nothing was changed, for the reason in the message.</summary>
        Refused,
    }

    /// <param name="Message">One status line for the caller; empty for NotNeeded and WithoutRule.</param>
    /// <param name="Error">Show the message as a problem.</param>
    /// <param name="Detail">The policy check's details, for the status line's tooltip.</param>
    /// <param name="Shown">The guard already showed the message in a dialog of its own: the caller needn't repeat it there.</param>
    internal sealed record MergeOffOutcome(MergeOffResult Result, string Message, bool Error, string? Detail = null, bool Shown = false)
    {
        /// <summary>True when the caller writes the change itself, its usual way.</summary>
        public bool CallerMergesOff => Result is MergeOffResult.NotNeeded or MergeOffResult.WithoutRule;
    }

    /// <summary>
    /// The change the guard stands in front of; it decides the wording, not the facts.
    /// LockDown and RuleRemoved have their own entries (LockDownLastChance, RuleRemovalAsync).
    /// </summary>
    internal enum GuardChange { MergeOff, InboundBlock, FirewallOn, StartupMove, LockDown, RuleRemoved, OutboundBlock }

    /// <summary>
    /// One profile ("Domain", "Private" or "Public") and the policy values it holds once the
    /// change is written; null = not changed by it. EnableFirewall 1 = on, DefaultInboundAction
    /// 1 = block, AllowLocalPolicyMerge 0 = merge off, DefaultOutboundAction 1 = block.
    /// </summary>
    internal sealed record ProfileAfter(string Profile, int? EnableFirewall, int? DefaultInboundAction, int? AllowLocalPolicyMerge,
                                        int? DefaultOutboundAction = null);

    /// <summary>
    /// A change to the app's own rules: <paramref name="Removed"/> are the CUSTOM_ value names
    /// switched off, deleted or replaced; <paramref name="After"/> what is written in their place
    /// (value name → the new rule; a null rule, or a name not in it, = deleted).
    /// </summary>
    internal sealed record RuleRemoval(IReadOnlyCollection<string> Removed, IReadOnlyDictionary<string, string?>? After = null);

    /// <summary>The words for one change, so every dialog and status line names it the same way.</summary>
    internal sealed record GuardWords(string Change, string Done, string State, string NotChanged, string Act,
                                      string CancelButton, string Drop, string Backup)
    {
        public static GuardWords Of(GuardChange change) => change switch
        {
            GuardChange.MergeOff => new("Merge off", "Local merge off", "merge is off", "Merge not changed", "merge off", "Cancel",
                "Count on this session dropping the moment merge goes off.", "before-merge-off"),
            GuardChange.InboundBlock => new("Inbound block", "Inbound blocked", "inbound is blocked", "Inbound not changed", "block inbound", "Cancel",
                "Count on this session dropping the moment inbound goes to block.", "before-inbound-block"),
            GuardChange.FirewallOn => new("Firewall on", "Firewall on", "the firewall is on", "Firewall not changed", "turn the firewall on", "Cancel",
                "Count on this session dropping the moment the firewall goes on.", "before-firewall-on"),
            GuardChange.StartupMove => new("Moving these values", "Start-up values moved", "the values are moved", "Nothing written", "move",
                "CLOSE APP: NOTHING IS WRITTEN, NOT EVEN WHAT I AGREED TO",
                "Count on this session dropping the moment these values move.", "before-startup-move"),
            GuardChange.LockDown => new("Lock down", "Locked down", "the lock-down is in place", "Not locked down", "lock down", "Cancel",
                "Count on this session dropping the moment the lock-down applies.", "before-lockdown"),
            GuardChange.RuleRemoved => new("Removing this rule", "Rule removed", "the rule is gone", "Rule not changed", "remove the rule", "Cancel",
                "Count on this session dropping the moment the rule goes.", "before-rule-removal"),
            _ => new("Outbound block", "Outbound blocked", "outbound is blocked", "Outbound not changed", "block outbound", "Cancel",
                "Count on this session dropping the moment outbound goes to block.", "before-outbound-block"),
        };
    }

    /// <summary>
    /// With the firewall on, inbound blocked and merge off, only the operator's own rules let
    /// anything in: Windows' Remote Desktop rule no longer counts. Over Remote Desktop, with no
    /// rule of the app letting the client in, a change that ends there cuts the session the
    /// operator is working in, the one thing a tired operator can't undo from where they sit.
    /// So before such a change this offers to write a rule for the client first, with Lock
    /// down's failsafe, and makes going on without one a deliberate, spelled-out statement
    /// (LastChanceWindow). It fires only on those facts; anything else goes through untouched.
    /// </summary>
    internal static class MergeOffGuard
    {
        // As Setup's Remote Desktop rule: reconnect and Keep within KeepSeconds, else the saved
        // state comes back (this code, or the task after BackstopSeconds if the app is gone).
        // While the rule is written, applied and checked, the task must not fire.
        private const int KeepSeconds = 180, BackstopSeconds = 360, BackstopWhileApplying = 900;

        private const string PolicyRoot = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";
        private static readonly string[] Profiles = { "Domain", "Private", "Public" };
        private static readonly string[] Values = { "EnableFirewall", "DefaultInboundAction", "AllowLocalPolicyMerge" };

        // A client no rule of the app lets in, the ports it is connected on, its rule, and what
        // writing it replaces (Lockdown.ReplaceNote: "" or " (replacing …)").
        private sealed record Client(string Address, List<int> Ports, RuleWriter.Spec Rule, string Replaces);

        // The profiles the change leaves cutting; the network clients no rule lets in (null: the
        // connections couldn't be read); the Remote Desktop ports a tunnel arrives on; the VPN or
        // tunnel adapters the session comes in on when the change blocks outbound (null: unreadable).
        private sealed record Facts(List<string> Cutting, List<Client>? Open, List<int> Tunnel, List<string>? Vpn);

        /// <summary>
        /// Merge off on all three profiles, with <paramref name="mergeOff"/> as the write: the
        /// general entry with <see cref="GuardChange.MergeOff"/>.
        /// </summary>
        public static Task<MergeOffOutcome> RunAsync(Window owner, BusyOverlay busy, Action<bool> lockContent, Action mergeOff,
                                                     Action? refresh = null) =>
            RunAsync(owner, busy, lockContent, GuardChange.MergeOff,
                     Profiles.Select(p => new ProfileAfter(p, null, null, 0)).ToList(), mergeOff, refresh);

        /// <summary>
        /// Call on the UI thread, right before the caller would write the change. It fires only
        /// when all of these hold: a profile in <paramref name="after"/> ends up with the firewall
        /// on, inbound blocked and merge off (values not in <paramref name="after"/> as they are
        /// in policy now; not set = what Windows then applies; unreadable = the value that cuts);
        /// this is a remote session; and a Remote Desktop client is connected over the network
        /// that no switched-on rule of the app lets in, or the session comes through a tunnel.
        /// Otherwise NotNeeded at once.
        /// <paramref name="lockContent"/>(true/false) switches the caller's content off and back on
        /// around the overlay's runs (keyboard included). <paramref name="write"/> is the caller's
        /// own write of the change: it runs on a worker, must touch no control, and throws if it
        /// fails. It is called only on the rule path; for NotNeeded and WithoutRule the caller
        /// writes itself, as usual. <paramref name="refresh"/>: redraws the caller's display from
        /// what is in force; called on the UI thread on the rule path, once the change is written
        /// and applied and before the Keep countdown opens, so the screen behind it is current.
        /// </summary>
        public static async Task<MergeOffOutcome> RunAsync(Window owner, BusyOverlay busy, Action<bool> lockContent,
                                                           GuardChange change, IReadOnlyList<ProfileAfter> after, Action write,
                                                           Action? refresh = null)
        {
            if (change is GuardChange.LockDown or GuardChange.RuleRemoved)
                throw new ArgumentException($"{change} has its own entry.", nameof(change));
            var words = GuardWords.Of(change);
            // At the console the operator's own session can't be cut, whoever else is connected.
            if (!Lockdown.IsRemoteSession()) return NotNeeded();
            if (change == GuardChange.OutboundBlock) return await OutboundAsync(owner, busy, lockContent, words, after);

            Facts facts;
            lockContent(true);
            try { facts = await busy.RunAsync<Facts>("Reading the Remote Desktop connections", _ => Read(after)); }
            finally { lockContent(false); }

            // In a remote session nothing can be assumed.
            if (facts.Cutting.Count > 0 && facts.Open == null)
                return new(MergeOffResult.Refused,
                    $"{words.NotChanged}: the machine's connections could not be read, so a Remote Desktop session can't be ruled out.", true);
            if (facts.Vpn is not { } vpn)
                return new(MergeOffResult.Refused,
                    $"{words.NotChanged}: the machine's connections could not be read, so a session over a VPN can't be ruled out.", true);
            var open   = facts.Cutting.Count > 0 ? facts.Open! : new List<Client>();
            var tunnel = facts.Cutting.Count > 0 ? facts.Tunnel : new List<int>();
            if (open.Count == 0 && tunnel.Count == 0 && vpn.Count == 0) return NotNeeded();   // e.g. an enhanced session

            // Neither a tunnel's own connection nor a VPN's carrier is seen here, so no rule can be
            // offered for them: without network clients, only the last question.
            if (open.Count == 0)
                return LastChanceWindow.Ask(owner, change, new List<string>(), new List<int>(), tunnel, vpn,
                                            note: change == GuardChange.StartupMove ? StartupReconsider : null)
                    ? new(MergeOffResult.WithoutRule, "", false)
                    : new(MergeOffResult.Cancelled, $"{words.NotChanged}.", false);

            while (true)
            {
                switch (AskFirst(owner, words, change, facts.Cutting, open, tunnel, vpn))
                {
                    case Choice.Rule:
                        return await WithRuleAsync(owner, busy, lockContent, words, write, open, refresh);
                    case Choice.NoRule:
                        if (LastChanceWindow.Ask(owner, change, open.Select(c => c.Address).ToList(),
                                                 open.SelectMany(c => c.Ports).Distinct().OrderBy(p => p).ToList(), tunnel, vpn))
                            return new(MergeOffResult.WithoutRule, "", false);
                        break;   // reconsidered: back to the first question
                    default:
                        return new(MergeOffResult.Cancelled, $"{words.NotChanged}.", false);
                }
            }
        }

        private static MergeOffOutcome NotNeeded() => new(MergeOffResult.NotNeeded, "", false);

        // At start-up there is no first question to go back to: the safe answer closes the app.
        private const string StartupReconsider = "Reconsidering closes the app; nothing is written, not even what you agreed to.";

        // Outbound block cuts no Remote Desktop connection itself, only the program that carries
        // one in over a VPN or tunnel adapter. The app can't know that program, so no rule is
        // offered: only the last question, and only when such an adapter carries the session.
        private static async Task<MergeOffOutcome> OutboundAsync(Window owner, BusyOverlay busy, Action<bool> lockContent,
                                                                 GuardWords words, IReadOnlyList<ProfileAfter> after)
        {
            (bool Blocks, List<string>? Adapters) facts;
            lockContent(true);
            try
            {
                facts = await busy.RunAsync<(bool, List<string>?)>("Reading the Remote Desktop connections", _ =>
                {
                    if (!after.Any(BlocksOut)) return (false, new List<string>());
                    return (true, Lockdown.RdpVpnAdapters(RdpPorts()));
                });
            }
            finally { lockContent(false); }

            if (!facts.Blocks) return NotNeeded();
            if (facts.Adapters is not { } adapters)
                return new(MergeOffResult.Refused,
                    $"{words.NotChanged}: the machine's connections could not be read, so a session over a VPN can't be ruled out.", true);
            if (adapters.Count == 0) return NotNeeded();
            return LastChanceWindow.Ask(owner, GuardChange.OutboundBlock, new List<string>(), new List<int>(), new List<int>(), adapters)
                ? new(MergeOffResult.WithoutRule, "", false)
                : new(MergeOffResult.Cancelled, $"{words.NotChanged}.", false);
        }

        /// <summary>
        /// Before the app's own rules are switched off, deleted, rewritten or switched on. Call on
        /// the UI thread. It fires, in a remote session, when either holds:
        /// a profile has the firewall on, inbound blocked and merge off now (as RunAsync reads
        /// them), and a Remote Desktop client connected over the network is let in now by a
        /// touched rule created in this app (a field that can't be judged counts as letting it in)
        /// and afterwards nothing surely lets it in or a Block may stop it, or a touched Block may
        /// stop it that didn't before; or
        /// a profile blocks outbound now, a touched switched-on outbound Allow goes, and the session
        /// comes in on a VPN or tunnel adapter (whether that rule is the carrier's can't be told).
        /// Then only the last question (PROCEED reads "I AM DONE HERE AND CUT MYSELF OUT"):
        /// WithoutRule, or Cancelled ("Rule not changed."). Otherwise NotNeeded. Unreadable
        /// connections or rules: Refused. A tunnel isn't judged: a rule doesn't touch its loopback
        /// leg. Nothing is written here; the caller writes its change for NotNeeded and WithoutRule only.
        /// </summary>
        public static async Task<MergeOffOutcome> RuleRemovalAsync(Window owner, BusyOverlay busy, Action<bool> lockContent, RuleRemoval removal)
        {
            var words = GuardWords.Of(GuardChange.RuleRemoved);
            if (!Lockdown.IsRemoteSession()) return NotNeeded();

            RemovalFacts facts;
            lockContent(true);
            try { facts = await busy.RunAsync<RemovalFacts>("Reading the Remote Desktop connections", _ => ReadRemoval(removal)); }
            finally { lockContent(false); }

            if (facts.Unreadable is { } what) return new(MergeOffResult.Refused, $"{words.NotChanged}: {what}.", true);
            if (facts.Addresses.Count == 0 && facts.Vpn.Count == 0) return NotNeeded();

            return LastChanceWindow.Ask(owner, GuardChange.RuleRemoved, facts.Addresses, facts.Ports, new List<int>(), facts.Vpn,
                                        rules: facts.Rules, removal: facts.Clause, others: facts.Others)
                ? new(MergeOffResult.WithoutRule, "", false)
                : new(MergeOffResult.Cancelled, $"{words.NotChanged}.", false);
        }

        // The clients the change cuts, their ports, the touched rules that decide it (as the list
        // names them), what happens to those rules ("RDP-51-IN is switched off"), whether other
        // Remote Desktop sessions stay connected (then the cut one may not be the operator's), the
        // VPN or tunnel adapters the session comes in on when a touched outbound allow may be its
        // carrier's; or why nothing can be said.
        private sealed record RemovalFacts(List<string> Addresses, List<int> Ports, List<string> Rules, string Clause, bool Others,
                                           List<string> Vpn, string? Unreadable = null);

        private static RemovalFacts ReadRemoval(RuleRemoval removal)
        {
            var none = new RemovalFacts(new(), new(), new(), "", false, new());
            var cutsIn    = Profiles.Any(p => Cuts(new ProfileAfter(p, null, null, null)));
            var blocksOut = Profiles.Any(p => BlocksOut(new ProfileAfter(p, null, null, null)));
            if (!cutsIn && !blocksOut) return none;

            Dictionary<string, string> now;
            try { now = Lockdown.OwnRules(); }
            catch { return none with { Unreadable = "the rules created in this app could not be read, so a Remote Desktop session can't be ruled out" }; }

            var after = removal.After == null ? null
                : new Dictionary<string, string?>(removal.After, StringComparer.OrdinalIgnoreCase);
            var touched = new HashSet<string>(removal.Removed, StringComparer.OrdinalIgnoreCase);
            if (after != null) touched.UnionWith(after.Keys);
            var then = new Dictionary<string, string>(now, StringComparer.OrdinalIgnoreCase);
            foreach (var name in removal.Removed) then.Remove(name);
            if (after != null)
                foreach (var (name, rule) in after)
                    if (rule == null) then.Remove(name); else then[name] = rule;

            // Inbound: what lets a client in now is touched, or a Block (which beats any Allow) comes
            // in or changes. Outbound: an allow that may be what lets a VPN's carrier out goes.
            var inbound = cutsIn && touched.Any(k => now.TryGetValue(k, out var r) && Lockdown.IsOnInboundAllow(r) ||
                                                     then.TryGetValue(k, out var t) && Lockdown.IsOnInboundBlock(t));
            var outbound = blocksOut && touched.Any(k => now.TryGetValue(k, out var r) && Lockdown.IsOnOutboundAllow(r));
            if (!inbound && !outbound) return none;

            var all = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var cut = new List<(string Address, int Port)>();
            var deciding = new List<string>();
            List<int> tunnel = new();
            List<string> vpn = new();
            try
            {
                var ports = RdpPorts();
                if (inbound)
                {
                    foreach (var port in ports)
                    {
                        if (Lockdown.RdpClients(port) is not { } clients)
                            return none with { Unreadable = "the machine's connections could not be read, so a Remote Desktop session can't be ruled out" };
                        foreach (var client in clients)
                        {
                            all.Add(client);
                            // A touched rule that may let the client in now (a field that can't be
                            // judged counts as matching); afterwards nothing surely lets it in, or a
                            // Block may stop it. A touched Block that may stop it and didn't before cuts it too.
                            var letIn = Lockdown.OwnRulesMayAllowRdp(client, port, now).Where(touched.Contains).ToList();
                            var blocksThen = Lockdown.OwnBlocksMayMatchRdp(client, port, then);
                            var blocksNow = Lockdown.OwnBlocksMayMatchRdp(client, port, now);
                            var newBlocks = blocksThen.Where(k => touched.Contains(k) && !blocksNow.Contains(k, StringComparer.OrdinalIgnoreCase)).ToList();
                            var cutHere = newBlocks.Count > 0 ||
                                          letIn.Count > 0 && (blocksThen.Count > 0 || !Lockdown.OwnRuleAllowsRdp(client, port, then));
                            if (!cutHere) continue;
                            cut.Add((client, port));
                            deciding.AddRange(letIn);
                            deciding.AddRange(newBlocks);
                        }
                    }
                    tunnel = Lockdown.RdpTunnelPorts(ports) ?? new List<int>();
                }
                if (outbound)
                {
                    if (Lockdown.RdpVpnAdapters(ports) is not { } adapters)
                        return none with { Unreadable = "the machine's connections could not be read, so a session over a VPN can't be ruled out" };
                    vpn = adapters;
                    // The app can't tell whether the touched allow is the carrier's: the fact is stated.
                    if (vpn.Count > 0)
                        deciding.AddRange(touched.Where(k => now.TryGetValue(k, out var r) && Lockdown.IsOnOutboundAllow(r)));
                }
            }
            catch { return none with { Unreadable = "the machine's connections could not be read, so a Remote Desktop session can't be ruled out" }; }
            if (cut.Count == 0 && vpn.Count == 0) return none;

            var addresses = cut.Select(c => c.Address).Distinct().ToList();
            deciding = deciding.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            string Shown(string key) => ShownName(key, now.TryGetValue(key, out var r) ? r : then[key]);
            // Deleted, switched off or on, added, or rewritten: each said as it is.
            string What(string key)
            {
                if (after == null || !after.TryGetValue(key, out var rule) || rule == null) return "gone";
                if (!now.TryGetValue(key, out var before)) return "added";
                var on = RuleText.IsOn(rule);
                return on == RuleText.IsOn(before) ? "changed" : on ? "switched on" : "switched off";
            }
            var clause = JoinWords(deciding.GroupBy(What, StringComparer.Ordinal)
                .Select(g => $"{JoinWords(g.Select(Shown).ToList())} {(g.Count() > 1 ? "are" : "is")} {g.Key}")
                .ToList());
            return new RemovalFacts(addresses, cut.Select(c => c.Port).Distinct().OrderBy(p => p).ToList(),
                                    deciding.Select(Shown).ToList(), clause,
                                    Others: all.Count > addresses.Count || tunnel.Count > 0, vpn);
        }

        // The name the rule list shows: its Name field, else the value name, without CUSTOM either way.
        private static string ShownName(string valueName, string rule) =>
            RuleWriter.Plain(
                RuleText.Fields(rule).LastOrDefault(f => f.Key.Equals("Name", StringComparison.OrdinalIgnoreCase)).Value?.Trim() is { Length: > 0 } shown
                    ? shown
                    : valueName);

        /// <summary>
        /// Lock down's own last question, for its tunnel facts (no network client; Lock down can't
        /// write a rule for a tunnel) and/or the VPN fact (the lock-down blocks outbound). Call on
        /// the UI thread; true only for PROCEED. <paramref name="failsafe"/>: Lock down goes on
        /// with its failsafe after PROCEED (then "No failsafe" isn't said). Lock down keeps its
        /// own flow around it.
        /// </summary>
        public static bool LockDownLastChance(Window owner, IReadOnlyList<int> tunnelPorts, IReadOnlyList<string> vpnAdapters, bool failsafe) =>
            LastChanceWindow.Ask(owner, GuardChange.LockDown, new List<string>(), new List<int>(), tunnelPorts, vpnAdapters, failsafe: failsafe);

        // The ports Remote Desktop listens on now, else its setting.
        private static List<int> RdpPorts() =>
            Lockdown.RdpListeningPorts() is { Count: > 0 } listening ? listening : new List<int> { Lockdown.RdpPort() };

        // Which profiles the change leaves cutting; only then, who is connected on the ports the
        // service listens on now (else the setting), which of them no rule of the app lets in,
        // and whether a tunnel arrives on one of those ports.
        private static Facts Read(IReadOnlyList<ProfileAfter> after)
        {
            var cutting = after.Where(Cuts).Select(a => a.Profile).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            // A profile where this change can alter what goes out and that then blocks outbound:
            // also when the block was there already, since firewall on or merge off can end what
            // let the carrier out until now (a VPN client's own local allow rule stops counting
            // with merge off). Inbound alone never touches an outgoing carrier.
            var vpn = after.Where(TouchesOutgoing).Any(BlocksOut)
                ? Lockdown.RdpVpnAdapters(RdpPorts()) : new List<string>();
            if (cutting.Count == 0) return new(cutting, new List<Client>(), new List<int>(), vpn);
            try
            {
                var ports = RdpPorts();
                if (Lockdown.RdpTunnelPorts(ports) is not { } tunnel) return new(cutting, null, new List<int>(), vpn);
                var open = new Dictionary<string, List<int>>();
                foreach (var port in ports)
                {
                    if (Lockdown.RdpClients(port) is not { } clients) return new(cutting, null, tunnel, vpn);
                    foreach (var c in clients.Where(c => !Allowed(c, port)))
                    {
                        if (!open.TryGetValue(c, out var on)) open[c] = on = new List<int>();
                        on.Add(port);
                    }
                }
                var all = open.Keys.ToList();
                return new(cutting, open.Select(o =>
                {
                    var rule = Lockdown.RdpRule(o.Key, o.Value[0], all) with
                    {
                        Ports = o.Value.Select(p => p.ToString(CultureInfo.InvariantCulture)).ToList()
                    };
                    return new Client(o.Key, o.Value, rule, Lockdown.ReplaceNote(rule.Name, o.Key, o.Value[0]));
                }).ToList(), tunnel, vpn);
            }
            catch { return new(cutting, null, new List<int>(), vpn); }
        }

        // Firewall on, inbound block and merge off once the change is written: then only the
        // app's own rules let anything in. A value not set is what Windows then applies (firewall
        // on, inbound block, merge on); one that can't be read counts as the one that cuts.
        private static bool Cuts(ProfileAfter a)
        {
            var firewall = a.EnableFirewall        ?? Current(a.Profile, "EnableFirewall");
            var inbound  = a.DefaultInboundAction  ?? Current(a.Profile, "DefaultInboundAction");
            var merge    = a.AllowLocalPolicyMerge ?? Current(a.Profile, "AllowLocalPolicyMerge");
            return firewall != 0 && inbound != 0 && (merge == 0 || merge == Unreadable);
        }

        // Outbound blocked once the change is written: firewall on and outbound block. Not set is
        // Windows' default (firewall on, outbound allow); a value that can't be read counts as the one that cuts.
        private static bool BlocksOut(ProfileAfter a)
        {
            var firewall = a.EnableFirewall        ?? Current(a.Profile, "EnableFirewall");
            var outbound = a.DefaultOutboundAction ?? Current(a.Profile, "DefaultOutboundAction");
            return firewall != 0 && outbound is not null and not 0;
        }

        // The change sets a value that can change what goes out: firewall on, outbound block, merge off.
        private static bool TouchesOutgoing(ProfileAfter a) =>
            a.EnableFirewall is { } f && f != 0 || a.DefaultOutboundAction is { } o && o != 0 || a.AllowLocalPolicyMerge == 0;

        private const int Unreadable = int.MinValue;

        // The policy value as it stands: null when not set, Unreadable when it can't be read.
        private static int? Current(string profile, string value)
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"{PolicyRoot}\{profile}Profile");
                return k?.GetValue(value) switch { null => null, int i => i, _ => Unreadable };
            }
            catch { return Unreadable; }
        }

        // Rules that can't be read let nobody in, as far as anyone can tell.
        private static bool Allowed(string client, int port)
        {
            try { return Lockdown.OwnRuleAllowsRdp(client, port); }
            catch { return false; }
        }

        private enum Choice { Cancel, Rule, NoRule }

        // "Remote Desktop reaches this machine through a tunnel: …", or "".
        internal static string TunnelFact(IReadOnlyList<int> tunnel) =>
            tunnel.Count == 0 ? "" :
            $"Remote Desktop reaches this machine through a tunnel: a connection from this machine itself on " +
            $"{(tunnel.Count == 1 ? "port" : "ports")} {JoinWords(tunnel.Select(p => p.ToString(CultureInfo.InvariantCulture)).ToList())}.";

        // "Your Remote Desktop connection comes in over a VPN or tunnel adapter (…). …" (owner's wording).
        internal static string VpnFact(IReadOnlyList<string> adapters, GuardChange change) =>
            $"Your Remote Desktop connection comes in over a VPN or tunnel adapter ({JoinWords(adapters)}). " +
            (change == GuardChange.LockDown
                ? "The lock-down blocks outbound, which ends the program that carries it unless a rule lets it out."
                : "Outbound block ends the program that carries it unless a rule lets it out.");

        // The firewall doesn't filter the loopback leg; the leg a change can cut comes in from the
        // network, and which connection that is (SSH, a VPN) isn't seen from here.
        internal const string TunnelNoRule = "The tunnel's own connection comes in from the network; whether anything still lets it in after this change can't be told here.";

        // Three plain answers, none on Enter; Esc and closing the window cancel.
        private static Choice AskFirst(Window owner, GuardWords words, GuardChange change, List<string> cutting, List<Client> open,
                                       List<int> tunnel, List<string> vpn)
        {
            var many = open.Count > 1;
            var from = JoinWords(open.Select(c => c.Address).ToList());
            string Line(Client c) => $"{c.Rule.Name}{c.Replaces}, " +
                                     $"TCP {JoinWords(c.Ports.Select(p => p.ToString(CultureInfo.InvariantCulture)).ToList())}";
            var message =
                $"You are connected over Remote Desktop from {from}. {words.Change} leaves {JoinWords(cutting)} with the firewall on, " +
                "inbound blocked and merge off, " +
                (many
                    ? $"and nothing of yours created in this app lets these addresses in. A rule for each is written first, Remote Desktop service only: {string.Join("; ", open.Select(Line))}."
                    : $"and nothing of yours created in this app lets this address in. A rule for it is written first: {Line(open[0])}, Remote Desktop service only.") +
                (tunnel.Count > 0 ? $"\n\n{TunnelFact(tunnel)} {TunnelNoRule}" : "") +
                (vpn.Count > 0 ? $"\n\n{VpnFact(vpn, change)} The {(many ? "rules" : "rule")} written here only {(many ? "let" : "lets")} the address in; it doesn't let that program out." : "") +
                "\n\n" +
                $"With the {(many ? "rules" : "rule")}, the current state is saved first. Then you reconnect within {KeepSeconds} s " +
                "and click Keep, or the firewall is put back as it was.";

            var dialog = new Window
            {
                Title = $"{words.Change} over Remote Desktop",
                Owner = owner,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                ShowInTaskbar = false,
                Width = 600,
                SizeToContent = SizeToContent.Height,
                ResizeMode = ResizeMode.NoResize,
            };
            dialog.SetResourceReference(FrameworkElement.StyleProperty, "Hue.Window");
            HueTitleBar.Attach(dialog);

            var stack = new StackPanel { Margin = new Thickness(22, 18, 22, 18) };
            stack.Children.Add(new TextBlock { Text = dialog.Title, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) }
                .Styled("Text.Heading").Ref(TextBlock.ForegroundProperty, "Brush.ErrorText"));
            // A long message scrolls inside a capped area, so the buttons never leave the screen.
            var scroll = new ScrollViewer
            {
                Content = new TextBlock { Text = message }.Styled("Text.Body"),
                MaxHeight = HueConfirm.MessageMaxHeight(owner),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                IsTabStop = false,
                Margin = new Thickness(0, 0, 0, 10)
            };
            scroll.ScrollChanged += (_, _) => scroll.IsTabStop = scroll.ScrollableHeight > 0;
            stack.Children.Add(scroll);

            // Wraps, so a long button (the start-up's CLOSE APP) takes a line of its own.
            var answer = Choice.Cancel;
            var row = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(-8, 0, 0, 0) };
            void Add(string text, Choice choice, string? style, bool cancel = false)
            {
                var b = new Button { Content = text, IsCancel = cancel, Margin = new Thickness(8, 8, 0, 0) };
                if (style != null) b.Styled(style);
                b.Click += (_, _) => { answer = choice; dialog.Close(); };
                row.Children.Add(b);
            }
            Add($"Write the {(many ? "rules" : "rule")} and {words.Act}", Choice.Rule, "Hue.Button.Primary");
            Add("NO RULE", Choice.NoRule, "Hue.Button.Danger");
            Add(words.CancelButton, Choice.Cancel, null, cancel: true);
            stack.Children.Add(row);

            dialog.Content = stack;
            dialog.ShowDialog();
            return answer;
        }

        // Lock down's order: save, arm the task, write the rules, write the change, apply and
        // check, then the countdown. The work runs on the overlay's worker and touches no control.
        private static async Task<MergeOffOutcome> WithRuleAsync(Window owner, BusyOverlay busy, Action<bool> lockContent,
                                                                 GuardWords words, Action write, List<Client> open, Action? refresh)
        {
            // The restore needs the firewall's own export and import; without netsh there is none.
            if (WindowsTools.NotFound(WindowsTools.Tool.Netsh, "the firewall state can't be saved and put back, so nothing was changed") is { } noNetsh)
                return new(MergeOffResult.Refused, $"{words.NotChanged}: {noNetsh}.", true);
            // Without schtasks there is no failsafe task, and no answer about one still armed.
            if (WindowsTools.NotFound(WindowsTools.Tool.Schtasks, "the failsafe task can't be armed, so nothing was changed") is { } noSchtasks)
                return new(MergeOffResult.Refused, $"{words.NotChanged}: {noSchtasks}.", true);

            var many  = open.Count > 1;
            var from  = JoinWords(open.Select(c => c.Address).ToList());
            var names = string.Join(", ", open.Select(c => c.Rule.Name));
            var backstopAt = DateTime.Now.AddSeconds(BackstopWhileApplying);
            string? snapshot = null, notChanged = null, failedPartWay = null, valuesAfter = null;
            bool armedBefore = false, armedUnsure = false;
            var written = new Dictionary<string, string?>();   // name → the rule as written
            PolicyApply.Result? check = null;
            Lockdown.PutBackResult? undo = null;

            lockContent(true);
            try
            {
                await busy.RunAsync<object?>($"{words.Change} with a Remote Desktop rule", async report =>
                {
                    // Arming replaces a task of the same name: one still armed would lose its saved
                    // state. One that may be there (no clear answer) is refused the same way.
                    if (Lockdown.BackstopState() is var there && there != false) { armedBefore = true; armedUnsure = there == null; return null; }

                    report.Say("Saving the current state…");
                    try { snapshot = Lockdown.Snapshot(words.Backup).Reg; }
                    catch (Exception ex) { notChanged = $"{words.NotChanged}: the current state could not be saved ({ex.Message.TrimEnd('.')})."; return null; }

                    report.Say("Arming the failsafe…");
                    try { Lockdown.ArmBackstop(snapshot, backstopAt); }
                    catch (Exception ex)
                    {
                        // A creation that timed out may have left the task anyway: it would put
                        // the saved state back over whatever is done meanwhile.
                        notChanged = $"{words.NotChanged}: {ex.Message.TrimEnd('.')}." +
                                     (Lockdown.DisarmBackstop() ? "" :
                                      $" The failsafe task may exist anyway and could not be confirmed removed: if \"{Lockdown.BackstopTask}\" " +
                                      $"is in Task Scheduler, delete it, or it puts the saved state back at {backstopAt:HH:mm:ss}.");
                        return null;
                    }

                    try
                    {
                        // The rules first, so the change never stands without them.
                        report.Say(many ? "Writing the rules…" : "Writing the rule…");
                        foreach (var c in open) RuleWriter.Write(c.Rule);
                        report.Say($"Writing the change ({words.Change.ToLowerInvariant()})…");
                        write();
                        report.Say("Applying the policy (gpupdate) and checking that the firewall applies it…");
                        check = await PolicyApply.RunAsync($"{words.Done}, {names} for Remote Desktop from {from}",
                                                           open.Select(c => RuleWriter.KeyFor(c.Rule.Name)));
                        // Read once gpupdate is done: a Group Policy may rewrite a value there, and
                        // only a change after this point means the failsafe task put the old state back.
                        foreach (var c in open) written[c.Rule.Name] = RuleValue(c.Rule.Name);
                        valuesAfter = PolicyValues();
                    }
                    catch (Exception ex)
                    {
                        // Anything unforeseen once writing began: the saved state goes back in the same run.
                        failedPartWay = $"{words.Change} failed part way ({ex.Message.TrimEnd('.')})";
                        undo = await Lockdown.PutBackAsync(snapshot, failedPartWay, backstopArmed: true, t => report.Say(t));
                    }
                    return null;
                });

                if (armedBefore)
                {
                    var text = armedUnsure
                        ? $"{words.NotChanged}: whether the failsafe task \"{Lockdown.BackstopTask}\" is still armed from an earlier " +
                          "lock-down or rule can't be told (Task Scheduler gave no clear answer), so it isn't replaced. Nothing was written."
                        : $"{words.NotChanged}: the failsafe task \"{Lockdown.BackstopTask}\" is still armed from an earlier " +
                          "lock-down or rule, so it isn't replaced. Nothing was written.";
                    ThemedDialog.Info(owner, "Failsafe task still armed", text, danger: true);
                    return new(MergeOffResult.Refused, text, true, Shown: true);
                }
                if (notChanged != null) return new(MergeOffResult.Refused, notChanged, true);
                if (failedPartWay != null) return PutBack(undo!, snapshot!, failedPartWay);

                // From here the rule and the change are live with the task armed: whatever goes
                // wrong, the saved state goes back, never an exception that leaves them in place.
                var armed = true;
                string why;
                try
                {
                    var applied = check!;
                    var ours = open.Select(c => RuleWriter.KeyFor(c.Rule.Name)["CUSTOM_".Length..]).ToList();
                    var refused = applied.Rejected?.Where(r => ours.Contains(r, StringComparer.OrdinalIgnoreCase)).ToList() ?? new List<string>();
                    if (refused.Count > 0)
                        // A rule Windows didn't load lets nobody in: nothing to test, nothing to keep.
                        why = $"{words.Change} not kept: Windows refused {JoinWords(refused)}";
                    else
                    {
                        // The countdown starts now, so the task moves to now as well. If moving
                        // fails, it stays armed at its first time.
                        var moved = DateTime.Now.AddSeconds(BackstopSeconds);
                        try { await Task.Run(() => Lockdown.ArmBackstop(snapshot!, moved)); backstopAt = moved; }
                        catch { }

                        var situation = $"You are connected over Remote Desktop from {from}. The {(many ? "rules are" : "rule is")} in place and {words.State}.\n\n" +
                            (applied.InForce
                                ? "Disconnect and reconnect now. If the new connection works, click Keep."
                                : $"{applied.Summary}\n\n" +
                                  (applied.Problem != null ? "Whether the firewall applies it couldn't be checked" : "The firewall doesn't apply all of it yet") +
                                  $", so a reconnect now may not test the {(many ? "rules" : "rule")}.");
                        // The screen behind the countdown shows what is in force. Only a redraw: if it
                        // fails, the firewall is as written, so it is no reason to put anything back.
                        try { refresh?.Invoke(); } catch { }
                        var win = new LockdownCountdownWindow(owner, situation, KeepSeconds, backstopAt,
                                                              heading: many ? "Keep the rules?" : "Keep the rule?", closing: null);
                        win.ShowDialog();

                        if (win.Kept)
                        {
                            var state = await Task.Run(Lockdown.RemoveBackstop);
                            var gone = state == false;
                            armed = !gone;
                            if (written.Any(w => RuleValue(w.Key) != w.Value) || PolicyValues() != valuesAfter)
                            {
                                const string late = "Keep came too late: the failsafe had already put the firewall back as it was.";
                                ThemedDialog.Info(owner, words.Change, late, danger: true);
                                return new(MergeOffResult.PutBack, late, true, Shown: true);
                            }
                            if (!gone)
                            {
                                var left = state == null
                                    ? $"{names} kept and {words.State}, but whether the failsafe task is gone couldn't be told (Task Scheduler gave no clear answer). " +
                                      $"If \"{Lockdown.BackstopTask}\" is in Task Scheduler, delete it, or it will put the old firewall back."
                                    : $"{names} kept and {words.State}, but the failsafe task could not be removed. " +
                                      $"Delete \"{Lockdown.BackstopTask}\" in Task Scheduler, or it will put the old firewall back.";
                                ThemedDialog.Info(owner, words.Change, left, danger: true);
                                return new(MergeOffResult.Kept, left, true, Shown: true);
                            }
                            return new(MergeOffResult.Kept, $"{applied.Summary} Kept; the failsafe task is removed.", applied.IsProblem, applied.Detail);
                        }
                        why = $"{words.Change} with {names} not kept";
                    }
                }
                catch (Exception ex)
                {
                    why = $"{words.Change} failed part way ({ex.Message.TrimEnd('.')})";
                }

                Lockdown.PutBackResult? back = null;
                await busy.RunAsync<object?>("Putting the firewall back", async report =>
                {
                    back = await Lockdown.PutBackAsync(snapshot!, why, backstopArmed: armed, t => report.Say(t));
                    return null;
                });
                return PutBack(back!, snapshot!, why);
            }
            finally { lockContent(false); }
        }

        private static MergeOffOutcome PutBack(Lockdown.PutBackResult u, string snapshot, string why)
        {
            var (text, error, detail) = Lockdown.PutBackText(u, snapshot, why);
            return new(MergeOffResult.PutBack, text, error, detail);
        }

        // The rule as it stands in the policy store: after Keep, a different one means the
        // failsafe task already put the old state back.
        private static string? RuleValue(string name)
        {
            using var key = Registry.LocalMachine.OpenSubKey(RuleWriter.RegGPO);
            return key?.GetValue(RuleWriter.KeyFor(name)) as string;
        }

        // The three profiles' guarded values as they stand, for the same purpose.
        private static string PolicyValues()
        {
            using var root = Registry.LocalMachine.OpenSubKey(PolicyRoot);
            return string.Join(",", Profiles.SelectMany(p =>
            {
                using var k = root?.OpenSubKey($"{p}Profile");
                return Values.Select(v => k?.GetValue(v)?.ToString() ?? "-").ToList();
            }));
        }

        // "a, b and c"
        internal static string JoinWords(IReadOnlyList<string> parts) =>
            parts.Count <= 1 ? string.Join("", parts) : $"{string.Join(", ", parts.Take(parts.Count - 1))} and {parts[^1]}";
    }
}
