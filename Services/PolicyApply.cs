using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// Makes written policy take effect, and checks that it did.
    ///
    /// The firewall re-reads the policy key only when Group Policy hands it a change (see
    /// LocalGroupPolicy), so after each write this runs gpupdate for the computer, then compares
    /// the policy key with what the firewall applies: profile settings, every policy rule's
    /// presence and on/off state, and the full definition of the rules just written, so an edit
    /// not yet picked up doesn't pass as "in force" just because a rule of that name is loaded.
    ///
    /// Windows' own local rules are not policy: gpupdate doesn't touch them and this check
    /// doesn't cover them, so they are reported as "not checked".
    ///
    /// One run at a time; requests made during a run are gathered into the next one.
    /// </summary>
    internal static class PolicyApply
    {
        /// <summary>Rejected: rules written in this run that the firewall didn't load at all.</summary>
        public sealed record Result(string What, bool InForce, IReadOnlyList<string> Differences, string? Problem,
                                    bool Unchecked = false, IReadOnlyList<string>? Rejected = null,
                                    string? GpupdateError = null)
        {
            /// <summary>
            /// One status-line sentence. A gpupdate that reported an error is said first, and the
            /// check still says what the firewall applies: the policy may be in force regardless.
            /// </summary>
            public string Summary =>
                GpupdateError == null
                    ? Verdict
                    : Verdict.Insert(What.Length + 2, $"gpupdate reported an error ({GpupdateError}); ");

            private string Verdict =>
                Unchecked
                    ? $"{What}: written. {Problem}"
                    : Problem != null
                        ? $"{What}: written. Couldn't check whether the firewall applies it ({Problem})."
                        : InForce
                            ? $"{What}: in force."
                            // A rule just written and not loaded was refused: a restart won't change that.
                            : Rejected is { Count: > 0 }
                                ? $"{What}: written, but the firewall didn't load {string.Join(", ", Rejected)}: Windows refused {(Rejected.Count == 1 ? "the rule" : "the rules")}."
                            : $"{What}: written, but the firewall doesn't apply it yet — {Differences.Count} difference{(Differences.Count == 1 ? "" : "s")} " +
                              $"({string.Join("; ", Differences.Take(2))}{(Differences.Count > 2 ? "; …" : "")}). It applies at the next restart.";

            /// <summary>Show as a problem (red), not as information.</summary>
            public bool IsProblem => (!InForce && !Unchecked) || GpupdateError != null;

            /// <summary>Every difference, for a tooltip.</summary>
            public string? Detail =>
                Differences.Count == 0 ? null
                : "Policy key vs. what the firewall applies:\n" + string.Join("\n", Differences.Select(d => "• " + d));
        }

        /// <summary>A run begins (argument: what was written). May be raised on any thread.</summary>
        public static event Action<string>? Started;
        /// <summary>A run ended. May be raised on any thread.</summary>
        public static event Action<Result>? Completed;

        /// <summary>Set by the start-up questions when they changed policy; the main window applies it.</summary>
        public static string? PendingAtStart { get; set; }

        private const string Root = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";

        private static readonly SemaphoreSlim OneAtATime = new(1, 1);
        private static readonly object Pending = new();
        private static readonly List<string> _whats = new();
        private static readonly HashSet<string> _rules = new(StringComparer.OrdinalIgnoreCase);
        private static int _requested;     // request counter (under Pending)
        private static int _covered;       // highest request covered by a finished run
        private static Result? _last;

        /// <summary>
        /// gpupdate, wait, verify. <paramref name="rules"/>: the policy rules (registry value
        /// names) this write created or changed, whose definition gets compared too. Never throws.
        /// </summary>
        public static async Task<Result> RunAsync(string what, IEnumerable<string>? rules = null)
        {
            int mine;
            lock (Pending)
            {
                _whats.Add(what);
                if (rules != null) foreach (var r in rules) _rules.Add(r);
                mine = ++_requested;
            }

            await OneAtATime.WaitAsync().ConfigureAwait(false);
            try
            {
                // A run that started after this request was made has covered it.
                if (_covered >= mine && _last != null) return _last;

                string label; string[] names; int covers;
                lock (Pending)
                {
                    var whats = _whats.Distinct().ToList();
                    label = whats.Count <= 2 ? string.Join("; ", whats) : $"{whats[^1]} (and {whats.Count - 1} earlier changes)";
                    names = _rules.ToArray();
                    _whats.Clear();
                    _rules.Clear();
                    covers = _requested;
                }

                try { Started?.Invoke(label); } catch { }
                var result = await Task.Run(() => RefreshAndVerify(label, names)).ConfigureAwait(false);
                _covered = covers;
                _last = result;
                try { Completed?.Invoke(result); } catch { }
                return result;
            }
            finally { OneAtATime.Release(); }
        }

        /// <summary>
        /// A write to Windows' own local rules: not policy, so no gpupdate and no check. Reported
        /// as such, so it never reads as confirmed.
        /// </summary>
        public static void ReportLocal(string what)
        {
            var mergeOffEverywhere = Profiles.All(p =>
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey($@"{Root}\{p.Key}");
                    return k?.GetValue("AllowLocalPolicyMerge") is int v && v == 0;
                }
                catch { return false; }
            });
            var r = new Result(what, false, Array.Empty<string>(),
                "Windows' own local rules aren't checked here (the check covers policy)" +
                (mergeOffEverywhere ? "; with merge off on every profile they don't apply anyway." : "."),
                Unchecked: true);
            try { Completed?.Invoke(r); } catch { }
        }

        private static Result RefreshAndVerify(string what, IReadOnlyCollection<string> names)
        {
            try
            {
                // An error from gpupdate doesn't mean the policy isn't applied (a domain machine
                // with outbound blocked can't reach its domain controller, yet applies the local
                // policy): the check runs regardless, and the status says both.
                var (ok, output) = Gpupdate();
                var gpupdateError = ok ? null : Short(output);

                // The firewall re-reads within a few seconds of Group Policy finishing.
                Result r = Verify(what, names);
                for (int i = 0; i < 4 && !r.InForce && r.Problem == null; i++)
                {
                    Thread.Sleep(2000);
                    r = Verify(what, names);
                }
                return gpupdateError == null ? r : r with { GpupdateError = gpupdateError };
            }
            catch (Exception ex)
            {
                return new Result(what, false, Array.Empty<string>(), ex.Message);
            }
        }

        // ── gpupdate ───────────────────────────────────────────────────────────

        /// <summary>Computer policy only, waited for (up to two minutes).</summary>
        public static (bool Ok, string Output) Gpupdate()
        {
            if (WindowsTools.NotFound(WindowsTools.Tool.Gpupdate, "the change is written but not applied") is { } missing)
                return (false, missing);
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.Gpupdate), Arguments = "/target:computer /force",
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    RedirectStandardInput = true     // closed at once: a restart question can't wait for an answer
                });
                if (p == null) return (false, "could not start");
                try { p.StandardInput.Close(); } catch { }
                var stdout = p.StandardOutput.ReadToEndAsync();
                var stderr = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(120_000))
                {
                    try { p.Kill(); } catch { }
                    return (false, "did not finish within two minutes");
                }
                var text = (stdout.Result + " " + stderr.Result).Trim();
                return (p.ExitCode == 0, text);
            }
            catch (Exception ex) { return (false, ex.Message); }
        }

        // ── Verify ─────────────────────────────────────────────────────────────

        private static readonly (string Label, string Key)[] Profiles =
        {
            ("Domain", "DomainProfile"), ("Private", "PrivateProfile"), ("Public", "PublicProfile"),
        };

        // What the firewall applies, read with Windows' own cmdlets (the active store). Tab-separated
        // lines: P = profile, R = a rule that came from policy, D = a written rule's definition.
        // __NAMES__ is replaced by the names as PsData, so no name can end a string in the script.
        // Free text (rule names, program, service) comes back Base64 (UTF-8), so no character in
        // it can shift the fields.
        private const string ReadActive = @"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$ErrorActionPreference = 'Stop'
function Enc([object]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$s)) }
Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
    ""P`t$($_.Name)`t$($_.Enabled)`t$($_.DefaultInboundAction)`t$($_.DefaultOutboundAction)`t$($_.AllowLocalFirewallRules)""
}
$policyRules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.PolicyStoreSourceType -eq 'GroupPolicy' })
$policyRules | ForEach-Object { ""R`t$(Enc ($_.Name))`t$($_.Enabled)"" }
foreach ($n in __NAMES__) {
    $r = $policyRules | Where-Object { $_.Name -eq $n } | Select-Object -First 1
    if (-not $r) { continue }
    $pf = $r | Get-NetFirewallPortFilter
    $af = $r | Get-NetFirewallAddressFilter
    $ap = $r | Get-NetFirewallApplicationFilter
    $sf = $r | Get-NetFirewallServiceFilter
    $addr = @($af.RemoteAddress) -join ','
    $la = @($af.LocalAddress) -join ','
    ""D`t$(Enc $n)`t$($r.Direction)`t$($r.Action)`t$($pf.Protocol)`t$(@($pf.LocalPort) -join ',')`t$(@($pf.RemotePort) -join ',')`t$addr`t$(Enc ($ap.Program))`t$(Enc ($sf.Service))`t$(Enc ($r.DisplayName))`t$la""
}
";

        /// <summary>Compares the policy key with what the firewall applies right now.</summary>
        public static Result Verify(string what, IReadOnlyCollection<string>? names = null)
        {
            names ??= Array.Empty<string>();
            var (ok, output) = RunPowerShell(ReadActive.Replace("__NAMES__", PsData.Strings(names)), 90_000);
            var lines = output.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
            var profiles = lines.Where(l => l.StartsWith("P\t")).Select(l => l.Split('\t')).Where(f => f.Length >= 6)
                                .GroupBy(f => f[1], StringComparer.OrdinalIgnoreCase)
                                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            if (!ok || profiles.Count == 0)
                return new Result(what, false, Array.Empty<string>(), $"reading the firewall failed: {Short(output)}");

            var rulesInForce = lines.Where(l => l.StartsWith("R\t")).Select(l => l.Split('\t')).Where(f => f.Length >= 3)
                                    .GroupBy(f => Decoded(f[1]), StringComparer.OrdinalIgnoreCase)
                                    .ToDictionary(g => g.Key, g => g.First()[2], StringComparer.OrdinalIgnoreCase);
            var definitions = lines.Where(l => l.StartsWith("D\t")).Select(l => l.Split('\t')).Where(f => f.Length >= 12)
                                   .Select(f => { foreach (var i in new[] { 1, 8, 9, 10 }) f[i] = Decoded(f[i]); return f; })
                                   .GroupBy(f => f[1], StringComparer.OrdinalIgnoreCase)
                                   .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

            var diffs = new List<string>();

            // Profile settings that the policy key sets.
            foreach (var (label, key) in Profiles)
            {
                if (!profiles.TryGetValue(label, out var a)) continue;
                using var k = Registry.LocalMachine.OpenSubKey($@"{Root}\{key}");
                if (k == null) continue;
                CompareValue(k, "EnableFirewall",        "Firewall", label, a[2], v => v == 1 ? "True"  : "False", v => v == 1 ? "on" : "off");
                CompareValue(k, "DefaultInboundAction",  "Inbound",  label, a[3], v => v == 1 ? "Block" : "Allow", v => v == 1 ? "Block" : "Allow");
                CompareValue(k, "DefaultOutboundAction", "Outbound", label, a[4], v => v == 1 ? "Block" : "Allow", v => v == 1 ? "Block" : "Allow");
                CompareValue(k, "AllowLocalPolicyMerge", "Merge",    label, a[5], v => v == 1 ? "True"  : "False", v => v == 1 ? "Yes" : "No");
            }

            void CompareValue(RegistryKey reg, string value, string setting, string profile, string actual,
                              Func<int, string> expected, Func<int, string> words)
            {
                if (reg.GetValue(value) is not int v) return;
                if (string.Equals(expected(v), actual, StringComparison.OrdinalIgnoreCase)) return;
                var now = actual switch
                {
                    "True" => setting == "Firewall" ? "on" : "Yes",
                    "False" => setting == "Firewall" ? "off" : "No",
                    _ => actual,
                };
                diffs.Add($"{profile} {setting}: policy {words(v)}, firewall {now}");
            }

            // Rules in the policy key: present, and switched on or off as written.
            var written = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using (var rk = Registry.LocalMachine.OpenSubKey($@"{Root}\FirewallRules"))
            {
                if (rk != null)
                    foreach (var name in rk.GetValueNames())
                        written[name] = rk.GetValue(name) as string ?? "";
            }
            foreach (var (name, raw) in written)
            {
                var on = RuleText.IsOn(raw);
                if (!rulesInForce.TryGetValue(name, out var enabled))
                    diffs.Add($"rule {Display(name)}: in policy, not loaded by the firewall");
                else if (on != string.Equals(enabled, "True", StringComparison.OrdinalIgnoreCase))
                    diffs.Add($"rule {Display(name)}: policy {(on ? "on" : "off")}, firewall {(on ? "off" : "on")}");
            }
            foreach (var name in rulesInForce.Keys.Where(n => !written.ContainsKey(n)))
                diffs.Add($"rule {Display(name)}: removed from policy, still in force");

            // The rules just written: is the firewall's copy the new definition?
            foreach (var name in names)
            {
                if (!written.TryGetValue(name, out var raw) || !rulesInForce.ContainsKey(name)) continue;   // reported above
                if (!definitions.TryGetValue(name, out var d)) { diffs.Add($"rule {Display(name)}: definition could not be read"); continue; }
                var differs = DefinitionDiffers(raw, d);
                if (differs.Count > 0)
                    diffs.Add($"rule {Display(name)}: firewall still has the old {string.Join(", ", differs)}");
            }

            var rejected = names.Where(n => written.ContainsKey(n) && !rulesInForce.ContainsKey(n)).Select(Display).ToList();
            return new Result(what, diffs.Count == 0, diffs, null, Rejected: rejected);
        }

        // Registry rule string ("v2.33|Action=Allow|Dir=In|Protocol=6|LPort=3389|RA4=…|App=…|Svc=…|")
        // against the firewall's copy: D, name, Direction, Action, Protocol, LocalPort, RemotePort,
        // remote addresses, Program, Service, DisplayName, local addresses.
        private static List<string> DefinitionDiffers(string raw, string[] d)
        {
            var fields = raw.Split('|').Where(p => p.Contains('='))
                            .Select(p => (Key: p[..p.IndexOf('=')], Value: p[(p.IndexOf('=') + 1)..]))
                            .ToList();
            string One(string k) => fields.FirstOrDefault(f => f.Key.Equals(k, StringComparison.OrdinalIgnoreCase)).Value ?? "";
            List<string> All(string k) => fields.Where(f => f.Key.Equals(k, StringComparison.OrdinalIgnoreCase))
                                                .SelectMany(f => f.Value.Split(','))
                                                .Select(v => v.Trim()).Where(v => v.Length > 0).ToList();
            static HashSet<string> Set(IEnumerable<string> items) =>
                items.Select(i => i.Trim())
                     .Where(i => i.Length > 0 && !i.Equals("Any", StringComparison.OrdinalIgnoreCase))
                     .ToHashSet(StringComparer.OrdinalIgnoreCase);
            static string Expand(string p) => Environment.ExpandEnvironmentVariables(p ?? "").Trim();

            var differs = new List<string>();

            var dir = One("Dir").Equals("In", StringComparison.OrdinalIgnoreCase) ? "Inbound" : "Outbound";
            if (!dir.Equals(d[2], StringComparison.OrdinalIgnoreCase)) differs.Add("direction");

            var action = One("Action");
            if (action.Length > 0 && !action.Equals(d[3], StringComparison.OrdinalIgnoreCase)) differs.Add("action");

            var proto = One("Protocol") switch { "" => "Any", "6" => "TCP", "17" => "UDP", "1" => "ICMPv4", "58" => "ICMPv6", var p => p };
            if (!proto.Equals(d[4], StringComparison.OrdinalIgnoreCase)) differs.Add("protocol");

            if (!Set(All("LPort")).SetEquals(Set(d[5].Split(',')))) differs.Add("local ports");
            if (!Set(All("RPort")).SetEquals(Set(d[6].Split(',')))) differs.Add("remote ports");

            var addresses   = Set(All("RA4").Concat(All("RA6")).Select(NormalizeAddress));
            var fwAddresses = Set(d[7].Split(',').Select(NormalizeAddress));
            if (!addresses.SetEquals(fwAddresses)) differs.Add("addresses");

            var local   = Set(All("LA4").Concat(All("LA6")).Select(NormalizeAddress));
            var fwLocal = Set(d[11].Split(',').Select(NormalizeAddress));
            if (!local.SetEquals(fwLocal)) differs.Add("local address");

            var app = Expand(One("App"));
            var fwApp = d[8].Equals("Any", StringComparison.OrdinalIgnoreCase) ? "" : Expand(d[8]);
            if (!app.Equals(fwApp, StringComparison.OrdinalIgnoreCase)) differs.Add("program");

            var svc = One("Svc");
            var fwSvc = d[9].Equals("Any", StringComparison.OrdinalIgnoreCase) ? "" : d[9];
            if (!svc.Equals(fwSvc, StringComparison.OrdinalIgnoreCase)) differs.Add("service");

            var shown = One("Name");
            if (shown.Length > 0 && !shown.Equals(d[10].Trim(), StringComparison.Ordinal)) differs.Add("name");

            return differs;
        }

        // One address entry in one form, so the policy string and the firewall's copy compare:
        // the firewall shows IPv4 subnets with a dotted mask (140.82.112.0/255.255.240.0) where
        // the policy has a prefix (/20); a single address may appear as x/32 or x-x; keywords
        // (LocalSubnet, DNS…) compare without case. Unparsable entries stay as they are.
        private static string NormalizeAddress(string entry)
        {
            var e = (entry ?? "").Trim();
            if (e.Length == 0) return e;

            var dash = e.IndexOf('-');
            if (dash > 0)
            {
                var a = Canon(e[..dash]); var b = Canon(e[(dash + 1)..]);
                if (a != null && b != null) return a == b ? a : $"{a}-{b}";
                return e.ToLowerInvariant();
            }

            var slash = e.IndexOf('/');
            if (slash > 0 && System.Net.IPAddress.TryParse(e[..slash], out var ip))
            {
                var suffix = e[(slash + 1)..];
                var v4 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
                int bits;
                if (int.TryParse(suffix, out var n)) bits = n;
                else if (v4 && System.Net.IPAddress.TryParse(suffix, out var mask))
                {
                    var m = mask.GetAddressBytes();
                    bits = m.Sum(x => System.Numerics.BitOperations.PopCount(x));
                }
                else return e.ToLowerInvariant();

                var max = v4 ? 32 : 128;
                if (bits >= max) return ip.ToString().ToLowerInvariant();
                // Network address of the subnet (the firewall stores it that way).
                var bytes = ip.GetAddressBytes();
                for (int i = 0; i < bytes.Length; i++)
                {
                    var keep = Math.Clamp(bits - i * 8, 0, 8);
                    bytes[i] &= (byte)(0xFF << (8 - keep));
                }
                return $"{new System.Net.IPAddress(bytes).ToString().ToLowerInvariant()}/{bits}";
            }

            return Canon(e) ?? e.ToLowerInvariant();

            static string? Canon(string s) =>
                System.Net.IPAddress.TryParse(s.Trim(), out var a) ? a.ToString().ToLowerInvariant() : null;
        }

        // A free-text field as ReadActive sends it (Base64 of UTF-8).
        private static string Decoded(string field)
        {
            try { return Encoding.UTF8.GetString(Convert.FromBase64String(field)); }
            catch (FormatException) { return field; }
        }

        // Rule IDs come from any writer: hidden characters are shown, as in the rule list.
        private static string Display(string key) =>
            TextHygiene.Reveal(key.StartsWith("CUSTOM_", StringComparison.OrdinalIgnoreCase) ? key[7..] : key).Shown;

        // ── Helpers ────────────────────────────────────────────────────────────

        /// <summary>Runs a PowerShell script (passed encoded, so no quoting issues); UTF-8 output.</summary>
        public static (bool Ok, string Output) RunPowerShell(string script, int timeoutMs)
        {
            if (WindowsTools.NotFound(WindowsTools.Tool.PowerShell, "this step was not run") is { } missing)
                return (false, missing);
            try
            {
                var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.PowerShell),
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
                });
                if (p == null) return (false, "could not start PowerShell");
                var stdout = p.StandardOutput.ReadToEndAsync();
                var stderr = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch { }
                    return (false, "PowerShell did not finish in time");
                }
                return (p.ExitCode == 0, p.ExitCode == 0 ? stdout.Result : (stderr.Result + stdout.Result));
            }
            catch (Exception ex) { return (false, ex.Message); }
        }

        private static string Short(string text)
        {
            var t = string.Join(" ", (text ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()));
            return t.Length > 160 ? t[..160] + "…" : t;
        }
    }
}
