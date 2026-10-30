using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// Windows' own local rules, removed and put back through the firewall service, so the
    /// running firewall changes at once instead of at the next restart. Removal is by the
    /// firewall's own command; putting back is an import of what `netsh advfirewall export`
    /// saved, which the firewall applies at once (a .reg import only reaches the registry).
    /// Used by Purge Local, by deleting one local rule, and by Lock down, whose restore depends on it.
    /// </summary>
    internal static class LocalRules
    {
        public const string Key = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

        /// <summary>
        /// Problem: why nothing was removed (no backup, key unreadable), else null. NotRemoved:
        /// one line per rule left in place. Wfw: the firewall export, or null with WfwProblem
        /// saying why not. StillHeld: purged rules the running firewall holds afterwards, or
        /// null when it couldn't be asked.
        /// </summary>
        public sealed record PurgeResult(int ByService, int ByRegistry, List<string> NotRemoved, string? Problem,
                                         string? Backup, string? Wfw, string? WfwProblem, int? StillHeld);

        public sealed record Removal(int ByService, int ByRegistry, List<string> NotRemoved);

        // Every value is a rule: a value that isn't one shows as an unreadable row, never hidden.
        public static int Count()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(Key);
                return key?.ValueCount ?? 0;
            }
            catch { return 0; }
        }

        /// <summary>Every value of the key, as stored. Null when there is no key.</summary>
        public static Dictionary<string, string>? ReadAll()
        {
            using var ro = Registry.LocalMachine.OpenSubKey(Key);
            return ro?.GetValueNames().ToDictionary(n => n, n => ro.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "");
        }

        public static PurgeResult Purge()
        {
            Dictionary<string, string> all;
            try
            {
                if (ReadAll() is not { } read) return new PurgeResult(0, 0, new(), "the local rules key can't be opened", null, null, null, null);
                all = read;
            }
            catch (Exception ex) { return new PurgeResult(0, 0, new(), ex.Message, null, null, null, null); }

            var ids = all.Keys.ToList();
            if (ids.Count == 0) return new PurgeResult(0, 0, new(), null, null, null, null, null);

            string backup;
            try
            {
                var body = new StringBuilder();
                body.AppendLine($@"[HKEY_LOCAL_MACHINE\{Key}]");
                foreach (var (name, value) in all)
                    body.AppendLine($"\"{RegEscape(name)}\"=\"{RegEscape(value)}\"");
                backup = AppFolder.WriteReg("local-rules", body.ToString());
            }
            catch (Exception ex)
            {
                return new PurgeResult(0, 0, new(), $"the backup couldn't be written ({ex.Message})", null, null, null, null);
            }

            // The firewall's own export next to it: importing it puts the rules back at once.
            // The .reg is the backup that counts; without the export, putting back waits for a restart.
            var wfw = System.IO.Path.ChangeExtension(backup, "wfw");
            var wfwProblem = Export(wfw);
            if (wfwProblem != null) wfw = null;

            var removal = Remove(all);
            var held = HeldNames();
            return new PurgeResult(removal.ByService, removal.ByRegistry, removal.NotRemoved, null, backup, wfw, wfwProblem,
                                   held == null ? null : ids.Count(held.Contains));
        }

        /// <summary>
        /// Removes the rules among <paramref name="before"/> through the firewall service, then
        /// deletes from the registry what the service didn't take (that part drops at the next
        /// restart). Only values unchanged since <paramref name="before"/> are deleted, so
        /// nothing that wasn't saved is lost.
        /// </summary>
        public static Removal Remove(IReadOnlyDictionary<string, string> before)
        {
            var ids = before.Keys.ToList();
            var notRemoved = new List<string>();

            // Matched by exact name against one listing, since -Name takes wildcards and one
            // query per rule is slow. A rule the service refuses is not an error here: the
            // registry step below takes it.
            foreach (var batch in Batches(ids))
            {
                var script = @"
$want = @{}
foreach ($id in " + PsData.Strings(batch) + @") { $want[$id] = $true }
Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $want.ContainsKey($_.Name) } |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
exit 0
";
                PolicyApply.RunPowerShell(script, 180_000);
            }

            var byService = 0;
            var byRegistry = 0;
            try
            {
                using var rw = Registry.LocalMachine.OpenSubKey(Key, writable: true);
                foreach (var id in ids)
                {
                    var (step, why) = RegistryStep(rw, id, before[id]);
                    if (step == Step.ByService) byService++;
                    else if (step == Step.ByRegistry) byRegistry++;
                    else notRemoved.Add($"{id}: {why}");
                }
            }
            catch (Exception ex) { notRemoved.Add(ex.Message); }
            return new Removal(byService, byRegistry, notRemoved);
        }

        // The script travels on the command line (32,767 characters), encoded twice: each ID
        // as Base64 inside it, then the whole script as UTF-16 Base64. About 6,000 bytes of IDs
        // stay well under that; local IDs can hold a full program path, so a count alone won't do.
        private static IEnumerable<List<string>> Batches(IEnumerable<string> ids)
        {
            const int MaxBytes = 6000, MaxCount = 100;
            var batch = new List<string>();
            var bytes = 0;
            foreach (var id in ids)
            {
                var size = Encoding.UTF8.GetByteCount(id);
                if (batch.Count > 0 && (batch.Count == MaxCount || bytes + size > MaxBytes))
                {
                    yield return batch;
                    batch = new List<string>();
                    bytes = 0;
                }
                batch.Add(id);
                bytes += size;
            }
            if (batch.Count > 0) yield return batch;
        }

        private enum Step { ByService, ByRegistry, NotRemoved }

        // After the firewall's own removal: a value that is gone was taken by the service; one
        // still there is deleted from the registry only if it is exactly what was saved.
        private static (Step Step, string? Why) RegistryStep(RegistryKey? rw, string id, string before)
        {
            var now = rw == null ? before : rw.GetValue(id, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString();
            if (now == null) return (Step.ByService, null);
            if (rw == null) return (Step.NotRemoved, "the local rules key can't be opened for writing");
            if (now != before) return (Step.NotRemoved, "changed since it was saved, so it was left alone");
            try { rw.DeleteValue(id); return (Step.ByRegistry, null); }
            catch (Exception ex) { return (Step.NotRemoved, ex.Message); }
        }

        /// <summary>What the removal through the firewall answered.</summary>
        public enum FirewallAnswer { Removed, Refused, NotRun }

        /// <summary>
        /// One local rule deleted. Problem: why nothing was deleted (no backup, rule gone, value
        /// changed). Answer and Message: what the firewall's removal said; Message is PowerShell's
        /// error text when it refused ("" when it gave none) or why it didn't run. StillHeld:
        /// whether the running firewall holds the rule afterwards, null when it couldn't be asked.
        /// </summary>
        public sealed record SingleResult(string? Problem, string? Backup, bool ByService, bool ByRegistry,
                                          FirewallAnswer Answer, string Message, bool? StillHeld);

        /// <summary>
        /// The same path as Purge Local, for one rule: a .reg backup of that value first (no
        /// backup, no delete), removal through the firewall, the registry as fallback, then the
        /// live check. No .wfw: importing one replaces the whole local store.
        /// </summary>
        public static SingleResult DeleteOne(string id)
        {
            string before;
            try
            {
                using var ro = Registry.LocalMachine.OpenSubKey(Key);
                if (ro?.GetValue(id, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() is not { } value)
                    return new SingleResult("it is no longer in the registry", null, false, false, FirewallAnswer.NotRun, "", null);
                before = value;
            }
            catch (Exception ex) { return new SingleResult(ex.Message, null, false, false, FirewallAnswer.NotRun, "", null); }

            // A fixed file name: the rule's name or ID could hold anything a file name can't.
            string backup;
            try { backup = AppFolder.WriteReg("local-rule", $"[HKEY_LOCAL_MACHINE\\{Key}]\r\n\"{RegEscape(id)}\"=\"{RegEscape(before)}\"\r\n"); }
            catch (Exception ex) { return new SingleResult($"the backup couldn't be written ({ex.Message})", null, false, false, FirewallAnswer.NotRun, "", null); }

            // Not SilentlyContinue: when the firewall refuses, its own message says why.
            var script = @"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$id = " + PsData.One(id) + @"
try {
    Remove-NetFirewallRule -PolicyStore PersistentStore -Name ([WildcardPattern]::Escape($id)) -ErrorAction Stop
    'REMOVED'
}
catch { 'REFUSED'; $_.Exception.Message }
exit 0
";
            var (ok, output) = PolicyApply.RunPowerShell(script, 120_000);
            var lines = output.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
            // Only an error PowerShell returned counts as a refusal; no answer at all is not one.
            var (answer, message) =
                !ok                               ? (FirewallAnswer.NotRun, OneLine(lines))
              : lines.Contains("REMOVED")         ? (FirewallAnswer.Removed, "")
              : lines.Contains("REFUSED")         ? (FirewallAnswer.Refused, OneLine(lines.SkipWhile(l => l != "REFUSED").Skip(1)))
              :                                     (FirewallAnswer.NotRun, "PowerShell gave no answer");

            (Step Step, string? Why) step;
            try
            {
                using var rw = Registry.LocalMachine.OpenSubKey(Key, writable: true);
                step = RegistryStep(rw, id, before);
            }
            catch (Exception ex) { step = (Step.NotRemoved, ex.Message); }
            if (step.Step == Step.NotRemoved)
                return new SingleResult(step.Why, backup, false, false, answer, message, null);

            var held = HeldNames();
            return new SingleResult(null, backup, step.Step == Step.ByService, step.Step == Step.ByRegistry,
                                    answer, message, held?.Contains(id));
        }

        private static string OneLine(IEnumerable<string> lines) => string.Join(" ", lines).Trim();

        /// <summary>`netsh advfirewall export`: the local store as the firewall sees it. Null, or why not.</summary>
        public static string? Export(string path) => Netsh($"advfirewall export \"{path}\"", "the firewall's own export wasn't saved");

        /// <summary>`netsh advfirewall import`: replaces the local store, applied at once. Null, or why not.</summary>
        public static string? Import(string path) => Netsh($"advfirewall import \"{path}\"", "the local rules weren't put back");

        private static string? Netsh(string arguments, string consequence)
        {
            if (WindowsTools.NotFound(WindowsTools.Tool.Netsh, consequence) is { } missing) return missing;
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.Netsh), Arguments = arguments,
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true
                });
                if (p == null) return $"netsh could not be started: {consequence}";
                try { p.StandardInput.Close(); } catch { }
                var stdout = p.StandardOutput.ReadToEndAsync();
                var stderr = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(120_000)) { try { p.Kill(); } catch { } return $"netsh did not finish within two minutes: {consequence}"; }
                var output = (stdout.Result + " " + stderr.Result).Trim();
                return p.ExitCode == 0 ? null : $"netsh ended with code {p.ExitCode} ({output}): {consequence}";
            }
            catch (Exception ex) { return $"{ex.Message}: {consequence}"; }
        }

        /// <summary>Names of the local rules the running firewall holds right now, or null when it can't be asked.</summary>
        private static HashSet<string>? HeldNames()
        {
            // "No rules found" is an answer (none held), not a failure.
            const string script = @"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
try { $all = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop) }
catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $all = @() } else { throw } }
$all | Where-Object { $_.PolicyStoreSourceType -eq 'Local' } | ForEach-Object { $_.Name }
";
            var (ok, output) = PolicyApply.RunPowerShell(script, 120_000);
            if (!ok) return null;
            return output.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0)
                         .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        private static string RegEscape(string raw) => raw.Replace(@"\", @"\\").Replace("\"", "\\\"");
    }
}
