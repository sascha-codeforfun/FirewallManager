using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// The machine's local Group Policy (what gpedit.msc edits), as far as the firewall cares.
    ///
    /// The firewall re-reads its policy key only when Group Policy hands it a change. With
    /// nothing firewall-related in the local Group Policy, a refresh hands it nothing, and
    /// everything this app writes waits for the next restart. One firewall setting there is
    /// enough: every forced refresh then makes the firewall re-read the whole key.
    /// </summary>
    internal static class LocalGroupPolicy
    {
        public static string PolFile =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "GroupPolicy", "Machine", "Registry.pol");

        private const string FirewallKey = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";

        /// <summary>
        /// The size the Public profile's firewall log already has (policy value, else Windows' own
        /// setting, else Windows' default 4096 KB). The seed uses it, so nothing changes.
        /// </summary>
        public static int SeedLogSizeKb()
        {
            static int? Read(string path)
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(path);
                    return k?.GetValue("LogFileSize") is int v && v >= 1 && v <= 32767 ? v : null;
                }
                catch { return null; }
            }
            return Read($@"{FirewallKey}\PublicProfile\Logging")
                ?? Read(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging")
                ?? 4096;
        }

        public static string SeedDescription(int kb) => $"Public profile — firewall log file size: {kb} KB";

        public sealed record Entry(string Key, string Value);

        /// <summary>Entries of the machine part of the local Group Policy (empty if there is none).</summary>
        public static List<Entry> Entries() => Entries(PolFile);

        /// <summary>Entries of a Registry.pol file (empty if missing or unreadable).</summary>
        public static List<Entry> Entries(string file)
        {
            var list = new List<Entry>();
            try
            {
                if (!File.Exists(file)) return list;
                byte[] b;
                using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var ms = new MemoryStream())
                {
                    fs.CopyTo(ms);
                    b = ms.ToArray();
                }
                // "PReg", version, then [key;value;type;size;data] in UTF-16.
                if (b.Length < 8 || Encoding.ASCII.GetString(b, 0, 4) != "PReg") return list;
                int pos = 8;
                string ReadString()
                {
                    int start = pos;
                    while (pos + 1 < b.Length && (b[pos] != 0 || b[pos + 1] != 0)) pos += 2;
                    var s = Encoding.Unicode.GetString(b, start, pos - start);
                    pos += 2;                                          // the terminating null
                    return s;
                }
                while (pos + 2 <= b.Length && BitConverter.ToChar(b, pos) == '[')
                {
                    pos += 2;
                    var key = ReadString();  pos += 2;                  // ';'
                    var value = ReadString(); pos += 2;                 // ';'
                    pos += 4 + 2;                                       // type, ';'
                    if (pos + 4 > b.Length) break;
                    var size = BitConverter.ToUInt32(b, pos); pos += 4 + 2;        // size, ';'
                    // A size past the file's end is corruption: as an int it could turn negative
                    // and walk the reader backwards for ever. What was read so far stands.
                    if (pos > b.Length || size > (uint)(b.Length - pos)) break;
                    pos += (int)size + 2;                               // data, ']'
                    list.Add(new Entry(key, value));
                }
            }
            catch { /* unreadable counts as empty: the question below is harmless to ask */ }
            return list;
        }

        /// <summary>
        /// True if the local Group Policy sets anything under the firewall's policy key. Deletion
        /// markers ("**del.…", "**DeleteValues") don't count: they set nothing.
        /// </summary>
        public static bool HasFirewallSetting() =>
            Entries().Any(e => e.Key.StartsWith(FirewallKey, StringComparison.OrdinalIgnoreCase) &&
                               !e.Value.StartsWith("**", StringComparison.Ordinal));

        /// <summary>
        /// Adds the seed setting with Windows' own tool (netsh, local Group Policy store), then
        /// checks it arrived. Returns netsh's output for the error message.
        /// </summary>
        public static (bool Ok, string Output) AddSeed(int logSizeKb)
        {
            // The store choice only lasts for one netsh session, so both commands go to the same
            // netsh: typed into it through its input, with no script file anywhere.
            var commands = new[]
            {
                $"advfirewall set store gpo={Environment.MachineName}",
                $"advfirewall set publicprofile logging maxfilesize {logSizeKb.ToString(System.Globalization.CultureInfo.InvariantCulture)}",
                "exit",
            };
            var (ok, output) = Netsh("", commands);
            if (ok && HasFirewallSetting()) return (true, output);

            // Fallback: the same commands as a script, in the app's protected folder, deleted
            // straight after.
            string? script = null;
            output = "";
            try
            {
                script = AppFolder.NewFile("netsh-gpo", "txt");
                File.WriteAllLines(script, commands[..^1], Encoding.ASCII);
                (ok, output) = Netsh($"-f \"{script}\"", null);
            }
            catch (Exception ex) { return (false, ex.Message + (output.Length > 0 ? $"\n\n{output}" : "")); }
            finally { if (script != null) try { File.Delete(script); } catch { } }

            if (!ok) return (false, output);
            return HasFirewallSetting()
                ? (true, output)
                : (false, "netsh reported success, but the setting is not in the local Group Policy.\n\n" + output);
        }

        private static (bool Ok, string Output) Netsh(string arguments, string[]? input)
        {
            if (WindowsTools.NotFound(WindowsTools.Tool.Netsh, "the setting was not added") is { } missing)
                return (false, missing);
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.Netsh), Arguments = arguments,
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true
                });
                if (p == null) return (false, "netsh could not be started.");
                var stdout = p.StandardOutput.ReadToEndAsync();
                var stderr = p.StandardError.ReadToEndAsync();
                try
                {
                    if (input != null) foreach (var line in input) p.StandardInput.WriteLine(line);
                    p.StandardInput.Close();
                }
                catch { /* netsh already ended: its output says why */ }
                if (!p.WaitForExit(30_000))
                {
                    try { p.Kill(); } catch { }
                    return (false, "netsh did not finish within 30 seconds.");
                }
                var output = (stdout.Result + "\n" + stderr.Result).Trim();
                return p.ExitCode == 0 ? (true, output) : (false, $"netsh ended with code {p.ExitCode}.\n\n{output}");
            }
            catch (Exception ex) { return (false, ex.Message); }
        }

        // ── Profile values under the wrong key ──────────────────────────────────

        /// <summary>
        /// A profile value under StandardProfile, the pre-Vista name the firewall policy does not
        /// read (it uses DomainProfile, PrivateProfile and PublicProfile). Such a value may have
        /// been meant for either the Private or the Public profile; PrivateValue and PublicValue
        /// are those profiles' own current values, if any.
        /// </summary>
        public sealed record Stray(string Name, string Label, int Value, int? PrivateValue, int? PublicValue);

        private static readonly (string Name, string Label)[] ProfileValues =
        {
            ("EnableFirewall", "Firewall"),
            ("DefaultInboundAction", "Inbound"),
            ("DefaultOutboundAction", "Outbound"),
            ("AllowLocalPolicyMerge", "Merge"),
            ("AllowLocalIPsecPolicyMerge", "IPsec merge"),
        };

        private static string StandardKey => $@"{FirewallKey}\StandardProfile";

        /// <summary>
        /// The stray values. Ones that come from Group Policy (set in gpedit.msc, or by a domain
        /// policy: its cached copies are checked too) are left out: those are someone's
        /// deliberate settings, and a refresh would put them back anyway.
        /// </summary>
        public static List<Stray> FindStrays()
        {
            var list = new List<Stray>();
            try
            {
                using var std = Registry.LocalMachine.OpenSubKey(StandardKey);
                if (std == null) return list;
                using var prv = Registry.LocalMachine.OpenSubKey($@"{FirewallKey}\PrivateProfile");
                using var pub = Registry.LocalMachine.OpenSubKey($@"{FirewallKey}\PublicProfile");

                var policyFiles = new List<string> { PolFile };
                var history = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                                           "Microsoft", "Group Policy", "History");
                if (Directory.Exists(history))
                    policyFiles.AddRange(Directory.GetDirectories(history)
                        .Select(d => Path.Combine(d, "Machine", "Registry.pol")));
                var fromGpo = policyFiles.SelectMany(f => Entries(f))
                    .Where(e => e.Key.Equals(StandardKey, StringComparison.OrdinalIgnoreCase))
                    .Select(e => e.Value)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var (name, label) in ProfileValues)
                {
                    if (std.GetValue(name) is not int v || fromGpo.Contains(name)) continue;
                    list.Add(new Stray(name, label, v,
                        prv?.GetValue(name) is int pv ? pv : null,
                        pub?.GetValue(name) is int uv ? uv : null));
                }
            }
            catch { }
            return list;
        }

        public static string Words(string name, int v) => name switch
        {
            "EnableFirewall"         => v == 1 ? "ON" : "OFF",
            "DefaultInboundAction"   => v == 1 ? "Block" : "Allow",
            "DefaultOutboundAction"  => v == 1 ? "Block" : "Allow",
            _                        => v == 0 ? "No" : "Yes",       // the merge values
        };

        /// <summary>
        /// Moves the stray values: into PrivateProfile and into PublicProfile, each only where
        /// that profile has no value of its own (its own value is what Windows uses, so it stays),
        /// then out of StandardProfile. The StandardProfile key goes too once it is empty.
        /// Each write and removal goes into <paramref name="done"/> as it happens, so a failure part
        /// way can say what was already changed.
        /// </summary>
        public static void MoveStrays(IEnumerable<Stray> strays, List<string>? done = null)
        {
            var list = strays.ToList();
            using (var prv = Registry.LocalMachine.CreateSubKey($@"{FirewallKey}\PrivateProfile"))
            using (var pub = Registry.LocalMachine.CreateSubKey($@"{FirewallKey}\PublicProfile"))
            using (var std = Registry.LocalMachine.OpenSubKey(StandardKey, writable: true))
            {
                // A move that skips a key would be reported as done; callers rely on a throw.
                if (prv == null || pub == null)
                    throw new InvalidOperationException("The Private or Public profile key could not be opened for writing.");
                foreach (var s in list)
                {
                    if (s.PrivateValue == null)
                    {
                        prv.SetValue(s.Name, s.Value, RegistryValueKind.DWord);
                        done?.Add($"{s.Label} in PrivateProfile");
                    }
                    if (s.PublicValue == null)
                    {
                        pub.SetValue(s.Name, s.Value, RegistryValueKind.DWord);
                        done?.Add($"{s.Label} in PublicProfile");
                    }
                    if (std?.GetValue(s.Name) != null)
                    {
                        std.DeleteValue(s.Name, throwOnMissingValue: false);
                        done?.Add($"{s.Label} removed from StandardProfile");
                    }
                }
            }
            using (var std = Registry.LocalMachine.OpenSubKey(StandardKey))
            {
                if (std == null || std.ValueCount > 0 || std.SubKeyCount > 0) return;
            }
            try { Registry.LocalMachine.DeleteSubKey(StandardKey, throwOnMissingSubKey: false); } catch { }
        }
    }
}
