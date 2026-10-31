using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  DefenderCloud — what Microsoft Defender does that a locked-down machine only waits for.
    //  With every profile locked down (firewall on, inbound and outbound blocked, no merge),
    //  Defender can't reach its cloud: cloud lookups, sample sending and block at first sight
    //  hold new files up for answers that never come. And new files usually arrive on the
    //  system drive, so the other fixed drives only hold what already passed that checkpoint.
    //
    //  The four switches are Defender's own policy values (HKLM\SOFTWARE\Policies\Microsoft\
    //  Windows Defender): written to turn a feature off, deleted to give it back to Defender's
    //  own settings. What is shown is always what Defender reports in force (Get-MpPreference),
    //  read back after every change, never what was written: Tamper Protection, an edition that
    //  ignores a value, or a setting made in Windows Security shows as it is.
    //
    //  Only fixed internal drives (SATA, NVMe, SAS, SCSI, RAID, Storage Spaces) other than the
    //  system drive are ever excluded. USB and FireWire drives, SD cards, attached disk images,
    //  network and iSCSI drives always stay scanned, even when Windows calls them "fixed".
    // ─────────────────────────────────────────────────────────────────────────
    internal static class DefenderCloud
    {
        private const string SpynetKey     = @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet";
        private const string ExclusionsKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions";
        private const string PathsKey      = ExclusionsKey + @"\Paths";

        /// <summary>What Defender reports in force. Null fields: not readable.</summary>
        public sealed record State(
            int? Maps,                  // MAPSReporting: 0 off, 1 basic, 2 advanced
            int? Samples,               // SubmitSamplesConsent: 0 ask, 1 safe, 2 never, 3 all
            bool? FirstSightOff,        // DisableBlockAtFirstSeen
            IReadOnlyList<string> Exclusions,
            bool? TamperProtected,
            string? Error)
        {
            public bool CloudOn      => Maps is > 0;
            public bool SamplesOn    => Samples is not 2;
            public bool FirstSightOn => FirstSightOff != true;

            public bool Excluded(string root) =>
                Exclusions.Any(e => Normal(e).Equals(Normal(root), StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Defender is installed: its service exists. Disabled or stopped still counts.</summary>
        public static bool Present()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinDefend");
                return k != null;
            }
            catch { return false; }
        }

        /// <summary>Asks Defender itself (takes a second or two: call it off the window's thread).</summary>
        public static State Read()
        {
            const string script =
                "$ErrorActionPreference='Stop'\n" +
                "$p = Get-MpPreference\n" +
                "$t = $null; try { $t = [bool](Get-MpComputerStatus).IsTamperProtected } catch { }\n" +
                "[pscustomobject]@{ Maps = [int]$p.MAPSReporting; Samples = [int]$p.SubmitSamplesConsent; " +
                "FirstSightOff = [bool]$p.DisableBlockAtFirstSeen; Excl = @($p.ExclusionPath | Where-Object { $_ }); " +
                "Tamper = $t } | ConvertTo-Json -Compress\n";
            var (ok, output) = PolicyApply.RunPowerShell(script, 30000);
            if (!ok) return Failed(string.IsNullOrWhiteSpace(output) ? "Defender didn't answer" : output.Trim());
            try
            {
                using var doc = JsonDocument.Parse(output.Trim());
                var r = doc.RootElement;
                int? Int(string n) => r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;
                bool? Bool(string n) => r.TryGetProperty(n, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : null;
                var excl = new List<string>();
                if (r.TryGetProperty("Excl", out var e))
                {
                    if (e.ValueKind == JsonValueKind.Array)
                        excl.AddRange(e.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!));
                    else if (e.ValueKind == JsonValueKind.String) excl.Add(e.GetString()!);
                }
                // Without administrator rights Defender answers this placeholder instead of the list.
                excl.RemoveAll(x => x.StartsWith("N/A", StringComparison.OrdinalIgnoreCase));
                return new State(Int("Maps"), Int("Samples"), Bool("FirstSightOff"), excl, Bool("Tamper"), null);
            }
            catch (Exception ex) { return Failed($"Defender's answer couldn't be read ({ex.Message.TrimEnd('.')})"); }
        }

        private static State Failed(string why) => new(null, null, null, Array.Empty<string>(), null, Short(why));

        // ── set by gpedit ────────────────────────────────────────────────────

        /// <summary>Which switches the local Group Policy (gpedit, Registry.pol) sets.</summary>
        public sealed record Gpedit(bool Cloud, bool Samples, bool FirstSight, bool Drives)
        {
            public bool Any => Cloud || Samples || FirstSight || Drives;
        }

        public const string GpeditMaps       = "Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus → MAPS";
        public const string GpeditExclusions = "Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus → Exclusions";

        /// <summary>
        /// A value the local Group Policy sets is written back over this app's at every policy
        /// refresh: such a switch is left to gpedit. Deletion markers ("**del.…") set nothing.
        /// </summary>
        public static Gpedit GpeditSets()
        {
            var set = LocalGroupPolicy.Entries()
                .Where(e => !e.Value.StartsWith("**", StringComparison.Ordinal))
                .Select(e => (Key: e.Key.Trim('\\'), e.Value))
                .ToList();
            bool Has(string key, string? value) => set.Any(e =>
                e.Key.Equals(key, StringComparison.OrdinalIgnoreCase) &&
                (value == null || e.Value.Equals(value, StringComparison.OrdinalIgnoreCase)));
            return new Gpedit(
                Has(SpynetKey, "SpynetReporting"),
                Has(SpynetKey, "SubmitSamplesConsent"),
                Has(SpynetKey, "DisableBlockAtFirstSeen"),
                Has(ExclusionsKey, "Exclusions_Paths") || Has(PathsKey, null));
        }

        // ── the four switches ────────────────────────────────────────────────

        /// <summary>A: cloud lookups. Off takes B and C with it; on gives all three back to Defender.</summary>
        public static void SetCloud(bool on)
        {
            if (on)
            {
                Delete(SpynetKey, "SpynetReporting", "SubmitSamplesConsent", "DisableBlockAtFirstSeen");
                return;
            }
            using var k = Registry.LocalMachine.CreateSubKey(SpynetKey)
                          ?? throw new InvalidOperationException("Defender's policy key could not be opened for writing");
            k.SetValue("SpynetReporting", 0, RegistryValueKind.DWord);
            k.SetValue("SubmitSamplesConsent", 2, RegistryValueKind.DWord);
            k.SetValue("DisableBlockAtFirstSeen", 1, RegistryValueKind.DWord);
        }

        /// <summary>B: sample sending (only while cloud lookups are on).</summary>
        public static void SetSamples(bool on)
        {
            if (on) { Delete(SpynetKey, "SubmitSamplesConsent"); return; }
            using var k = Registry.LocalMachine.CreateSubKey(SpynetKey)
                          ?? throw new InvalidOperationException("Defender's policy key could not be opened for writing");
            k.SetValue("SubmitSamplesConsent", 2, RegistryValueKind.DWord);
        }

        /// <summary>C: block at first sight (only while cloud lookups are on).</summary>
        public static void SetFirstSight(bool on)
        {
            if (on) { Delete(SpynetKey, "DisableBlockAtFirstSeen"); return; }
            using var k = Registry.LocalMachine.CreateSubKey(SpynetKey)
                          ?? throw new InvalidOperationException("Defender's policy key could not be opened for writing");
            k.SetValue("DisableBlockAtFirstSeen", 1, RegistryValueKind.DWord);
        }

        /// <summary>
        /// D: scanning of the given drive roots. Off writes them as policy path exclusions; on
        /// removes every drive-root exclusion in the policy (a whole drive excluded this way is
        /// this switch's), never other policy exclusions and never Defender's own list.
        /// </summary>
        public static void SetDrives(bool scan, IEnumerable<string> roots)
        {
            if (scan)
            {
                using var paths = Registry.LocalMachine.OpenSubKey(PathsKey, writable: true);
                if (paths != null)
                {
                    foreach (var name in paths.GetValueNames().Where(IsDriveRoot))
                        paths.DeleteValue(name, throwOnMissingValue: false);
                    if (paths.ValueCount == 0) Delete(ExclusionsKey, "Exclusions_Paths");
                }
                return;
            }
            using (var ex = Registry.LocalMachine.CreateSubKey(ExclusionsKey)
                            ?? throw new InvalidOperationException("Defender's exclusion policy could not be opened for writing"))
                ex.SetValue("Exclusions_Paths", 1, RegistryValueKind.DWord);
            using var p = Registry.LocalMachine.CreateSubKey(PathsKey)
                          ?? throw new InvalidOperationException("Defender's exclusion policy could not be opened for writing");
            foreach (var root in roots) p.SetValue(root, "0", RegistryValueKind.String);
        }

        /// <summary>Drive roots this switch wrote (whole drives excluded by policy).</summary>
        public static List<string> PolicyDrives()
        {
            try
            {
                using var paths = Registry.LocalMachine.OpenSubKey(PathsKey);
                return paths?.GetValueNames().Where(IsDriveRoot).Select(Normal).ToList() ?? new List<string>();
            }
            catch { return new List<string>(); }
        }

        private static void Delete(string key, params string[] names)
        {
            using var k = Registry.LocalMachine.OpenSubKey(key, writable: true);
            if (k == null) return;
            foreach (var n in names) k.DeleteValue(n, throwOnMissingValue: false);
        }

        // ── which drives ─────────────────────────────────────────────────────

        /// <summary>The system drive's root, e.g. "C:\".</summary>
        public static string SystemRoot =>
            Normal(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\");

        /// <summary>
        /// Fixed internal drives other than the system drive, ready and with a letter. Decided by
        /// the bus the disk hangs on, not by Windows' "fixed": a USB disk often calls itself fixed.
        /// </summary>
        public static List<string> InternalDrives()
        {
            var list = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                    var root = Normal(d.RootDirectory.FullName);
                    if (root.Equals(SystemRoot, StringComparison.OrdinalIgnoreCase)) continue;
                    if (IsInternal(root)) list.Add(root);
                }
                catch { /* a drive that can't be asked is left scanned */ }
            }
            return list;
        }

        // STORAGE_BUS_TYPE values for disks inside the machine.
        private static readonly HashSet<int> InternalBuses = new()
        {
            1,   // SCSI
            3,   // ATA
            8,   // RAID
            10,  // SAS
            11,  // SATA
            16,  // Storage Spaces
            17,  // NVMe
            19,  // UFS
        };

        private static bool IsInternal(string root)
        {
            var bus = BusType(root, out var removable);
            return bus is { } b && !removable && InternalBuses.Contains(b);
        }

        // The disk's bus, from its storage device descriptor (no access rights needed).
        private static int? BusType(string root, out bool removable)
        {
            removable = true;
            var device = @"\\.\" + root.TrimEnd('\\');
            using var h = CreateFile(device, 0, FileShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (h.IsInvalid) return null;
            var query = new byte[12];   // STORAGE_PROPERTY_QUERY: StorageDeviceProperty (0), PropertyStandardQuery (0)
            var buffer = new byte[1024];
            if (!DeviceIoControl(h, IoctlStorageQueryProperty, query, query.Length, buffer, buffer.Length, out var got, IntPtr.Zero)
                || got < 32) return null;
            removable = buffer[10] != 0;              // STORAGE_DEVICE_DESCRIPTOR.RemovableMedia
            return BitConverter.ToInt32(buffer, 28);  // STORAGE_DEVICE_DESCRIPTOR.BusType
        }

        private const uint IoctlStorageQueryProperty = 0x002D1400;
        private const uint FileShareReadWrite = 0x1 | 0x2;
        private const uint OpenExisting = 3;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
                                                        uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] inBuffer, int inSize,
                                                   byte[] outBuffer, int outSize, out int returned, IntPtr overlapped);

        // ── helpers ──────────────────────────────────────────────────────────

        private static bool IsDriveRoot(string path) =>
            path.Length is 2 or 3 && char.IsLetter(path[0]) && path[1] == ':' && (path.Length == 2 || path[2] == '\\');

        /// <summary>"d:" and "D:\" alike as "D:\"; other paths unchanged but for a trailing backslash.</summary>
        public static string Normal(string path)
        {
            var p = path.Trim();
            if (p.Length == 2 && p[1] == ':') p += "\\";
            if (p.Length == 3 && p[1] == ':') return char.ToUpperInvariant(p[0]) + @":\";
            return p;
        }

        private static string Short(string text)
        {
            var t = string.Join(" ", text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()));
            return t.Length > 160 ? t[..160] + "…" : t;
        }
    }
}
