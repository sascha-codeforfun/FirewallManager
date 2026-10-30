using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace FirewallManager
{
    /// <summary>
    /// The one place the app writes files: %SystemDrive%\FirewallManager. Machine-wide, like the
    /// firewall; outside AppData and Program Files, which other tools clean up; local, so a
    /// profile redirected to a network share can't put it out of reach while outbound is
    /// blocked, and SYSTEM (the lock-down failsafe) can read it.
    ///
    /// The failsafe imports a file from here as SYSTEM, so no unelevated program may be able to
    /// change anything here. The folder is created with its security in one step. An existing
    /// folder is used only if it is owned by Administrators, SYSTEM or TrustedInstaller, has its
    /// own (not inherited) permissions, and nobody but Administrators and SYSTEM can write to it.
    /// It is never repaired, since a folder someone else made could be changed back or swapped
    /// while being repaired.
    /// </summary>
    internal static class AppFolder
    {
        public static string FolderPath =>
            Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "FirewallManager");

        private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier LocalSystem    = new(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier Users          = new(WellKnownSidType.BuiltinUsersSid, null);
        // OWNER RIGHTS: limits what a file's owner may do, so an owner who isn't an administrator
        // (possible under a non-default Windows policy) can't change the access rules.
        private static readonly SecurityIdentifier OwnerRights    = new("S-1-3-4");
        private static readonly SecurityIdentifier TrustedInstaller =
            new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

        // Any of these lets a holder change, add or remove files, or change the folder's security.
        private const int WriteRights =
            0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

        /// <summary>
        /// Creates the folder, or checks an existing one. Throws with a plain reason when it
        /// can't be trusted.
        /// </summary>
        public static string Ensure()
        {
            var sec = new DirectorySecurity();
            sec.SetOwner(Administrators);
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags all = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            sec.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, all, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(OwnerRights, FileSystemRights.ReadAndExecute, all, PropagationFlags.None, AccessControlType.Allow));

            var descriptor = sec.GetSecurityDescriptorBinaryForm();
            var pin = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
            try
            {
                var attributes = new SecurityAttributes
                {
                    Length = Marshal.SizeOf<SecurityAttributes>(),
                    Descriptor = pin.AddrOfPinnedObject(),
                };
                if (!CreateDirectoryW(FolderPath, ref attributes))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != ErrorAlreadyExists)
                        throw new InvalidOperationException($"{FolderPath} could not be created: {new Win32Exception(error).Message}");
                }
            }
            finally { pin.Free(); }

            // Checked every time, also right after creating: someone may have been quicker.
            Verify();
            return FolderPath;
        }

        // The folder as it is on disk, looked at through one handle that doesn't follow links.
        private static void Verify()
        {
            using var handle = CreateFileW(FolderPath, ReadControl, 7, IntPtr.Zero, OpenExisting,
                                           FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid)
                throw new InvalidOperationException($"{FolderPath} can't be opened: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");

            if (!GetFileInformationByHandle(handle, out var info))
                throw new InvalidOperationException($"{FolderPath} can't be read: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
            if ((info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0)
                throw Refuse("is a link or a file, not a folder");

            var status = GetSecurityInfo(handle, 1, 1 | 4, out _, out _, out _, out _, out var sd);
            if (status != 0) throw new InvalidOperationException($"{FolderPath}: its security can't be read ({new Win32Exception(status).Message}).");
            RawSecurityDescriptor raw;
            try
            {
                var bytes = new byte[GetSecurityDescriptorLength(sd)];
                Marshal.Copy(sd, bytes, 0, bytes.Length);
                raw = new RawSecurityDescriptor(bytes, 0);
            }
            finally { LocalFree(sd); }

            var owner = raw.Owner;
            if (owner != Administrators && owner != LocalSystem && owner != TrustedInstaller)
                throw Refuse($"belongs to {Name(owner)}, who could change what this app saves there");
            if (!raw.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) || raw.DiscretionaryAcl == null)
                throw Refuse("takes its permissions from the drive, so others may be allowed to change it");
            foreach (var ace in raw.DiscretionaryAcl.OfType<CommonAce>())
            {
                if (ace.AceQualifier != AceQualifier.AccessAllowed) continue;
                if (ace.SecurityIdentifier == Administrators || ace.SecurityIdentifier == LocalSystem) continue;
                if ((ace.AccessMask & WriteRights) != 0)
                    throw Refuse($"lets {Name(ace.SecurityIdentifier)} change it");
            }
            if (raw.DiscretionaryAcl.OfType<GenericAce>().Any(a => a is not CommonAce))
                throw Refuse("has permissions this app doesn't recognise");
        }

        private static InvalidOperationException Refuse(string why)
        {
            var appInside = string.Equals(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                                          Path.TrimEndingDirectorySeparator(FolderPath), StringComparison.OrdinalIgnoreCase);
            return new($"{FolderPath} {why}. This app saves backups there that may be imported with full rights, so it won't use it. " +
                       (appInside
                           ? "The app itself is in that folder: move it somewhere else, delete the folder, and the app creates it with the right permissions."
                           : "Delete the folder; the app then creates it with the right permissions."));
        }

        /// <summary>A new file path in the folder: "&lt;name&gt;-&lt;date-time&gt;.&lt;ext&gt;", never an existing one.</summary>
        public static string NewFile(string name, string extension)
        {
            Ensure();
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            var path = Path.Combine(FolderPath, $"{name}-{stamp}.{extension}");
            for (var n = 2; File.Exists(path); n++)
                path = Path.Combine(FolderPath, $"{name}-{stamp}-{n}.{extension}");
            return path;
        }

        /// <summary>A .reg file as regedit writes them: version 5.00, UTF-16 LE with BOM.</summary>
        public static string WriteReg(string name, string body)
        {
            var path = NewFile(name, "reg");
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, Encoding.Unicode))
                writer.Write("Windows Registry Editor Version 5.00\r\n\r\n" + body);
            return path;
        }

        private static string Name(SecurityIdentifier? sid)
        {
            if (sid == null) return "an unknown owner";
            try { return sid.Translate(typeof(NTAccount)).Value; }
            catch { return sid.Value; }
        }

        // ── Win32 ──────────────────────────────────────────────────────────────

        private const int ErrorAlreadyExists = 183;
        private const uint ReadControl = 0x20000, OpenExisting = 3;
        private const uint FlagBackupSemantics = 0x02000000, FlagOpenReparsePoint = 0x00200000;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr Descriptor;
            public int InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct FileInfo
        {
            public uint Attributes;
            public long CreationTime, LastAccessTime, LastWriteTime;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
                                                         uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);

        [DllImport("advapi32.dll")]
        private static extern int GetSecurityInfo(SafeFileHandle handle, int objectType, int info,
                                                  out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

        [DllImport("advapi32.dll")]
        private static extern int GetSecurityDescriptorLength(IntPtr descriptor);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);
    }
}
