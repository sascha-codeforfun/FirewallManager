using System;
using System.Runtime.InteropServices;
using System.Text;

namespace FirewallManager
{
    /// <summary>
    /// Whether anything at the machine itself could take over once Remote Desktop is gone: a
    /// screen, keyboard or mouse Windows lists as present. Remote Desktop's own devices and
    /// software or root-enumerated ones don't count; everything else does, PS/2 (also emulated)
    /// and Hyper-V's VMBus devices included, since a VM's console is direct access. So it errs
    /// on the quiet side: only a machine with none of them gets the fact. SetupAPI, read-only.
    /// </summary>
    internal static class LocalConsole
    {
        private static readonly Guid[] Classes =
        {
            new("4d36e96e-e325-11ce-bfc1-08002be10318"),   // Monitor
            new("4d36e96b-e325-11ce-bfc1-08002be10318"),   // Keyboard
            new("4d36e96f-e325-11ce-bfc1-08002be10318"),   // Mouse
        };

        /// <summary>
        /// True when no screen, keyboard or mouse is attached (none present but Remote Desktop's
        /// and software ones); false when one is; null when the device list can't be read.
        /// Any thread.
        /// </summary>
        public static bool? NoneAttached()
        {
            try
            {
                var unknown = false;
                foreach (var cls in Classes)
                {
                    switch (AnyCounted(cls))
                    {
                        case true: return false;
                        case null: unknown = true; break;
                    }
                }
                return unknown ? null : true;
            }
            catch { return null; }
        }

        // Remote Desktop's own input and display, and devices that exist only in software.
        private static bool Counts(string instanceId)
        {
            var id = instanceId.ToUpperInvariant();
            return !(id.StartsWith(@"TERMINPUT_BUS\", StringComparison.Ordinal) ||
                     id.StartsWith(@"ROOT\", StringComparison.Ordinal) ||
                     id.StartsWith(@"SWD\", StringComparison.Ordinal) ||
                     id.Contains("TS_INPT", StringComparison.Ordinal) ||
                     id.Contains("RDP", StringComparison.Ordinal));
        }

        // True: a present device of the class counts; false: none does; null: unreadable.
        private static bool? AnyCounted(Guid cls)
        {
            var set = SetupDiGetClassDevs(ref cls, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT);
            if (set == InvalidHandleValue) return null;
            try
            {
                var data = new SP_DEVINFO_DATA { cbSize = Marshal.SizeOf<SP_DEVINFO_DATA>() };
                for (var index = 0; ; index++)
                {
                    if (!SetupDiEnumDeviceInfo(set, index, ref data))
                        return Marshal.GetLastWin32Error() == ERROR_NO_MORE_ITEMS ? false : null;
                    if (InstanceId(set, ref data) is not { } id) return null;
                    if (Counts(id)) return true;
                }
            }
            finally { SetupDiDestroyDeviceInfoList(set); }
        }

        private static string? InstanceId(IntPtr set, ref SP_DEVINFO_DATA data)
        {
            var buffer = new StringBuilder(256);
            if (SetupDiGetDeviceInstanceId(set, ref data, buffer, buffer.Capacity, out var required)) return buffer.ToString();
            if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER || required <= 0) return null;
            buffer = new StringBuilder(required);
            return SetupDiGetDeviceInstanceId(set, ref data, buffer, buffer.Capacity, out _) ? buffer.ToString() : null;
        }

        private const int DIGCF_PRESENT = 0x2;
        private const int ERROR_INSUFFICIENT_BUFFER = 122, ERROR_NO_MORE_ITEMS = 259;
        private static readonly IntPtr InvalidHandleValue = new(-1);

        // 32 bytes on x64: cbSize 4, ClassGuid 16, DevInst 4, then the pointer aligned to 8.
        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid ClassGuid;
            public int DevInst;
            public IntPtr Reserved;
        }

        [DllImport("setupapi.dll", EntryPoint = "SetupDiGetClassDevsW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator, IntPtr parent, int flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiEnumDeviceInfo(IntPtr set, int index, ref SP_DEVINFO_DATA data);

        [DllImport("setupapi.dll", EntryPoint = "SetupDiGetDeviceInstanceIdW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiGetDeviceInstanceId(IntPtr set, ref SP_DEVINFO_DATA data, StringBuilder id, int size, out int required);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    }
}
