using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;

namespace FirewallManager
{
    /// <summary>
    /// Windows stores many rule names as a reference into a resource ("@FirewallAPI.dll,-28775"),
    /// resolved in Windows' display language. Shared by the main list and the service-rules
    /// window, so both show the same text. The reference itself stays what is stored, backed
    /// up and exported: it is the same on every machine, the text is not.
    /// </summary>
    internal static class IndirectNames
    {
        private static readonly ConcurrentDictionary<string, string?> Cache = new(StringComparer.OrdinalIgnoreCase);

        public static bool IsReference(string? name) => name is { Length: > 1 } && name[0] == '@';

        /// <summary>The readable text, or null when it isn't a reference or can't be resolved.</summary>
        public static string? Resolve(string? reference)
        {
            if (!IsReference(reference)) return null;
            return Cache.GetOrAdd(reference!, static r =>
            {
                try
                {
                    var buffer = new StringBuilder(1024);
                    return SHLoadIndirectString(Environment.ExpandEnvironmentVariables(r), buffer, (uint)buffer.Capacity, IntPtr.Zero) == 0
                           && buffer.Length > 0 ? buffer.ToString() : null;
                }
                catch { return null; }
            });
        }

        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
        private static extern int SHLoadIndirectString(string source, StringBuilder output, uint outputSize, IntPtr reserved);
    }
}
