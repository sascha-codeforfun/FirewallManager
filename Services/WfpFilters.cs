using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace FirewallManager
{
    /// <summary>
    /// The live filters in Windows' filtering engine (WFP), the level below firewall rules, read
    /// only. Needed for one fact the rule cmdlets don't give: whether a permit is "hard".
    ///
    /// Within one layer, WFP asks each sublayer in order of weight, highest first, and a block
    /// from any of them normally wins. A permit marked with the "clear action right" flag is
    /// hard: blocks from sublayers of lower weight in the same layer can't override it. Blocks
    /// from higher sublayers still can. So whether a hard permit gets past the firewall's own
    /// rules depends on its sublayer's weight against theirs, and only in a layer where their
    /// sublayer has filters at all: in any other layer the two never meet.
    ///
    /// Read only on purpose. Deleting a filter by its ID would go around every rule store, and
    /// a hard permit found here needs investigating before anything is done about it: see
    /// "Purging obsolete rules" in ServiceHardening.
    /// </summary>
    internal static class WfpFilters
    {
        public const uint FlagClearActionRight = 0x8;
        private const uint ActionBlock = 0x1001, ActionPermit = 0x1002;

        public sealed record Filter(ulong Id, string Name, string Provider, uint Flags, uint Action,
                                    Guid Layer, Guid SubLayer, string SubLayerName, int SubLayerWeight)
        {
            public bool IsPermit => Action == ActionPermit;
            public bool IsBlock  => Action == ActionBlock;
            /// <summary>A permit that blocks from lower-weight sublayers of the same layer can't override.</summary>
            public bool IsHard   => IsPermit && (Flags & FlagClearActionRight) != 0;

            public string Describe =>
                $"{Id} {(IsPermit ? "permit" : IsBlock ? "block" : $"action 0x{Action:X}")}" +
                (IsHard ? " HARD" : "") + (Provider.Length > 0 ? $", provider {Provider}" : "") +
                $", sublayer {SubLayerName} (weight {(SubLayerWeight >= 0 ? SubLayerWeight.ToString() : "?")})";
        }

        /// <summary>Every filter, or null and the reason when the engine can't be read.</summary>
        public static (List<Filter>? Filters, string? Problem) Read()
        {
            // The offsets below are those of the 64-bit FWPM_FILTER0, FWPM_PROVIDER0 and FWPM_SUBLAYER0.
            if (IntPtr.Size != 8) return (null, "only readable by the 64-bit app");

            IntPtr engine = IntPtr.Zero, enumHandle = IntPtr.Zero;
            var list = new List<Filter>();
            var providers = new Dictionary<Guid, string>();
            var sublayers = new Dictionary<Guid, (string Name, int Weight)>();
            try
            {
                var rc = FwpmEngineOpen0(null, RpcCAuthnWinNt, IntPtr.Zero, IntPtr.Zero, out engine);
                if (rc != 0) return (null, $"the filtering engine can't be opened (0x{rc:X8})");
                rc = FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out enumHandle);
                if (rc != 0) return (null, $"the filters can't be listed (0x{rc:X8})");

                const uint Batch = 1000;
                while (true)
                {
                    rc = FwpmFilterEnum0(engine, enumHandle, Batch, out var entries, out var count);
                    if (rc != 0) return (null, $"the filters can't be read (0x{rc:X8})");
                    try
                    {
                        for (var i = 0; i < count; i++)
                            list.Add(ReadFilter(engine, Marshal.ReadIntPtr(entries, i * IntPtr.Size), providers, sublayers));
                    }
                    finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                    if (count < Batch) break;
                }
                return (list, null);
            }
            catch (Exception ex) { return (null, ex.Message); }
            finally
            {
                if (enumHandle != IntPtr.Zero) FwpmFilterDestroyEnumHandle0(engine, enumHandle);
                if (engine != IntPtr.Zero) FwpmEngineClose0(engine);
            }
        }

        private static Filter ReadFilter(IntPtr engine, IntPtr f, Dictionary<Guid, string> providers,
                                         Dictionary<Guid, (string Name, int Weight)> sublayers)
        {
            var name     = Marshal.PtrToStringUni(Marshal.ReadIntPtr(f, 16)) ?? "";
            var flags    = (uint)Marshal.ReadInt32(f, 32);
            var provider = Marshal.ReadIntPtr(f, 40);
            var action   = (uint)Marshal.ReadInt32(f, 128);
            var id       = (ulong)Marshal.ReadInt64(f, 176);
            var layer    = Marshal.PtrToStructure<Guid>(f + 64);
            var subKey   = Marshal.PtrToStructure<Guid>(f + 80);

            if (!sublayers.TryGetValue(subKey, out var sub))
            {
                sub = (subKey.ToString("B"), -1);
                if (FwpmSubLayerGetByKey0(engine, ref subKey, out var p) == 0 && p != IntPtr.Zero)
                {
                    sub = (Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 16)) ?? sub.Name, (ushort)Marshal.ReadInt16(p, 64));
                    FwpmFreeMemory0(ref p);
                }
                sublayers[subKey] = sub;
            }

            var providerName = "";
            if (provider != IntPtr.Zero)
            {
                var key = Marshal.PtrToStructure<Guid>(provider);
                if (!providers.TryGetValue(key, out var known))
                {
                    known = key.ToString("B");
                    if (FwpmProviderGetByKey0(engine, ref key, out var p) == 0 && p != IntPtr.Zero)
                    {
                        known = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 16)) ?? known;
                        FwpmFreeMemory0(ref p);
                    }
                    providers[key] = known;
                }
                providerName = known;
            }
            return new Filter(id, name, providerName, flags, action, layer, subKey, sub.Name, sub.Weight);
        }

        // ── Win32 ──────────────────────────────────────────────────────────────

        private const uint RpcCAuthnWinNt = 10;

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        private static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity,
                                                   IntPtr session, out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterCreateEnumHandle0(IntPtr engineHandle, IntPtr enumTemplate, out IntPtr enumHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested,
                                                   out IntPtr entries, out uint numEntriesReturned);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmProviderGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr provider);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr subLayer);

        [DllImport("fwpuclnt.dll")]
        private static extern void FwpmFreeMemory0(ref IntPtr p);
    }
}
