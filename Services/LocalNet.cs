using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using System.Diagnostics;

namespace FirewallManager
{
    /// <summary>
    /// This machine's own network, for Setup's pre-filled addresses: the IPv4 network of the
    /// adapter that has a gateway ("192.168.7." — you type the last number), and the gateway
    /// itself. Read live; nothing stored.
    /// </summary>
    internal static class LocalNet
    {
        public sealed record Info(string Address, int PrefixLength, string Gateway, string Adapter)
        {
            /// <summary>The first three numbers and a dot: what you complete with the last one.</summary>
            public string Prefix => string.Join('.', Address.Split('.').Take(3)) + ".";
        }

        public static Info? Primary()
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up ||
                        nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    var props = nic.GetIPProperties();
                    var gw = props.GatewayAddresses
                        .Select(g => g.Address)
                        .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
                    if (gw == null) continue;
                    var ua = props.UnicastAddresses.FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (ua == null) continue;
                    return new Info(ua.Address.ToString(), ua.PrefixLength, gw.ToString(), nic.Name);
                }
            }
            catch { }
            return null;
        }

        /// <summary>A complete, plain IPv4 address (four ASCII numbers, each 0–255): the app's one reading of an address.</summary>
        public static bool IsAddress(string text) => Ipv4Scope.TryAddress((text ?? "").Trim(), out _, out _);

        public static string LastOctet(string address) => address.Trim().Split('.').LastOrDefault() ?? "";
    }

    /// <summary>
    /// Can this machine accept Remote Desktop, and is it switched on? Read from the registry
    /// (numbers, so any Windows language); a Group Policy value wins over the local one.
    /// </summary>
    internal static class RemoteDesktop
    {
        public enum State { NotAvailable, Off, On, OffByPolicy, OnByPolicy }

        private const string LocalKey  = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
        private const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
        private const string RdpTcpKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

        public static State Current()
        {
            try
            {
                // Home editions ("Core…") can connect out but can't accept Remote Desktop.
                using (var cv = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                    if ((cv?.GetValue("EditionID") as string ?? "").StartsWith("Core", StringComparison.OrdinalIgnoreCase))
                        return State.NotAvailable;
                using (var svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TermService"))
                    if (svc == null) return State.NotAvailable;

                using (var pol = Registry.LocalMachine.OpenSubKey(PolicyKey))
                    if (pol?.GetValue("fDenyTSConnections") is int p)
                        return p == 0 ? State.OnByPolicy : State.OffByPolicy;

                using var local = Registry.LocalMachine.OpenSubKey(LocalKey);
                return local?.GetValue("fDenyTSConnections") is int d && d == 0 ? State.On : State.Off;
            }
            catch { return State.Off; }
        }

        /// <summary>
        /// Switches Remote Desktop on, with Network Level Authentication required (nobody gets a
        /// sign-in screen without valid credentials first), and starts its service.
        /// </summary>
        /// <returns>Null when it is on, else why not.</returns>
        public static string? Enable()
        {
            // Checked before anything is written, so a missing tool leaves Windows unchanged.
            if (WindowsTools.NotFound(WindowsTools.Tool.Sc, "the Remote Desktop service can't be started, so nothing was changed") is { } missing)
                return missing;
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(LocalKey, writable: true))
                    k?.SetValue("fDenyTSConnections", 0, RegistryValueKind.DWord);
                using (var k = Registry.LocalMachine.OpenSubKey(RdpTcpKey, writable: true))
                    k?.SetValue("UserAuthentication", 1, RegistryValueKind.DWord);
                Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.Sc), Arguments = "start TermService",
                    CreateNoWindow = true, UseShellExecute = false
                })?.WaitForExit(10000);
                return Current() is State.On or State.OnByPolicy ? null : "Remote Desktop didn't come on.";
            }
            catch (System.Exception ex) { return ex.Message; }
        }
    }
}
