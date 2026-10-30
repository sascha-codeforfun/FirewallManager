using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// The DNS rule: UDP 53 to one resolver, for the DNS Client service (Dnscache) only. Every
    /// program's lookups go through that service, so the scope takes nothing away from them, and
    /// a program that sends DNS itself can't go around the resolver. One resolver, so every
    /// answer has one known source. TCP 53 (answers too big for UDP) gets a rule only once the
    /// log shows it is needed. A TCP DNS rule under this key, if there is one, is switched along,
    /// so the switch never shows half of what it switches.
    /// </summary>
    internal static class DnsRule
    {
        public const string UdpKey  = "CUSTOM_DNS_UDP_Out";
        public const string TcpKey  = "CUSTOM_DNS_TCP_Out";
        public const string UdpName = "CUSTOM DNS Out";
        public const string TcpName = "CUSTOM DNS TCP Out";
        public const string Program = @"%SystemRoot%\system32\svchost.exe";
        public const string Service = "Dnscache";

        /// <summary>A rule value for one protocol (17 UDP, 6 TCP) to one IPv4 resolver.</summary>
        public static string Value(int protocol, string server, bool active) =>
            $"v2.33|Action=Allow|Dir=Out|Protocol={protocol}|RPort=53|RA4={server}|App={Program}|Svc={Service}|" +
            $"Active={(active ? "TRUE" : "FALSE")}|Name={(protocol == 6 ? TcpName : UdpName)}|";

        /// <summary>
        /// True when the DNS Client service is set to Disabled. The scoped rules then allow
        /// nothing: on Windows 10 each program sends its own DNS, which they don't cover; on
        /// Windows 11 26300 Windows resolves no names at all (measured), and only programs with
        /// their own DNS code still send any.
        /// </summary>
        public static bool ServiceDisabled()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Dnscache");
                return k?.GetValue("Start") is int v && v == 4;
            }
            catch { return false; }
        }
    }
}
