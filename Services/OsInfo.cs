using System;
using System.Linq;
using Microsoft.Win32;

namespace FirewallManager
{
    /// <summary>
    /// Which Windows this runs on, for the header: "Windows 11 Pro" over "24H2 · build 26100.4061".
    /// Read-only, from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
    ///
    /// ProductName is not trusted for the version number: on Windows 11 it still says
    /// "Windows 10 …" (Microsoft never changed it), so client builds from 22000 up are
    /// renamed to Windows 11. Server names are taken as they are ("Windows Server 2022
    /// Datacenter").
    /// </summary>
    internal static class OsInfo
    {
        /// <param name="CatalogQuery">What to search the Microsoft Update Catalog for to find this
        /// machine's updates: "Windows 11 26H2 x64", "Windows Server 2019 x64".</param>
        public sealed record Description(string Title, string Detail, string Tooltip, string CatalogQuery);

        public static Description Describe()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
                if (k == null) return Fallback();

                string Str(string name) => k.GetValue(name)?.ToString()?.Trim() ?? "";

                var product  = Str("ProductName");            // "Windows 10 Pro"
                var edition  = Str("EditionID");              // "Professional", "Core", "ServerStandard"…
                var install  = Str("InstallationType");       // "Client", "Server", "Server Core"
                var version  = Str("DisplayVersion");         // "24H2" (20H2 and later)
                if (version.Length == 0) version = Str("ReleaseId");   // "1909" and earlier
                int.TryParse(Str("CurrentBuildNumber"), out var build);
                var ubr      = k.GetValue("UBR") is int u ? u : 0;     // update revision

                var isServer = install.StartsWith("Server", StringComparison.OrdinalIgnoreCase);
                if (!isServer && build >= 22000 && product.StartsWith("Windows 10", StringComparison.OrdinalIgnoreCase))
                    product = "Windows 11" + product["Windows 10".Length..];
                if (product.Length == 0) product = "Windows";

                var detail = build > 0 ? $"build {build}{(ubr > 0 ? $".{ubr}" : "")}" : "";
                if (version.Length > 0) detail = detail.Length > 0 ? $"{version} · {detail}" : version;
                if (install.Equals("Server Core", StringComparison.OrdinalIgnoreCase))
                    detail += " · Server Core";

                var tooltip = $"{product}\n" +
                              $"Edition: {(edition.Length > 0 ? edition : "unknown")}\n" +
                              $"Installation: {(install.Length > 0 ? install : "unknown")}\n" +
                              $"Version: {(version.Length > 0 ? version : "unknown")}\n" +
                              $"Build: {build}{(ubr > 0 ? $".{ubr}" : "")}";

                // The catalog names products without their edition ("Windows 11", "Windows Server
                // 2019") and client releases by version; the app is x64-only, so is this machine.
                var words  = product.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var family = string.Join(' ', words.Take(isServer ? 3 : 2));
                var query  = (isServer || version.Length == 0 ? family : $"{family} {version}") + " x64";

                return new Description(product, detail, tooltip, query);
            }
            catch
            {
                return Fallback();
            }
        }

        private static Description Fallback()
        {
            var v = Environment.OSVersion.Version;
            return new Description("Windows", $"build {v.Build}", Environment.OSVersion.VersionString, "Windows x64");
        }
    }
}
