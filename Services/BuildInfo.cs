using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace FirewallManager
{
    /// <summary>
    /// What built this exe and what it runs on, for the header ("built with SDK 10.0.401",
    /// "runtime 10.0.12"). The SDK version is written into the assembly at build time
    /// (AssemblyMetadata "BuildSdkVersion" in the .csproj); the runtime version is read live,
    /// which for a self-contained exe is exactly the runtime bundled inside it.
    /// </summary>
    internal static class BuildInfo
    {
        public static string SdkVersion { get; } =
            typeof(BuildInfo).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                .FirstOrDefault(a => a.Key == "BuildSdkVersion")?.Value is { Length: > 0 } v ? v : "unknown";

        public static string RuntimeVersion { get; } = Environment.Version.ToString();

        /// <summary>The app version (e.g. "2.0.8"): the .csproj Version, or -p:Version from the build command.</summary>
        public static string AppVersion { get; } =
            (typeof(BuildInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
             ?? typeof(BuildInfo).Assembly.GetName().Version?.ToString(3)
             ?? "unknown").Split('+')[0];

        public static string Tooltip =>
            $"Firewall Rule Manager {AppVersion}\n" +
            $"Built with .NET SDK {SdkVersion}\n" +
            $"Runtime: {RuntimeInformation.FrameworkDescription}\n" +
            $"Target: {AppContext.TargetFrameworkName ?? "unknown"}\n" +
            $"Platform: {RuntimeInformation.RuntimeIdentifier} ({RuntimeInformation.ProcessArchitecture})";
    }
}
