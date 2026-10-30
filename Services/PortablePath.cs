using System;
using System.Collections.Generic;

namespace FirewallManager
{
    /// <summary>
    /// A program path as rules store it: %SystemRoot%\… and %SystemDrive%\Program Files…\, as
    /// gpedit writes them, so a rule reads the same on a machine whose Windows lives elsewhere.
    /// Compared against this machine's real folders (a system in D:\W is recognised), and only
    /// at the start of the path. One conversion for the rule editor and Setup.
    /// </summary>
    internal static class PortablePath
    {
        public static string ToPortable(string path)
        {
            var p = (path ?? "").Trim();
            if (p.Equals("System", StringComparison.OrdinalIgnoreCase)) return "System";
            p = ExpandLeadingSystemVariable(p);

            var root  = (Environment.GetEnvironmentVariable("SystemRoot") ?? "").TrimEnd('\\');
            var drive = (Environment.GetEnvironmentVariable("SystemDrive") ?? "").TrimEnd('\\');
            var pairs = new List<(string Real, string Token)>();
            // Without the variable there is no real folder to compare with, so no token either.
            if (drive.Length > 0)
            {
                pairs.Add((drive + @"\Program Files (x86)\", @"%SystemDrive%\Program Files (x86)\"));
                pairs.Add((drive + @"\Program Files\",       @"%SystemDrive%\Program Files\"));
            }
            if (root.Length > 0) pairs.Add((root + @"\", @"%SystemRoot%\"));
            foreach (var (real, token) in pairs)
                if (p.StartsWith(real, StringComparison.OrdinalIgnoreCase))
                    return token + p[real.Length..];
            return p;
        }

        // Only the variables that name system folders: %LOCALAPPDATA% and the like would expand
        // to this user's folders, which the firewall service doesn't share, so they stay as typed.
        private static string ExpandLeadingSystemVariable(string p)
        {
            foreach (var name in new[] { "SystemRoot", "windir", "SystemDrive", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432" })
            {
                var token = "%" + name + "%";
                if (p.StartsWith(token, StringComparison.OrdinalIgnoreCase) &&
                    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value)
                    return value.TrimEnd('\\') + p[token.Length..];
            }
            return p;
        }
    }
}
