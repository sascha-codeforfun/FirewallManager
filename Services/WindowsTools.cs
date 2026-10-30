using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace FirewallManager
{
    /// <summary>
    /// The Windows tools the app starts, by full path. Started by bare name, Windows would look
    /// in the exe's own folder first, and whatever lies there would run as administrator.
    /// </summary>
    internal static class WindowsTools
    {
        public enum Tool { Gpupdate, PowerShell, Reg, Schtasks, Netsh, Auditpol, Sc, Ipconfig }

        /// <summary>Without these a change would be written but not applied, not checked or not undoable.</summary>
        public static readonly Tool[] NeededForChanges = { Tool.Gpupdate, Tool.PowerShell, Tool.Reg, Tool.Schtasks };

        /// <summary>Each of these serves single features; without one, only that feature stops.</summary>
        public static readonly Tool[] NeededByFeatures = { Tool.Netsh, Tool.Auditpol, Tool.Sc, Tool.Ipconfig };

        /// <summary>The Windows folder comes from Windows, so a system on another drive is found.</summary>
        public static string PathOf(Tool tool) => Path.Combine(Environment.SystemDirectory, tool switch
        {
            Tool.Gpupdate   => "gpupdate.exe",
            Tool.PowerShell => @"WindowsPowerShell\v1.0\powershell.exe",
            Tool.Reg        => "reg.exe",
            Tool.Schtasks   => "schtasks.exe",
            Tool.Netsh      => "netsh.exe",
            Tool.Auditpol   => "auditpol.exe",
            Tool.Sc         => "sc.exe",
            Tool.Ipconfig   => "ipconfig.exe",
            _               => throw new ArgumentOutOfRangeException(nameof(tool)),
        });

        public static bool Exists(Tool tool) => File.Exists(PathOf(tool));

        public static List<Tool> Missing(IEnumerable<Tool> tools) => tools.Where(t => !Exists(t)).ToList();

        /// <summary>"gpupdate.exe" (or the PowerShell path below System32), as the user would look for it.</summary>
        public static string Name(Tool tool) =>
            Path.GetRelativePath(Environment.SystemDirectory, PathOf(tool));

        /// <summary>
        /// "gpupdate.exe not found in C:\Windows\system32: {consequence}", or null when the tool
        /// is there. Never falls back to a search by bare name, which would bring the risk back.
        /// </summary>
        public static string? NotFound(Tool tool, string consequence) =>
            Exists(tool) ? null : $"{Name(tool)} not found in {Environment.SystemDirectory}: {consequence}";
    }
}
