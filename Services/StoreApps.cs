using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Microsoft.Win32;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  StoreApps — the Store apps installed for this user that a rule by path can
    //  match, with the exe each one starts, for the rule editor's Store app list.
    //
    //  Windows records each installed package's folder for the user under
    //  HKCU\…\AppModel\Repository\Packages (PackageRootFolder); the package's
    //  AppxManifest.xml names the exe(s) it starts. Only desktop apps packaged for
    //  the Store (full trust: Claude, most tools) are listed: those run as ordinary
    //  programs, so a rule by path matches them. Sandboxed Store apps (Calculator,
    //  Photos) are matched by Windows by their package, not their path, so a path
    //  rule would never apply to them: they aren't offered. Frameworks and resource
    //  packages start nothing and aren't either. No judgement beyond that.
    //
    //  The exe's folder carries the package version, so it changes with every update;
    //  the editor's Update button follows it.
    // ─────────────────────────────────────────────────────────────────────────
    internal static class StoreApps
    {
        /// <param name="Name">The app's display name, or the package's name where that is a resource reference.</param>
        /// <param name="Exe">The exe's full path, version folder included.</param>
        /// <param name="Package">The package's name (without version), e.g. AnthropicPBC.Claude.</param>
        public sealed record App(string Name, string Exe, string Package);

        private const string Repository =
            @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

        /// <summary>Reads every package's manifest: a moment's work, so call it off the window's thread.</summary>
        public static List<App> List()
        {
            var found = new List<(App App, Version Version)>();
            using var root = Registry.CurrentUser.OpenSubKey(Repository);
            if (root == null) return new List<App>();

            foreach (var full in root.GetSubKeyNames())
            {
                try
                {
                    using var key = root.OpenSubKey(full);
                    if (key?.GetValue("PackageRootFolder") is not string folder || !Directory.Exists(folder)) continue;
                    var manifest = Path.Combine(folder, "AppxManifest.xml");
                    if (!File.Exists(manifest)) continue;
                    found.AddRange(FromManifest(XDocument.Load(manifest), folder));
                }
                catch { /* an unreadable package is left out */ }
            }

            // An update can leave the old version's folder behind for a while: the newest one per app.
            return found
                .GroupBy(f => (f.App.Package.ToLowerInvariant(), Path.GetFileName(f.App.Exe).ToLowerInvariant()))
                .Select(g => g.OrderByDescending(f => f.Version).First().App)
                .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        }

        private static IEnumerable<(App, Version)> FromManifest(XDocument doc, string folder)
        {
            if (doc.Root == null) yield break;
            XElement? Child(XElement? parent, string local) => parent?.Elements().FirstOrDefault(e => e.Name.LocalName == local);

            var identity   = Child(doc.Root, "Identity");
            var properties = Child(doc.Root, "Properties");
            if (string.Equals(Child(properties, "Framework")?.Value, "true", StringComparison.OrdinalIgnoreCase)) yield break;
            if (string.Equals(Child(properties, "ResourcePackage")?.Value, "true", StringComparison.OrdinalIgnoreCase)) yield break;

            var package = identity?.Attribute("Name")?.Value ?? Path.GetFileName(folder);
            var version = Version.TryParse(identity?.Attribute("Version")?.Value, out var v) ? v : new Version(0, 0);
            var packageName = Child(properties, "DisplayName")?.Value;

            foreach (var app in doc.Root.Descendants().Where(e => e.Name.LocalName == "Application"))
            {
                var exe = app.Attribute("Executable")?.Value;
                if (string.IsNullOrWhiteSpace(exe) || exe.Contains('$')) continue;
                if (!FullTrust(app)) continue;

                string path;
                try { path = Path.GetFullPath(Path.Combine(folder, exe)); }
                catch { continue; }
                if (!File.Exists(path)) continue;

                var visual = app.Elements().FirstOrDefault(e => e.Name.LocalName == "VisualElements")?.Attribute("DisplayName")?.Value;
                var name = new[] { visual, packageName }.FirstOrDefault(Readable) ?? Prettify(package);
                yield return (new App(name, path, package), version);
            }
        }

        // Runs as an ordinary program: the classic full-trust entry point, or a manifest that
        // says so in one of its newer forms.
        // A win32App with TrustLevel appContainer is a sandboxed (isolated) Win32 app: not listed.
        private static bool FullTrust(XElement app)
        {
            string? Attr(string local) => app.Attributes().FirstOrDefault(a => a.Name.LocalName == local)?.Value;
            var trust   = Attr("TrustLevel");
            var runtime = Attr("RuntimeBehavior");
            if (string.Equals(trust, "appContainer", StringComparison.OrdinalIgnoreCase)) return false;
            return string.Equals(app.Attribute("EntryPoint")?.Value, "Windows.FullTrustApplication", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(trust, "mediumIL", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(runtime, "packagedClassicApp", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(runtime, "win32App", StringComparison.OrdinalIgnoreCase);
        }

        // A display name that is a resource reference ("ms-resource:AppName") needs the package's
        // resources to be read: the package name stands in for it.
        private static bool Readable(string? name) =>
            !string.IsNullOrWhiteSpace(name) && !name.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase);

        // "AnthropicPBC.Claude" → "Claude"; a name without a publisher part stays as it is.
        private static string Prettify(string package)
        {
            var dot = package.LastIndexOf('.');
            return dot > 0 && dot < package.Length - 1 ? package[(dot + 1)..] : package;
        }
    }
}
