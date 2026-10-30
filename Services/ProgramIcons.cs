using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace FirewallManager
{
    /// <summary>What the rules grid shows in front of a rule's program: a Windows icon, or one of the app's own.</summary>
    /// <param name="Image">The icon Windows has for it; null to draw <paramref name="Glyph"/> instead.</param>
    /// <param name="Glyph">An Icon.* resource key of the app's own, drawn when there is no image; null for nothing.</param>
    /// <param name="Alert">The rule's program isn't there: drawn in the warning colour.</param>
    /// <param name="Tip">Why it looks this way, when that isn't obvious; null for none.</param>
    public sealed record ProgramLook(ImageSource? Image, string? Glyph, bool Alert, string? Tip);

    // ─────────────────────────────────────────────────────────────────────────
    //  ProgramIcons — the icon in front of a rule's program in the rules grid, so an
    //  app's rules are found by eye (and two copies of one app show twice).
    //
    //  • A program file: the icon Explorer shows for it. Not there: the app's own
    //    alert, since the rule still allows whatever is put at that path later. Not
    //    checked (a network path, which can stall for seconds; access denied): the
    //    app's own program icon, and the tooltip says why.
    //  • One service inside svchost.exe: a Windows icon that stands for it
    //    (TermService → Remote Desktop Connection, Dnscache → globe, W32Time → clock
    //    globe, any other → the Services console's gear). Windows trimmed of that file
    //    (NTLite and the like): the app's own icon for it, the one its Setup tile or
    //    button uses.
    //  • A rule tied to a service the firewall can't tell apart (no service identity)
    //    or that isn't installed: the alert, since the rule never matches.
    //  • A program by name only, or a relative path: the alert, since a rule matches a
    //    program by its full path and this one never matches.
    //  • System, or no program: nothing.
    //
    //  Looked up once per file or icon and cached, on a background thread of its own,
    //  so the grid shows at once and the icons follow. Refresh clears the cache.
    // ─────────────────────────────────────────────────────────────────────────
    public static class ProgramIcons
    {
        /// <summary>A file's icon, or an icon by its fixed ID in imageres.dll (ResId > 0).</summary>
        private sealed record Source(string Key, string Path, int ResId);

        /// <summary>What to show for one rule before anything is looked up.</summary>
        private sealed record Plan(Source? Source, string Glyph, bool RulesOwnFile, string? Tip, bool Alert = false);

        private enum FileState { Present, Missing, Unchecked }
        private sealed record Result(ImageSource? Image, FileState State, string? Why);

        // imageres.dll by fixed ID, not by position: positions move between Windows versions.
        private const int GlobeId = 25;        // globe on a monitor
        private const int ClockGlobeId = 144;  // clock on a globe

        private static readonly object Gate = new();
        private static readonly Dictionary<string, Result> Cache = new(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> Pending = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// What to show now: from the cache, or the plan's own icon while the lookup is still to
        /// come (pending). Null: nothing to show (System, no program).
        /// </summary>
        public static ProgramLook? For(string program, string service, out bool pending)
        {
            pending = false;
            if (PlanFor(program, service) is not { } plan) return null;
            if (plan.Source == null) return new ProgramLook(null, plan.Glyph, plan.Alert, plan.Tip);
            Result? result;
            lock (Gate) Cache.TryGetValue(plan.Source.Key, out result);
            if (result == null)
            {
                pending = true;
                return null;   // blank until it is known: an alert that then turns out wrong would mislead
            }
            return LookFrom(plan, result);
        }

        /// <summary>Forgets every lookup, so a refresh shows what is on disk now.</summary>
        public static void Clear()
        {
            lock (Gate) { Cache.Clear(); Pending.Clear(); ServiceAnswers.Clear(); }
        }

        // Each service's answer, read once (a quick registry read, but asked for every rule on
        // every reload); Refresh reads them again.
        private static readonly Dictionary<string, string?> ServiceAnswers = new(StringComparer.OrdinalIgnoreCase);

        private static string? WhyNotMatched(string service)
        {
            lock (Gate)
            {
                if (!ServiceAnswers.TryGetValue(service, out var why))
                    ServiceAnswers[service] = why = ServiceIdentity.WhyNotMatched(service);
                return why;
            }
        }

        /// <summary>
        /// Looks up what the given rules need and isn't cached yet, on a background thread; done
        /// runs on the UI thread once it is in the cache. Nothing to look up: done is not called.
        /// </summary>
        public static void Load(IEnumerable<(string Program, string Service)> rules, Action done)
        {
            var todo = new List<Source>();
            lock (Gate)
                foreach (var (program, service) in rules)
                    if (PlanFor(program, service)?.Source is { } source && !Cache.ContainsKey(source.Key) && Pending.Add(source.Key))
                        todo.Add(source);
            if (todo.Count == 0) return;

            var dispatcher = Application.Current?.Dispatcher;
            // The shell asks for a single-threaded apartment for icon lookups.
            var thread = new Thread(() =>
            {
                foreach (var source in todo)
                {
                    Result result;
                    try { result = Lookup(source); }
                    catch (Exception ex) { result = new Result(null, FileState.Unchecked, ex.Message.TrimEnd('.')); }
                    lock (Gate) { Cache[source.Key] = result; Pending.Remove(source.Key); }
                }
                try { dispatcher?.InvokeAsync(done); } catch { }
                // Making the icon images gave this thread a dispatcher of its own: end it with the thread.
                System.Windows.Threading.Dispatcher.FromThread(Thread.CurrentThread)?.InvokeShutdown();
            })
            { IsBackground = true, Name = "Program icons" };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
        }

        // ── what each rule gets ──────────────────────────────────────────────

        private static Plan? PlanFor(string program, string service)
        {
            // A rule for one service that the firewall can't tell apart (no service identity) or
            // that isn't installed never matches: that, not the program, is what the icon says.
            var named = service?.Trim() ?? "";
            if (named.Length > 0 && named != "*" && WhyNotMatched(named) is { } notMatched)
                return new Plan(null, "Icon.Alert", false, notMatched, Alert: true);

            var stored = program?.Trim() ?? "";
            if (stored.Length == 0 || stored.Equals("System", StringComparison.OrdinalIgnoreCase)) return null;

            string path;
            try { path = Environment.ExpandEnvironmentVariables(stored); }
            catch { path = stored; }

            // A firewall rule matches a program by its full path: a bare name ("svchost.exe") or
            // a relative one never matches, whatever service it names.
            if (!ProgramTrust.IsFullPath(path))
                return new Plan(null, "Icon.Alert", false,
                    $"Not a full path: {stored}. A rule matches a program by its full path, so this rule never matches.", Alert: true);

            // One service inside svchost.exe: svchost's own icon says nothing about which.
            if (Path.GetFileName(path).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) &&
                named is { Length: > 0 } svc && svc != "*")
            {
                var system = Environment.SystemDirectory;
                return svc.ToUpperInvariant() switch
                {
                    "TERMSERVICE" => StandIn(FileSource(Path.Combine(system, "mstsc.exe")), "Icon.Rdp"),
                    "DNSCACHE"    => StandIn(ImageresSource(GlobeId), "Icon.Dns"),
                    "W32TIME"     => StandIn(ImageresSource(ClockGlobeId), "Icon.Clock"),
                    _             => StandIn(FileSource(Path.Combine(system, "services.msc")), "Icon.Settings"),
                };
            }

            if (Unreachable(path) is { } why)
                return new Plan(null, "Icon.Program", true, $"Not checked whether the program is there: {why}.");
            return new Plan(FileSource(path), "Icon.Program", true, null);
        }

        private static Plan StandIn(Source source, string glyph) => new(source, glyph, false, null);
        private static Source FileSource(string path) => new("file:" + path, path, 0);
        private static Source ImageresSource(int id) =>
            new($"imageres:{id}", Path.Combine(Environment.SystemDirectory, "imageres.dll"), id);

        /// <summary>Why the path isn't looked at, or null when it is a file on a local drive.</summary>
        private static string? Unreachable(string path)
        {
            // \\?\C:\… and \\.\C:\… are long or device forms of a local path: look at the path behind them.
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\.\", StringComparison.Ordinal))
            {
                var rest = path[4..];
                if (rest.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase)) return "it is a network path, which can stall when the share is out of reach";
                path = rest;
            }
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return "it is a network path, which can stall when the share is out of reach";
            try
            {
                if (new DriveInfo(path[..1]).DriveType == DriveType.Network)
                    return "it is on a network drive, which can stall when the share is out of reach";
            }
            catch { return "its drive can't be read"; }
            return null;
        }

        private static ProgramLook LookFrom(Plan plan, Result result)
        {
            if (!plan.RulesOwnFile)
                // A stand-in for a service: Windows' icon, else the app's own. Nothing to warn about.
                return new ProgramLook(result.Image, result.Image == null ? plan.Glyph : null, false, null);

            var path = plan.Source!.Path;
            return result.State switch
            {
                FileState.Missing => new ProgramLook(null, "Icon.Alert", true,
                    (result.Why != null ? $"Not a program: {path} is {result.Why}." : $"Program not found: {path}") +
                    "\nThe rule still allows whatever is put at this path." +
                    // A Store app's folder carries its version, so every update leaves the old path empty.
                    (path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase)
                        ? "\nStore app, probably updated: Edit → Update finds the new folder." : "")),
                FileState.Unchecked => new ProgramLook(null, "Icon.Program", false,
                    $"Not checked whether the program is there: {result.Why}."),
                _ => result.Image != null
                    ? new ProgramLook(result.Image, null, false, null)
                    : new ProgramLook(null, "Icon.Program", false, "Windows has no icon for this file."),
            };
        }

        // ── looking up (background thread) ───────────────────────────────────

        private static Result Lookup(Source source)
        {
            // Windows answers "not found" for a file it won't let us see, too: only a clear
            // not-found counts as missing, anything else as not checked.
            try
            {
                var attributes = File.GetAttributes(source.Path);
                if (attributes.HasFlag(FileAttributes.Directory))
                    return new Result(null, FileState.Missing, "a folder, not a program");
            }
            catch (FileNotFoundException)       { return new Result(null, FileState.Missing, null); }
            catch (DirectoryNotFoundException)  { return new Result(null, FileState.Missing, null); }
            catch (UnauthorizedAccessException) { return new Result(null, FileState.Unchecked, "Windows denies access to it"); }
            catch (Exception ex)                { return new Result(null, FileState.Unchecked, ex.Message.TrimEnd('.')); }

            var image = source.ResId > 0 ? ResourceIcon(source.Path, source.ResId) : FileIcon(source.Path);
            return new Result(image, FileState.Present, null);
        }

        // The icon Explorer shows for the file, at the large size (32 px at 100 %, more when scaled).
        private static ImageSource? FileIcon(string path)
        {
            var info = new SHFILEINFO();
            var ok = SHGetFileInfo(path, 0, ref info, (uint)Marshal.SizeOf<SHFILEINFO>(), SHGFI_ICON | SHGFI_LARGEICON);
            if (ok == IntPtr.Zero || info.hIcon == IntPtr.Zero) return null;
            return Owned(info.hIcon);
        }

        // An icon by its fixed resource ID, at 48 px, so it stays sharp drawn at 24 on a scaled screen.
        // imageres.dll's icons sit in SystemResources\imageres.dll.mun; Windows reads them from there.
        private static ImageSource? ResourceIcon(string file, int id)
        {
            if (SHDefExtractIcon(file, -id, 0, out var large, IntPtr.Zero, 48 | (16 << 16)) != 0 || large == IntPtr.Zero)
                return null;
            return Owned(large);
        }

        // A plain, frozen copy of the icon's pixels, free of the handle (destroyed here), so the
        // UI thread can use it.
        private static ImageSource? Owned(IntPtr hIcon)
        {
            try
            {
                var source = Imaging.CreateBitmapSourceFromHIcon(hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                var w = source.PixelWidth;
                var h = source.PixelHeight;
                var stride = w * 4;
                var pixels = new byte[stride * h];
                new FormatConvertedBitmap(source, PixelFormats.Pbgra32, null, 0).CopyPixels(pixels, stride, 0);
                var copy = BitmapSource.Create(w, h, 96, 96, PixelFormats.Pbgra32, null, pixels, stride);
                copy.Freeze();
                return copy;
            }
            finally { DestroyIcon(hIcon); }
        }

        private const uint SHGFI_ICON      = 0x000000100;
        private const uint SHGFI_LARGEICON = 0x000000000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHFILEINFO
        {
            public IntPtr hIcon;
            public int iIcon;
            public uint dwAttributes;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string? szDisplayName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]  public string? szTypeName;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);

        // S_OK (0) with the icon; S_FALSE or an error without. A negative index is a resource ID.
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHDefExtractIconW")]
        private static extern int SHDefExtractIcon(string pszIconFile, int iIndex, uint uFlags,
                                                   out IntPtr phiconLarge, IntPtr phiconSmall, uint nIconSize);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr hIcon);
    }
}
