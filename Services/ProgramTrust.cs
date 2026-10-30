using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace FirewallManager
{
    /// <summary>
    /// How a program name is coloured, and why: one scale for the rules list, the rule editor,
    /// the connection log and its Talkers. Facts only, never "trusted" or "safe".
    /// </summary>
    public enum ProgramTone
    {
        /// <summary>Not looked at yet, or nothing to say (no file, not a full path): the normal text colour.</summary>
        None,
        /// <summary>Windows' own file, unchanged since Microsoft signed it: dark green.</summary>
        Windows,
        /// <summary>Signed by its maker and unchanged since: light green.</summary>
        Signed,
        /// <summary>Matches the user's own pin: light green, as good as a signature and needing no one's trust.</summary>
        Pinned,
        /// <summary>Not signed: the outlier colour (indigo). Common for one's own tools; not a fault.</summary>
        Unsigned,
        /// <summary>An off case: a signature that doesn't hold, a look-alike name, an unexpected signer: amber.</summary>
        Off,
        /// <summary>Doesn't match the user's pin any more: red.</summary>
        Mismatch,
    }

    /// <summary>The verdict on one program file.</summary>
    /// <param name="Icon">Replaces the program's icon: "Warn" (amber alert) or "Error" (red alert); null keeps it.</param>
    public sealed record ProgramVerdict(ProgramTone Tone, string? Tip, string? Icon);

    // ─────────────────────────────────────────────────────────────────────────
    //  ProgramTrust — combines what FileTrust, LookAlike and Pins say about a program
    //  file into one tone and one tooltip, in this order: a pin that no longer matches;
    //  a signature that doesn't hold; a look-alike; Windows' own; a matching pin; signed;
    //  not signed. The signature and look-alike answers are looked up once per file, in
    //  the background, and kept until Refresh; the pin part is read fresh each time, so a
    //  pin added or checked shows at once.
    // ─────────────────────────────────────────────────────────────────────────
    public static class ProgramTrust
    {
        private sealed record Found(FileTrust.Result Trust, string? LookAlike);

        private static readonly object Gate = new();
        private static readonly Dictionary<string, Found> Cache = new(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> Pending = new(StringComparer.OrdinalIgnoreCase);
        // Raised by Clear: a lookup still running from before doesn't write its old answers back.
        private static int _generation;

        /// <summary>The file a rule's program stands for, or null when there is none to look at.</summary>
        public static string? PathOf(string program)
        {
            var stored = program?.Trim() ?? "";
            if (stored.Length == 0 || stored.Equals("System", StringComparison.OrdinalIgnoreCase)) return null;
            string path;
            try { path = Environment.ExpandEnvironmentVariables(stored); }
            catch { return null; }
            if (!IsFullPath(path)) return null;
            // A network path can stall for seconds when the share is out of reach: not looked at.
            if (path.StartsWith(@"\\", StringComparison.Ordinal) &&
                (!path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))) return null;
            try
            {
                if (path.Length > 2 && path[1] == ':' && new DriveInfo(path[..1]).DriveType == DriveType.Network) return null;
            }
            catch { return null; }
            return path;
        }

        /// <summary>A full path after expanding variables: X:\… or \\server\… (also the \\?\ forms).</summary>
        public static bool IsFullPath(string expanded) =>
            expanded.StartsWith(@"\\", StringComparison.Ordinal) ||
            (expanded.Length >= 3 && char.IsAsciiLetter(expanded[0]) && expanded[1] == ':' && (expanded[2] == '\\' || expanded[2] == '/'));

        /// <summary>The verdict as far as it is known now; null while the file is still being looked at, or for none.</summary>
        public static ProgramVerdict? For(string program)
        {
            if (PathOf(program) is not { } path) return null;
            Found? found;
            lock (Gate) Cache.TryGetValue(path, out found);
            return found == null ? null : Combine(path, found);
        }

        /// <summary>Looks at the files not looked at yet, in the background; done runs on the UI thread afterwards.</summary>
        public static void Load(IEnumerable<string> programs, Action done)
        {
            var todo = new List<string>();
            lock (Gate)
                foreach (var program in programs)
                    if (PathOf(program) is { } path && !Cache.ContainsKey(path) && Pending.Add(path))
                        todo.Add(path);
            if (todo.Count == 0) return;

            var dispatcher = Application.Current?.Dispatcher;
            int generation;
            lock (Gate) generation = _generation;
            Task.Run(() =>
            {
                foreach (var path in todo)
                {
                    Found found;
                    try
                    {
                        var trust = FileTrust.Check(path);
                        var look  = trust.Kind == FileTrust.Kind.Unchecked ? null : LookAlike.Check(path, trust);
                        found = new Found(trust, look);
                    }
                    catch { found = new Found(new FileTrust.Result(FileTrust.Kind.Unchecked, "", false, null), null); }
                    lock (Gate)
                    {
                        if (generation != _generation) return;   // cleared meanwhile: Refresh looks again
                        Cache[path] = found;
                        Pending.Remove(path);
                    }
                }
                try { dispatcher?.InvokeAsync(done); } catch { }
            });
        }

        /// <summary>
        /// The verdict for one file, looked up now if it hasn't been (signature checks take a
        /// moment: call it off the window's thread). Null for no file to look at.
        /// </summary>
        public static ProgramVerdict? Evaluate(string program)
        {
            if (PathOf(program) is not { } path) return null;
            Found? found;
            lock (Gate) Cache.TryGetValue(path, out found);
            if (found == null)
            {
                var trust = FileTrust.Check(path);
                found = new Found(trust, trust.Kind == FileTrust.Kind.Unchecked ? null : LookAlike.Check(path, trust));
                lock (Gate) Cache[path] = found;
            }
            return Combine(path, found);
        }

        /// <summary>Forgets every answer, so Refresh looks at the files as they are now.</summary>
        public static void Clear()
        {
            lock (Gate) { Cache.Clear(); Pending.Clear(); _generation++; }
        }

        private static string Day(DateTime t) => t.ToString("d", CultureInfo.CurrentCulture);

        private static ProgramVerdict? Combine(string path, Found found)
        {
            var trust = found.Trust;
            if (trust.Kind == FileTrust.Kind.Unchecked) return null;   // missing: the program icon says so

            var pin = Pins.For(path);
            string? pinLine = pin.Pin == null ? null : pin.State switch
            {
                Pins.State.Confirmed => $"Matches your pin from {Day(pin.Pin.Pinned)}" +
                                        (pin.Quick ? $"; size and date unchanged since the last full check on {Day(pin.Pin.LastFullCheck)}."
                                                   : $"; last full check {Day(pin.Pin.LastFullCheck)}."),
                Pins.State.Mismatch  => $"Changed since you pinned it on {Day(pin.Pin.Pinned)}: its SHA-256 differs " +
                                        $"(found on {Day(pin.Pin.LastFullCheck)}). Pin it again if you changed it yourself.",
                Pins.State.Checking  => $"Pinned on {Day(pin.Pin.Pinned)}; its size or date changed since, so its fingerprint is being checked.",
                _                    => null,
            };
            var signer = trust.Signer.Length > 0 ? trust.Signer : "an unnamed signer";
            string? signature = trust.Kind switch
            {
                FileTrust.Kind.WindowsOwn => $"Signed by Microsoft Windows{(trust.Catalog ? " (catalog)" : "")}; the file is unchanged since Microsoft signed it.",
                FileTrust.Kind.Signed     => $"Signed by {signer}; the file is unchanged since it was signed.",
                FileTrust.Kind.Unsigned   => "Not signed.",
                FileTrust.Kind.Invalid    => $"Signature doesn't hold: {trust.Problem}.",
                _                         => null,
            };
            string Tip(params string?[] lines) => string.Join("\n", Array.FindAll(lines, l => !string.IsNullOrEmpty(l)));

            if (pin.State == Pins.State.Mismatch) return new ProgramVerdict(ProgramTone.Mismatch, Tip(pinLine, signature), "Error");
            if (trust.Kind == FileTrust.Kind.Invalid) return new ProgramVerdict(ProgramTone.Off, Tip(signature, pinLine), "Warn");
            if (found.LookAlike != null) return new ProgramVerdict(ProgramTone.Off, Tip(found.LookAlike, signature, pinLine), null);
            if (trust.Kind == FileTrust.Kind.WindowsOwn) return new ProgramVerdict(ProgramTone.Windows, Tip(signature, pinLine), null);
            if (pin.State == Pins.State.Confirmed) return new ProgramVerdict(ProgramTone.Pinned, Tip(pinLine, signature), null);
            if (trust.Kind == FileTrust.Kind.Signed) return new ProgramVerdict(ProgramTone.Signed, Tip(signature), null);
            return new ProgramVerdict(ProgramTone.Unsigned, Tip(signature), null);
        }
    }
}
