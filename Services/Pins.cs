using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  Pins — a program file the user approved, by its exact content (SHA-256).
    //  No certificate authority in it: this file, as it was when pinned. For programs
    //  nobody signs (one's own builds), and as good as a signature for any other.
    //
    //  Kept in FirewallManager.json next to the exe, so the app and its pins travel
    //  together. Per pinned path: SHA-256, size, last-write time, the date pinned and
    //  of the last full check, and whether that check matched.
    //
    //  Hashing a large exe takes a moment, so checks are layered:
    //  • at start, size and last-write time only (milliseconds); a file where either
    //    differs is hashed, in the background;
    //  • a pin last fully checked more than 30 days ago is hashed in the background;
    //  • the fingerprint button in the rules list hashes every pinned file, one by one.
    //  A pin that doesn't match shows as changed until the file is pinned again, or until
    //  a later check finds the pinned content back.
    // ─────────────────────────────────────────────────────────────────────────
    internal static class Pins
    {
        public sealed class Pin
        {
            public string Path { get; set; } = "";
            public string Sha256 { get; set; } = "";
            public long Size { get; set; }
            public DateTime LastWriteUtc { get; set; }
            public DateTime Pinned { get; set; }
            public DateTime LastFullCheck { get; set; }
            public bool Matched { get; set; } = true;
        }

        private sealed class Store
        {
            public int Version { get; set; } = 1;
            public List<Pin> Pins { get; set; } = new();
        }

        /// <summary>Checking: size or date changed since the pin, and the fingerprint is being computed.</summary>
        public enum State { None, Confirmed, Mismatch, Missing, Checking }

        /// <summary>A pin as it stands now. Quick: only size and date were compared since the last full check.</summary>
        public sealed record Status(State State, Pin? Pin, bool Quick);

        private static readonly TimeSpan FullCheckAge = TimeSpan.FromDays(30);
        private static readonly object Gate = new();
        private static Store? _store;
        private static readonly Dictionary<string, bool> Quick = new(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> Checking = new(StringComparer.OrdinalIgnoreCase);
        // The file couldn't be read: nothing is written over it, so the pins in it aren't lost.
        private static string? _unreadable;

        /// <summary>The app's own settings file, next to the exe (AppContext.BaseDirectory, single-file safe).</summary>
        public static string FilePath => System.IO.Path.Combine(AppContext.BaseDirectory, "FirewallManager.json");

        /// <summary>Raised (on any thread) when a check changed what a pin shows.</summary>
        public static event Action? Changed;

        /// <summary>The full path a rule's program stands for, as pins are keyed.</summary>
        public static string Key(string program)
        {
            try { return System.IO.Path.GetFullPath(Environment.ExpandEnvironmentVariables(program.Trim())); }
            catch { return program.Trim(); }
        }

        public static bool Any { get { lock (Gate) return Load().Pins.Count > 0; } }

        public static Status For(string program)
        {
            var key = Key(program);
            lock (Gate)
            {
                var pin = Load().Pins.FirstOrDefault(p => p.Path.Equals(key, StringComparison.OrdinalIgnoreCase));
                if (pin == null) return new Status(State.None, null, false);
                if (!File.Exists(key)) return new Status(State.Missing, pin, false);
                if (Checking.Contains(key)) return new Status(State.Checking, pin, false);
                return new Status(pin.Matched ? State.Confirmed : State.Mismatch, pin, Quick.GetValueOrDefault(key));
            }
        }

        /// <summary>Pins the file as it is now. Null, or why it couldn't be saved.</summary>
        public static string? Add(string program)
        {
            RetryUnreadable();
            var key = Key(program);
            Pin pin;
            try
            {
                var info = new FileInfo(key);
                if (!info.Exists) return "the file isn't there";
                pin = new Pin
                {
                    Path = key, Sha256 = Hash(key), Size = info.Length, LastWriteUtc = info.LastWriteTimeUtc,
                    Pinned = DateTime.Now, LastFullCheck = DateTime.Now, Matched = true,
                };
            }
            catch (Exception ex) { return $"the file can't be read ({ex.Message.TrimEnd('.')})"; }

            lock (Gate)
            {
                var store = Load();
                store.Pins.RemoveAll(p => p.Path.Equals(key, StringComparison.OrdinalIgnoreCase));
                store.Pins.Add(pin);
                Quick.Remove(key);
                Session.Add(key);   // just hashed
                return Save(store);
            }
        }

        /// <summary>Removes the pin. Null, or why it couldn't be saved.</summary>
        public static string? Remove(string program)
        {
            RetryUnreadable();
            var key = Key(program);
            lock (Gate)
            {
                var store = Load();
                if (store.Pins.RemoveAll(p => p.Path.Equals(key, StringComparison.OrdinalIgnoreCase)) == 0) return null;
                Quick.Remove(key);
                Session.Remove(key);
                return Save(store);
            }
        }

        /// <summary>
        /// The check at start: size and date for every pin, a full hash in the background where
        /// they differ or the last full check is older than 30 days. Never blocks.
        /// </summary>
        public static void CheckAtStart()
        {
            List<Pin> toHash;
            lock (Gate)
            {
                toHash = new List<Pin>();
                foreach (var pin in Load().Pins)
                {
                    var info = new FileInfo(pin.Path);
                    if (!info.Exists) continue;
                    var same = info.Length == pin.Size && info.LastWriteTimeUtc == pin.LastWriteUtc;
                    if (same && pin.Matched) Quick[pin.Path] = true;
                    if (!same) Checking.Add(pin.Path);   // not "matches" while it isn't known
                    if (!same || DateTime.Now - pin.LastFullCheck > FullCheckAge) toHash.Add(pin);
                }
            }
            if (toHash.Count > 0) _ = Task.Run(() => HashAll(toHash, null, CancellationToken.None));
        }

        /// <summary>The pinned files, as keyed (full paths).</summary>
        public static List<string> Paths() { lock (Gate) return Load().Pins.Select(p => p.Path).ToList(); }

        /// <summary>True when some pinned file no longer matches its pin.</summary>
        public static bool AnyMismatch { get { lock (Gate) return Load().Pins.Any(p => !p.Matched && File.Exists(p.Path)); } }

        /// <summary>The file was hashed in this session and matched: what the green mark stands for.</summary>
        public static bool CheckedThisSession(string program)
        {
            var key = Key(program);
            lock (Gate) return Session.Contains(key);
        }

        /// <summary>
        /// Hashes one pinned file now (the fingerprint button, file by file) and saves the result.
        /// Takes as long as the file is big: call it off the window's thread.
        /// </summary>
        public static State CheckOne(string program)
        {
            var key = Key(program);
            Pin? pin;
            lock (Gate) pin = Load().Pins.FirstOrDefault(p => p.Path.Equals(key, StringComparison.OrdinalIgnoreCase));
            if (pin == null) return State.None;
            HashOne(pin);
            lock (Gate) Save(Load());
            return For(key).State;
        }

        // Matched in this session (a full hash), by key.
        private static readonly HashSet<string> Session = new(StringComparer.OrdinalIgnoreCase);

        private static void HashAll(List<Pin> pins, IProgress<(int, int)>? progress, CancellationToken cancel)
        {
            var done = 0;
            foreach (var pin in pins)
            {
                if (cancel.IsCancellationRequested) break;
                HashOne(pin);
                progress?.Report((++done, pins.Count));
            }
            lock (Gate) Save(Load());
            try { Changed?.Invoke(); } catch { }
        }

        private static void HashOne(Pin pin)
        {
            try
            {
                var info = new FileInfo(pin.Path);
                if (!info.Exists)
                {
                    lock (Gate) { Checking.Remove(pin.Path); Session.Remove(pin.Path); }   // gone: the icon says so
                    return;
                }
                var matched = Hash(pin.Path).Equals(pin.Sha256, StringComparison.OrdinalIgnoreCase);
                lock (Gate)
                {
                    pin.Matched = matched;
                    pin.LastFullCheck = DateTime.Now;
                    // A file that matches but was touched (copied back, date reset): the quick
                    // check compares against what it is now.
                    if (matched) { pin.Size = info.Length; pin.LastWriteUtc = info.LastWriteTimeUtc; }
                    Quick.Remove(pin.Path);
                    Checking.Remove(pin.Path);
                    if (matched) Session.Add(pin.Path); else Session.Remove(pin.Path);
                }
            }
            catch { lock (Gate) { Checking.Remove(pin.Path); Session.Remove(pin.Path); } /* unreadable now: the pin keeps what it last knew */ }
        }

        private static string Hash(string path)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20);
            return Convert.ToHexString(SHA256.HashData(stream));
        }

        // ── the file ──────────────────────────────────────────────────────────

        private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

        // A file that couldn't be read (fixed since, or locked by a scanner then) is read again
        // before a pin is changed, rather than refusing for the rest of the session.
        private static void RetryUnreadable()
        {
            lock (Gate)
            {
                if (_unreadable == null) return;
                _unreadable = null;
                _store = null;
                Load();
            }
        }

        private static Store Load()
        {
            if (_store != null) return _store;
            try
            {
                _store = File.Exists(FilePath)
                    ? JsonSerializer.Deserialize<Store>(File.ReadAllText(FilePath), Options) ?? new Store()
                    : new Store();
            }
            catch (Exception ex)
            {
                _store = new Store();
                _unreadable = ex.Message.TrimEnd('.');
            }
            _store.Pins ??= new List<Pin>();
            return _store;
        }

        private static string? Save(Store store)
        {
            if (_unreadable != null)
                return $"{System.IO.Path.GetFileName(FilePath)} can't be read ({_unreadable}), so it isn't written over: fix or remove it first";
            try
            {
                File.WriteAllText(FilePath, JsonSerializer.Serialize(store, Options));
                return null;
            }
            catch (UnauthorizedAccessException) { return "the app's folder is read-only, so pins can't be kept there"; }
            catch (Exception ex) { return ex.Message.TrimEnd('.'); }
        }
    }
}
