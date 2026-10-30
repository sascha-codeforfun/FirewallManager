using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  ConfigService — decides, per section, whether config.json or the
    //  compiled-in baseline wins. Decisions persist in HKCU\Software\GeekFirewallManager.
    //
    //  ReconcileOnSetup() asks only when the file's canonical hash differs from
    //  the last acknowledged one, so an unchanged config never prompts again.
    //  File values are used only while the file is exactly what was acknowledged
    //  and holds no impossible values: a file changed since, by anyone, falls back
    //  to the baseline until it has been reviewed in Setup.
    //  The default and the dismiss fallback are always the baseline side.
    //  Consumers read Effective(), never the baseline directly.
    // ─────────────────────────────────────────────────────────────────────────
    public static class ConfigService
    {
        private const string RegPath = @"Software\GeekFirewallManager";

        public enum Section { Noise, DnsPresets, Services, OrgTags, EncryptedDns }

        private static AppConfig.LoadResult? _load;
        private static AppConfig _file = AppConfig.Baseline();
        private static readonly Dictionary<Section, bool> _useJson = new()
        {
            [Section.Noise] = false, [Section.DnsPresets] = false,
            [Section.Services] = false, [Section.OrgTags] = false,
            [Section.EncryptedDns] = false,
        };
        private static bool _loaded;
        private static bool _approved;

        public static AppConfig.LoadStatus Status => _load?.Status ?? AppConfig.LoadStatus.UsedBaselineNoFile;
        public static string? LoadError => _load?.Error;
        public static bool FileUsable => _load?.Status == AppConfig.LoadStatus.UsedFile;

        public static void EnsureLoaded()
        {
            if (_loaded) return;
            _load = AppConfig.Load();
            _file = _load.Config;
            LoadDecisions();
            _loaded = true;
            _approved = FileUsable && !string.IsNullOrEmpty(_load.Hash) && _load.Hash == ReadStoredHash()
                        && ImpossibleValues().Count == 0;
        }

        /// <summary>Force a fresh read (e.g. after the user exports/edits a config.json this session).</summary>
        public static void Reload()
        {
            _loaded = false;
            EnsureLoaded();
        }

        /// <summary>Per-section: file values if chosen & usable, else baseline. Never null sections.</summary>
        public static AppConfig Effective()
        {
            EnsureLoaded();
            var bl = AppConfig.Baseline();
            return new AppConfig
            {
                Version    = _file.Version,
                Noise      = (_useJson[Section.Noise]      && _approved) ? _file.Noise      : bl.Noise,
                DnsPresets = (_useJson[Section.DnsPresets] && _approved) ? _file.DnsPresets : bl.DnsPresets,
                Services   = (_useJson[Section.Services]   && _approved) ? _file.Services   : bl.Services,
                OrgTags    = (_useJson[Section.OrgTags]    && _approved) ? _file.OrgTags    : bl.OrgTags,
                EncryptedDns = (_useJson[Section.EncryptedDns] && _approved) ? _file.EncryptedDns : bl.EncryptedDns,
            };
        }

        /// <summary>Sections whose file content differs from baseline (empty if no usable file).</summary>
        public static List<Section> DifferingSections()
        {
            EnsureLoaded();
            var diffs = new List<Section>();
            if (!FileUsable) return diffs;
            var bl = AppConfig.Baseline();
            if (AppConfig.CanonicalOf(_file.Noise)      != AppConfig.CanonicalOf(bl.Noise))      diffs.Add(Section.Noise);
            if (AppConfig.CanonicalOf(_file.DnsPresets) != AppConfig.CanonicalOf(bl.DnsPresets)) diffs.Add(Section.DnsPresets);
            if (AppConfig.CanonicalOf(_file.Services)   != AppConfig.CanonicalOf(bl.Services))   diffs.Add(Section.Services);
            if (AppConfig.CanonicalOf(_file.OrgTags)    != AppConfig.CanonicalOf(bl.OrgTags))    diffs.Add(Section.OrgTags);
            if (AppConfig.CanonicalOf(_file.EncryptedDns) != AppConfig.CanonicalOf(bl.EncryptedDns)) diffs.Add(Section.EncryptedDns);
            return diffs;
        }

        /// <summary>Impossible values in the file (bad IPv4 octets, CIDR prefix out of
        /// range, malformed fragments) as human-readable messages; empty means coherent.
        /// Valid but risky values are not flagged: that is the user's call.</summary>
        public static List<string> ImpossibleValues()
        {
            EnsureLoaded();
            var bad = new List<string>();
            if (!FileUsable) return bad;

            foreach (var svc in _file.Services)
                foreach (var c in svc.Cidrs)
                    if (BadCidr(c, out var why)) bad.Add($"services/{svc.Name}: \"{c}\" — {why}");

            foreach (var ot in _file.OrgTags)
                foreach (var p in ot.Prefixes)
                    if (BadPrefix(p, out var why)) bad.Add($"orgTags/{ot.Tag}: \"{p}\" — {why}");

            foreach (var dp in _file.DnsPresets)
                if (!string.IsNullOrWhiteSpace(dp.Ip) && !IsSentinel(dp.Ip) && BadIp(dp.Ip, out var why))
                    bad.Add($"dnsPresets/{dp.Label}: \"{dp.Ip}\" — {why}");

            foreach (var ed in _file.EncryptedDns)
                foreach (var p in ed.Prefixes)
                    if (BadPrefix(p, out var why)) bad.Add($"encryptedDns/{ed.Name}: \"{p}\" — {why}");

            return bad;
        }

        // Non-IP keywords the app itself writes and resolves at runtime, so the
        // validator must not flag them. "gateway" is the preset that resolves to the gateway.
        private static readonly HashSet<string> Sentinels =
            new(System.StringComparer.OrdinalIgnoreCase) { "gateway" };

        private static bool IsSentinel(string v) => Sentinels.Contains(v.Trim());

        private static bool BadOctet(string s, out string why)
        {
            why = "";
            if (!int.TryParse(s, out var n)) { why = $"'{s}' is not a number"; return true; }
            if (n < 0 || n > 255)            { why = $"octet {n} > 255"; return true; }
            return false;
        }

        // An IP-prefix fragment like "642.82." — each present octet must be 0..255.
        private static bool BadPrefix(string p, out string why)
        {
            why = "";
            if (string.IsNullOrWhiteSpace(p)) { why = "empty prefix"; return true; }
            foreach (var seg in p.Split('.'))
                if (seg.Length > 0 && BadOctet(seg, out why)) return true;
            return false;
        }

        private static bool BadIp(string ip, out string why)
        {
            why = "";
            var segs = ip.Split('.');
            if (segs.Length != 4) { why = $"not 4 octets"; return true; }
            foreach (var seg in segs) if (BadOctet(seg, out why)) return true;
            return false;
        }

        private static bool BadCidr(string cidr, out string why)
        {
            why = "";
            var slash = cidr.IndexOf('/');
            var ipPart = slash >= 0 ? cidr[..slash] : cidr;
            if (BadIp(ipPart, out why)) return true;
            if (slash >= 0)
            {
                var bitsStr = cidr[(slash + 1)..];
                if (!int.TryParse(bitsStr, out var bits)) { why = $"prefix '/{bitsStr}' not a number"; return true; }
                if (bits < 0 || bits > 32) { why = $"prefix /{bits} out of range (0–32)"; return true; }
                if (bits == 0) { why = "prefix /0: Windows refuses to load a rule with it"; return true; }
            }
            return false;
        }

        /// <summary>Names of the entries within a section that differ from baseline,
        /// for showing the user what changed.</summary>
        public static List<string> ChangedEntries(Section s)
        {
            EnsureLoaded();
            var changed = new List<string>();
            if (!FileUsable) return changed;
            var bl = AppConfig.Baseline();

            switch (s)
            {
                case Section.Services:
                    foreach (var f in _file.Services)
                    {
                        var b = bl.Services.FirstOrDefault(x => x.Name == f.Name);
                        if (b == null || AppConfig.CanonicalOf(f) != AppConfig.CanonicalOf(b)) changed.Add(f.Name);
                    }
                    foreach (var b in bl.Services)
                        if (!_file.Services.Any(x => x.Name == b.Name)) changed.Add(b.Name + " (removed)");
                    break;
                case Section.OrgTags:
                    foreach (var f in _file.OrgTags)
                    {
                        var b = bl.OrgTags.FirstOrDefault(x => x.Tag == f.Tag);
                        if (b == null || AppConfig.CanonicalOf(f) != AppConfig.CanonicalOf(b)) changed.Add(f.Tag);
                    }
                    break;
                case Section.DnsPresets:
                    if (AppConfig.CanonicalOf(_file.DnsPresets) != AppConfig.CanonicalOf(bl.DnsPresets))
                        changed.Add("preset list");
                    break;
                case Section.EncryptedDns:
                    foreach (var f in _file.EncryptedDns)
                    {
                        var b = bl.EncryptedDns.FirstOrDefault(x => x.Name == f.Name);
                        if (b == null || AppConfig.CanonicalOf(f) != AppConfig.CanonicalOf(b)) changed.Add(f.Name);
                    }
                    foreach (var b in bl.EncryptedDns)
                        if (!_file.EncryptedDns.Any(x => x.Name == b.Name)) changed.Add(b.Name + " (removed)");
                    break;
                case Section.Noise:
                    foreach (var f in _file.Noise)
                    {
                        var b = bl.Noise.FirstOrDefault(x => x.Name == f.Name);
                        if (b == null || AppConfig.CanonicalOf(f) != AppConfig.CanonicalOf(b)) changed.Add(f.Name);
                    }
                    break;
            }
            return changed;
        }

        /// <summary>
        /// Called when Setup opens. If the file's hash matches the last acknowledged hash,
        /// stored decisions apply silently; otherwise the user chooses per differing
        /// section and the new hash and decisions are stored. Shows dialogs.
        /// </summary>
        public static void ReconcileOnSetup(Window owner)
        {
            Reload();                  // the user may have edited config.json this session,
                                       // and EnsureLoaded caches
            if (!FileUsable) return;

            // Impossible values are incoherent rather than a risky choice, so the whole file
            // stays at the baseline (EnsureLoaded doesn't approve it), the user is shown the
            // problems, and the hash is not acknowledged: every Setup open re-checks until fixed.
            var impossible = ImpossibleValues();
            if (impossible.Count > 0)
            {
                new ConsentWindow(impossible) { Owner = owner }.ShowDialog();
                return;
            }

            var fileHash   = _load!.Hash;
            var storedHash = ReadStoredHash();

            if (!string.IsNullOrEmpty(storedHash) && fileHash == storedHash)
                return;

            var diffs = DifferingSections();
            if (diffs.Count == 0)
            {
                StoreHashAndDecisions(fileHash);   // same as baseline: nothing to ask
                _approved = true;
                return;
            }

            // Closed without a button (X, Alt+F4, Esc): nothing was chosen, so nothing is
            // acknowledged. The file stays unapproved, the baseline applies, and the next
            // Setup open asks again.
            var dlg = new ConfigReconcileWindow(diffs, _useJson) { Owner = owner };
            if (dlg.ShowDialog() != true)
            {
                _approved = false;
                return;
            }
            foreach (var kv in dlg.Decisions) _useJson[kv.Key] = kv.Value;

            StoreHashAndDecisions(fileHash);
            _approved = true;
        }

        // ── registry ─────────────────────────────────────────────────────────
        private static string ReadStoredHash()
        {
            try { using var k = Registry.CurrentUser.OpenSubKey(RegPath);
                  return k?.GetValue("ConfigHash")?.ToString() ?? ""; }
            catch { return ""; }
        }

        private static void StoreHashAndDecisions(string hash)
        {
            try
            {
                using var k = Registry.CurrentUser.CreateSubKey(RegPath);
                k?.SetValue("ConfigHash", hash, RegistryValueKind.String);
                k?.SetValue("ConfigDecisions", EncodeDecisions(), RegistryValueKind.String);
            }
            catch { }
        }

        private static void LoadDecisions()
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(RegPath);
                DecodeDecisions(k?.GetValue("ConfigDecisions")?.ToString() ?? "");
            }
            catch { }
        }

        private static string EncodeDecisions()
            => $"noise={B(Section.Noise)};dns={B(Section.DnsPresets)};services={B(Section.Services)};orgtags={B(Section.OrgTags)};encdns={B(Section.EncryptedDns)}";
        private static string B(Section s) => _useJson[s] ? "json" : "hardcoded";

        private static void DecodeDecisions(string s)
        {
            foreach (var part in s.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var kv = part.Split('=');
                if (kv.Length != 2) continue;
                var json = kv[1].Trim().Equals("json", StringComparison.OrdinalIgnoreCase);
                switch (kv[0].Trim().ToLowerInvariant())
                {
                    case "noise":    _useJson[Section.Noise]      = json; break;
                    case "dns":      _useJson[Section.DnsPresets]  = json; break;
                    case "services": _useJson[Section.Services]   = json; break;
                    case "orgtags":  _useJson[Section.OrgTags]     = json; break;
                    case "encdns":   _useJson[Section.EncryptedDns] = json; break;
                }
            }
        }
    }
}
