using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  AppConfig — the app's externalized "knowledge" (config.json).
    //
    //  Design (per the release plan):
    //    • The JSON holds ALL app knowledge: noise predicates, DNS presets,
    //      service CIDR ranges, and LogViewer org-tags. Nothing knowledge-like
    //      is hardcoded-only; the compiled-in Baseline() is purely a fallback.
    //    • config.json present  -> use it
    //    • config.json missing  -> use Baseline()
    //    • config.json corrupt  -> use Baseline() + warn once
    //    • config.json disagrees with Baseline() -> caller reconciles per-section
    //      (surfaced on Setup, hash-gated so an unchanged file never re-nags).
    //
    //  Windows reality (see sascha-codeforfun/EolInspector): a JSON file's BYTES
    //  can differ (CRLF vs LF vs CR vs Mixed, UTF-8 BOM vs none, trailing ws,
    //  key order) with no change in MEANING. So we never hash raw bytes. We parse
    //  into this typed model and hash the model round-tripped through a canonical
    //  serialization (UTF-8, no BOM, LF, fixed property order). Only a real value
    //  change moves the hash. We are liberal in what we read (any EOL/BOM) and
    //  strict in what we write (UTF-8 / no BOM / LF).
    // ─────────────────────────────────────────────────────────────────────────

    public sealed class AppConfig
    {
        [JsonPropertyName("version")]
        public int Version { get; set; } = 1;

        [JsonPropertyName("noise")]
        public List<NoiseCategory> Noise { get; set; } = new();

        [JsonPropertyName("dnsPresets")]
        public List<DnsPreset> DnsPresets { get; set; } = new();

        [JsonPropertyName("services")]
        public List<ServiceRanges> Services { get; set; } = new();

        [JsonPropertyName("orgTags")]
        public List<OrgTag> OrgTags { get; set; } = new();

        // ── Section types ────────────────────────────────────────────────────

        public sealed class NoiseCategory
        {
            [JsonPropertyName("name")]       public string Name { get; set; } = "";
            [JsonPropertyName("suppress")]   public bool Suppress { get; set; } = true;
            // Match predicates — any populated list contributes (OR semantics).
            [JsonPropertyName("ipPrefixes")] public List<string> IpPrefixes { get; set; } = new();
            [JsonPropertyName("ipSuffixes")] public List<string> IpSuffixes { get; set; } = new();
            [JsonPropertyName("ipExact")]    public List<string> IpExact { get; set; } = new();
            [JsonPropertyName("ports")]      public List<string> Ports { get; set; } = new();
            // Loopback also checks the SOURCE ip; flagged so the consumer knows.
            [JsonPropertyName("matchSource")] public bool MatchSource { get; set; } = false;
            [JsonPropertyName("note")]       public string Note { get; set; } = "";
        }

        public sealed class DnsPreset
        {
            [JsonPropertyName("label")] public string Label { get; set; } = "";
            [JsonPropertyName("ip")]    public string Ip { get; set; } = "";
        }

        public sealed class ServiceRanges
        {
            [JsonPropertyName("name")]   public string Name { get; set; } = "";
            [JsonPropertyName("cidrs")]  public List<string> Cidrs { get; set; } = new();
            [JsonPropertyName("note")]   public string Note { get; set; } = "";
        }

        public sealed class OrgTag
        {
            [JsonPropertyName("tag")]      public string Tag { get; set; } = "";
            [JsonPropertyName("prefixes")] public List<string> Prefixes { get; set; } = new();
        }

        // ── Locations ────────────────────────────────────────────────────────

        /// <summary>config.json sits next to the executable.</summary>
        public static string ConfigPath =>
            Path.Combine(AppContext.BaseDirectory, "config.json");

        // ── Compiled-in baseline (the trusted fallback) ──────────────────────
        //  This is the COMPLETE current knowledge harvested from the app. If
        //  config.json is absent or unparseable, the app runs on exactly this.

        public static AppConfig Baseline() => new AppConfig
        {
            Version = 1,
            Noise = new()
            {
                new() { Name = "Multicast",  IpPrefixes = { "224.", "239." },                     Note = "224.x / 239.x" },
                new() { Name = "Broadcast",  IpSuffixes = { ".255" }, IpExact = { "255.255.255.255" }, Note = "x.x.x.255 / 255.255.255.255" },
                new() { Name = "Link-local", IpPrefixes = { "169.254." },                          Note = "169.254.x" },
                new() { Name = "NetBIOS",    Ports = { "137", "138", "139" },                       Note = "ports 137/138/139" },
                new() { Name = "mDNS",       Ports = { "5353" },                                    Note = "port 5353" },
                new() { Name = "SSDP/WSD",   Ports = { "1900", "3702", "5357" },                    Note = "ports 1900/3702/5357" },
                new() { Name = "LLMNR",      Ports = { "5355" },                                    Note = "port 5355" },
                new() { Name = "Loopback",   IpPrefixes = { "127." }, MatchSource = true,           Note = "127.x — local IPC, never egress" },
            },
            DnsPresets = new()
            {
                new() { Label = "Gateway (auto)",         Ip = "gateway" },
                new() { Label = "Cloudflare 1.1.1.1",     Ip = "1.1.1.1" },
                new() { Label = "Cloudflare 1.0.0.1",     Ip = "1.0.0.1" },
                new() { Label = "Google 8.8.8.8",         Ip = "8.8.8.8" },
                new() { Label = "Google 8.8.4.4",         Ip = "8.8.4.4" },
                new() { Label = "Quad9 9.9.9.9",          Ip = "9.9.9.9" },
                new() { Label = "Quad9 149.112.112.112",  Ip = "149.112.112.112" },
                new() { Label = "OpenDNS 208.67.222.222", Ip = "208.67.222.222" },
                new() { Label = "OpenDNS 208.67.220.220", Ip = "208.67.220.220" },
            },
            Services = new()
            {
                new() { Name = "GitHub",       Cidrs = { "140.82.112.0/20", "192.30.252.0/22", "185.199.108.0/22", "20.201.28.0/22" }, Note = "github.com / api / codeload — public ranges, may rotate" },
                new() { Name = "WinUpdate",    Cidrs = { "13.107.4.0/24", "13.107.5.0/24", "204.79.197.200/32", "20.112.250.0/24" },   Note = "Windows Update core (CDN-sprawling; coarse)" },
                new() { Name = "VSUpdate",     Cidrs = { "13.107.6.0/24", "13.107.9.0/24", "13.107.42.0/24", "20.190.128.0/18" },      Note = "Visual Studio update" },
                new() { Name = "OfficeUpdate", Cidrs = { "13.107.18.0/24", "13.107.19.0/24", "52.108.0.0/14", "52.238.106.0/24" },     Note = "Office update / CDN" },
            },
            OrgTags = new()
            {
                new() { Tag = "github?",    Prefixes = { "140.82." } },
                new() { Tag = "fastly?",    Prefixes = { "199.232." } },
                new() { Tag = "cloudflare?", Prefixes = { "104.16.", "104.17.", "104.18.", "104.19.", "172.64.", "172.67.", "162.159." } },
                new() { Tag = "microsoft?", Prefixes = { "13.107.", "20.190.", "40.126." } },
                new() { Tag = "nuget/ms?",  Prefixes = { "150.171." } },
            },
        };

        // ── Load ─────────────────────────────────────────────────────────────

        public enum LoadStatus { UsedBaselineNoFile, UsedFile, UsedBaselineParseError }

        public sealed class LoadResult
        {
            public AppConfig Config = Baseline();
            public LoadStatus Status = LoadStatus.UsedBaselineNoFile;
            public string? Error;
            /// <summary>Canonical hash of the loaded config (for nag-gating).</summary>
            public string Hash = "";
        }

        private static readonly JsonSerializerOptions ReadOpts = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };

        /// <summary>
        /// Read config.json if present (tolerant of any EOL/BOM), else fall back
        /// to the baseline. Never throws — corrupt files degrade to baseline.
        /// </summary>
        public static LoadResult Load()
        {
            var r = new LoadResult();
            try
            {
                if (!File.Exists(ConfigPath))
                {
                    r.Config  = Baseline();
                    r.Status  = LoadStatus.UsedBaselineNoFile;
                    r.Hash    = CanonicalHash(r.Config);
                    return r;
                }

                // File.ReadAllText strips a UTF-8 BOM automatically; System.Text.Json
                // tolerates any line endings in whitespace. So CRLF/LF/CR/Mixed and
                // BOM-or-not all parse identically.
                var text = File.ReadAllText(ConfigPath);
                var cfg  = JsonSerializer.Deserialize<AppConfig>(text, ReadOpts);

                if (cfg == null)
                {
                    r.Config = Baseline();
                    r.Status = LoadStatus.UsedBaselineParseError;
                    r.Error  = "config.json parsed to null.";
                    r.Hash   = CanonicalHash(r.Config);
                    return r;
                }

                r.Config = cfg;
                r.Status = LoadStatus.UsedFile;
                r.Hash   = CanonicalHash(cfg);
                return r;
            }
            catch (Exception ex)
            {
                r.Config = Baseline();
                r.Status = LoadStatus.UsedBaselineParseError;
                r.Error  = ex.Message;
                r.Hash   = CanonicalHash(r.Config);
                return r;
            }
        }

        // ── Canonical serialization + hash (EOL/BOM/whitespace/key-order immune) ─

        // Deterministic writer: indented, fixed property order (model order),
        // no BOM. We then normalize newlines to LF before hashing so the hash
        // depends only on VALUES, never on how the bytes were stored.
        private static readonly JsonSerializerOptions CanonicalOpts = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        /// <summary>Canonical JSON text: round-tripped through the typed model, LF, no BOM.</summary>
        public static string CanonicalJson(AppConfig cfg) => CanonicalOf(cfg);

        /// <summary>Canonical serialization of any model object (LF-normalized) — used for per-section diffing.</summary>
        public static string CanonicalOf<T>(T obj)
        {
            var json = JsonSerializer.Serialize(obj, CanonicalOpts);
            return json.Replace("\r\n", "\n").Replace("\r", "\n");
        }

        /// <summary>
        /// SHA-256 of the canonical JSON (UTF-8, no BOM). Because we serialize
        /// FROM the parsed model, the input file's EOL style, BOM, indentation,
        /// trailing whitespace, and object key order are all irrelevant — two
        /// files that mean the same thing hash the same.
        /// </summary>
        public static string CanonicalHash(AppConfig cfg)
        {
            var canonical = CanonicalJson(cfg);
            var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(canonical);
            var hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash);   // upper-case hex, no dashes
        }

        // ── Write (template export) ──────────────────────────────────────────

        /// <summary>
        /// Write a config.json. Always UTF-8, NO BOM, LF endings — the clean
        /// single-style file EolInspector treats as well-behaved, so the app
        /// never emits the Mixed/BOM files its sibling tool exists to flag.
        /// </summary>
        public static void Write(AppConfig cfg, string path)
        {
            var canonical = CanonicalJson(cfg);                 // LF, no BOM, deterministic
            var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            File.WriteAllText(path, canonical, utf8NoBom);
        }

        /// <summary>Write the baseline out as an editable template at the default location.</summary>
        public static void WriteTemplate(string? path = null)
            => Write(Baseline(), path ?? ConfigPath);
    }
}
