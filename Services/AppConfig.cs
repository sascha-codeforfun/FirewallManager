using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  AppConfig — the app's editable knowledge (config.json): noise predicates,
    //  DNS presets, service CIDR ranges, org-tags and encrypted-DNS servers.
    //  Baseline() is the fallback when the file is missing or corrupt; when the
    //  file disagrees with it, the caller reconciles per section.
    //
    //  The same JSON can be stored with different bytes (EOL style, BOM, trailing
    //  whitespace, key order), so the hash is taken over the parsed model in a
    //  canonical serialization, never over raw bytes: only a real value change
    //  moves it. Reading accepts any EOL/BOM; writing is always UTF-8, no BOM, LF.
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

        // Known encrypted-DNS servers (DNS over HTTPS / TLS): a program talking to one of these
        // on 443 or 853, or looking one of these names up, is resolving around your resolver.
        [JsonPropertyName("encryptedDns")]
        public List<EncryptedDnsServer> EncryptedDns { get; set; } = new();

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
            // 255.255.255.255 and the broadcast address of each network this machine is on (read
            // live), so a host that merely ends in .255 still shows. Not written while false, so a
            // config.json without it keeps the hash it was approved with.
            [JsonPropertyName("localBroadcast")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
            public bool LocalBroadcast { get; set; } = false;
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

        public sealed class EncryptedDnsServer
        {
            [JsonPropertyName("name")]     public string Name { get; set; } = "";
            // Host names; a name also matches its subdomains (abc.dns.nextdns.io).
            [JsonPropertyName("hosts")]    public List<string> Hosts { get; set; } = new();
            // IPv4 prefixes, like the org-tags ("1.1.1.").
            [JsonPropertyName("prefixes")] public List<string> Prefixes { get; set; } = new();
        }

        // ── Locations ────────────────────────────────────────────────────────

        public static string ConfigPath =>
            Path.Combine(AppContext.BaseDirectory, "config.json");

        // ── Compiled-in baseline (the trusted fallback) ──────────────────────
        //  Complete on its own: if config.json is absent or unparseable, the app
        //  runs on exactly this.

        public static AppConfig Baseline() => new AppConfig
        {
            Version = 1,
            Noise = new()
            {
                new() { Name = "Multicast",  IpPrefixes = { "224.", "225.", "226.", "227.", "228.", "229.", "230.", "231.",
                                                           "232.", "233.", "234.", "235.", "236.", "237.", "238.", "239." },
                                                                                                    Note = "224.x–239.x, ff00::/8" },
                new() { Name = "Broadcast",  LocalBroadcast = true,                                 Note = "255.255.255.255 / this machine's network broadcast" },
                new() { Name = "Link-local", IpPrefixes = { "169.254." },                          Note = "169.254.x, fe80::/10" },
                new() { Name = "NetBIOS",    Ports = { "137", "138", "139" },                       Note = "ports 137/138/139" },
                new() { Name = "mDNS",       Ports = { "5353" },                                    Note = "port 5353" },
                new() { Name = "SSDP/WSD",   Ports = { "1900", "3702", "5357" },                    Note = "ports 1900/3702/5357" },
                new() { Name = "LLMNR",      Ports = { "5355" },                                    Note = "port 5355" },
                new() { Name = "Loopback",   IpPrefixes = { "127." }, MatchSource = true,           Note = "127.x, ::1 — local IPC, never egress" },
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
                new() { Name = "GitHub", Cidrs = { "140.82.112.0/20", "192.30.252.0/22", "185.199.108.0/22", "20.201.28.0/22" }, Note = "github.com / api / codeload — public ranges, may rotate" },
            },
            OrgTags = new()
            {
                new() { Tag = "github?",    Prefixes = { "140.82." } },
                new() { Tag = "fastly?",    Prefixes = { "199.232." } },
                new() { Tag = "cloudflare?", Prefixes = { "104.16.", "104.17.", "104.18.", "104.19.", "172.64.", "172.67.", "162.159." } },
                // 150.171.x is Microsoft's in general (Bing, Azure Front Door, NuGet's CDN among
                // others), so a narrower tag such as "nuget" would mislabel unrelated traffic.
                new() { Tag = "microsoft?", Prefixes = { "13.107.", "20.190.", "40.126.", "150.171." } },
            },
            EncryptedDns = new()
            {
                new() { Name = "Cloudflare",     Hosts = { "cloudflare-dns.com", "one.one.one.one" },
                                                 Prefixes = { "1.1.1.", "1.0.0.", "162.159.36.", "162.159.46." } },
                new() { Name = "Google",         Hosts = { "dns.google", "dns.google.com", "8888.google" },
                                                 Prefixes = { "8.8.8.", "8.8.4." } },
                new() { Name = "Quad9",          Hosts = { "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net" },
                                                 Prefixes = { "9.9.9.", "149.112.112." } },
                new() { Name = "OpenDNS DoH",    Hosts = { "doh.opendns.com", "doh.familyshield.opendns.com" },
                                                 Prefixes = { "146.112.41." } },
                new() { Name = "AdGuard",        Hosts = { "dns.adguard.com", "dns.adguard-dns.com", "unfiltered.adguard-dns.com", "family.adguard-dns.com" },
                                                 Prefixes = { "94.140.14.", "94.140.15." } },
                new() { Name = "NextDNS",        Hosts = { "dns.nextdns.io" },
                                                 Prefixes = { "45.90.28.", "45.90.30." } },
                new() { Name = "CleanBrowsing",  Hosts = { "doh.cleanbrowsing.org" },
                                                 Prefixes = { "185.228.168.", "185.228.169." } },
                new() { Name = "Mullvad",        Hosts = { "dns.mullvad.net", "doh.mullvad.net" },
                                                 Prefixes = { "194.242.2." } },
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

        /// <summary>Never throws: a missing or corrupt config.json degrades to the baseline.</summary>
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

                // File.ReadAllText strips a UTF-8 BOM and System.Text.Json accepts any
                // line endings, so every EOL/BOM variant parses identically.
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

                // Valid JSON can still say null where a list or text belongs. An empty list is a
                // real setting, so null isn't read as one: the file counts as unreadable instead.
                if (NullIn(cfg) is { } where)
                {
                    r.Config = Baseline();
                    r.Status = LoadStatus.UsedBaselineParseError;
                    r.Error  = $"{where} is null; use [] for an empty list or \"\" for empty text.";
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

        /// <summary>The first place in the file that is null where a value belongs, as a JSON path; or null.</summary>
        private static string? NullIn(AppConfig c)
        {
            static string? List<T>(List<T>? list, string path, Func<T, string, string?> inner) where T : class
            {
                if (list == null) return path;
                for (var i = 0; i < list.Count; i++)
                    if (list[i] is not { } item) return $"{path}[{i}]";
                    else if (inner(item, $"{path}[{i}]") is { } deeper) return deeper;
                return null;
            }
            static string? Texts(List<string>? list, string path) => List(list, path, (_, _) => null);
            static string? Text(string? s, string path) => s == null ? path : null;

            return List(c.Noise, "noise", (n, p) =>
                       Text(n.Name, p + ".name") ?? Texts(n.IpPrefixes, p + ".ipPrefixes") ?? Texts(n.IpSuffixes, p + ".ipSuffixes") ??
                       Texts(n.IpExact, p + ".ipExact") ?? Texts(n.Ports, p + ".ports") ?? Text(n.Note, p + ".note"))
                ?? List(c.DnsPresets, "dnsPresets", (d, p) => Text(d.Label, p + ".label") ?? Text(d.Ip, p + ".ip"))
                ?? List(c.Services, "services", (s, p) => Text(s.Name, p + ".name") ?? Texts(s.Cidrs, p + ".cidrs") ?? Text(s.Note, p + ".note"))
                ?? List(c.OrgTags, "orgTags", (o, p) => Text(o.Tag, p + ".tag") ?? Texts(o.Prefixes, p + ".prefixes"))
                ?? List(c.EncryptedDns, "encryptedDns", (e, p) => Text(e.Name, p + ".name") ?? Texts(e.Hosts, p + ".hosts") ?? Texts(e.Prefixes, p + ".prefixes"));
        }

        // ── Canonical serialization + hash (EOL/BOM/whitespace/key-order immune) ─

        // Deterministic: fixed property order (model order). Newlines are then
        // normalised to LF so the hash depends only on values.
        private static readonly JsonSerializerOptions CanonicalOpts = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        public static string CanonicalJson(AppConfig cfg) => CanonicalOf(cfg);

        /// <summary>LF-normalised canonical JSON of any model object, so sections can be diffed by string.</summary>
        public static string CanonicalOf<T>(T obj)
        {
            var json = JsonSerializer.Serialize(obj, CanonicalOpts);
            return json.Replace("\r\n", "\n").Replace("\r", "\n");
        }

        /// <summary>
        /// SHA-256 of the canonical JSON, as upper-case hex. Two files that mean
        /// the same thing hash the same regardless of EOL, BOM, indentation or key order.
        /// </summary>
        public static string CanonicalHash(AppConfig cfg)
        {
            var canonical = CanonicalJson(cfg);
            var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(canonical);
            var hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash);
        }

        // ── Write (template export) ──────────────────────────────────────────

        /// <summary>
        /// Always UTF-8 without BOM and with LF endings, so the app never emits a
        /// mixed-EOL or BOM file of its own.
        /// </summary>
        public static void Write(AppConfig cfg, string path)
        {
            var canonical = CanonicalJson(cfg);
            var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            File.WriteAllText(path, canonical, utf8NoBom);
        }

        /// <summary>Write the baseline out as an editable template at the default location.</summary>
        public static void WriteTemplate(string? path = null)
            => Write(Baseline(), path ?? ConfigPath);
    }
}
