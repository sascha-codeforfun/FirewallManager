using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace FirewallManager
{
    /// <summary>
    /// What a typed or pasted field may hold, and what to say about a character it may not.
    /// Every place a value goes has its own grammar (the rule string splits on |, the registry
    /// name turns spaces into _, scripts and exports have quotes): plain ASCII keeps all of
    /// them simple. A character that doesn't fit is taken out, named, and plain alternatives
    /// are offered; nothing is changed silently.
    /// </summary>
    internal static class TextHygiene
    {
        /// <summary>For tooltips and the README: what a rule name accepts, and why.</summary>
        public const string NameRule =
            "Plain ASCII (letters, digits, space and the usual punctuation), except | (it separates the fields of a rule) " +
            "and _ (it stands for a space in the rule's registry name).";

        /// <summary>Space to ~: what addresses, ports and the like are made of.</summary>
        public static bool IsPlainAscii(int codePoint) => codePoint is >= 0x20 and <= 0x7E;

        public static bool IsNameChar(int codePoint) => IsPlainAscii(codePoint) && codePoint != '|' && codePoint != '_';

        /// <summary>Why a name can't be saved, or null. Names the first character that doesn't fit.</summary>
        public static string? BadName(string name)
        {
            foreach (var r in name.EnumerateRunes())
            {
                if (r.Value == '|') return "A name can't contain |: it separates the fields of a rule.";
                if (r.Value == '_') return "A name can't contain _: it stands for a space in the rule's registry name. Use a space.";
                if (!IsPlainAscii(r.Value)) return $"A name is plain ASCII: {Describe(r)} isn't allowed.";
            }
            return null;
        }

        public sealed record Removed(int Index, Rune Character);

        /// <summary>
        /// The text without the characters that don't fit, and each one taken out with the
        /// position it had in the cleaned text (where a chosen alternative goes back in).
        /// </summary>
        public static (string Text, List<Removed> Removed) Clean(string text, Func<int, bool> fits)
        {
            var kept = new StringBuilder(text.Length);
            var removed = new List<Removed>();
            foreach (var r in text.EnumerateRunes())
            {
                if (fits(r.Value)) kept.Append(r.ToString());
                else removed.Add(new Removed(kept.Length, r));
            }
            return (kept.ToString(), removed);
        }

        /// <summary>"ü (U+00FC, letter)", or for a hidden character its short name: "ZWSP (U+200B)".</summary>
        public static string Describe(Rune r)
        {
            var code = $"U+{r.Value:X4}";
            if (Hidden(r) is { } hidden) return hidden;
            var kind = Rune.GetUnicodeCategory(r) switch
            {
                UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter
                    or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter => "letter",
                UnicodeCategory.DecimalDigitNumber or UnicodeCategory.LetterNumber or UnicodeCategory.OtherNumber => "digit",
                UnicodeCategory.SpaceSeparator => "space",
                UnicodeCategory.Control or UnicodeCategory.Format => "control character",
                UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark => "accent mark",
                UnicodeCategory.MathSymbol or UnicodeCategory.CurrencySymbol or UnicodeCategory.ModifierSymbol
                    or UnicodeCategory.OtherSymbol => "symbol",
                _ => "punctuation",
            };
            var shown = kind is "control character" or "space" or "accent mark" ? "" : r.ToString() + " ";
            return $"{shown}({code}, {kind})".TrimStart();
        }

        /// <summary>
        /// Plain ASCII text that could stand in for the character, best first; empty when there
        /// is none (emoji, symbols, invisible characters). Never chosen for the user.
        /// </summary>
        public static IReadOnlyList<string> Alternatives(Rune r)
        {
            if (Spelled.TryGetValue(r.Value, out var spelled)) return spelled;
            if (Rune.GetUnicodeCategory(r) == UnicodeCategory.SpaceSeparator) return new[] { " " };
            if (Hidden(r) != null) return Array.Empty<string>();

            // A letter with an accent: the letter without it ("é" → "e"); a full-width or other
            // compatibility form: its plain twin ("１" → "1", as pasted from some web pages).
            var bare = new string(r.ToString().Normalize(NormalizationForm.FormKD)
                                   .Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
                                   .ToArray());
            return bare.Length > 0 && bare.All(c => c is >= ' ' and <= '~') && bare != r.ToString()
                ? new[] { bare }
                : Array.Empty<string>();
        }

        // Look-alikes and letters with a customary plain spelling; the first entry is the closest.
        private static readonly Dictionary<int, string[]> Spelled = new()
        {
            [0x2018] = new[] { "'" }, [0x2019] = new[] { "'" }, [0x201A] = new[] { "'" }, [0x201B] = new[] { "'" },
            [0x2032] = new[] { "'" }, [0x00B4] = new[] { "'" },
            [0x201C] = new[] { "\"" }, [0x201D] = new[] { "\"" }, [0x201E] = new[] { "\"" }, [0x2033] = new[] { "\"" },
            [0x00AB] = new[] { "\"" }, [0x00BB] = new[] { "\"" },
            [0x2010] = new[] { "-" }, [0x2011] = new[] { "-" }, [0x2012] = new[] { "-" }, [0x2013] = new[] { "-" },
            [0x2014] = new[] { "-" }, [0x2015] = new[] { "-" }, [0x2212] = new[] { "-" },
            [0x2026] = new[] { "..." },
            [0x00A0] = new[] { " " }, [0x202F] = new[] { " " }, [0x2009] = new[] { " " }, [0x2002] = new[] { " " },
            [0x2003] = new[] { " " }, [0x3000] = new[] { " " },
            [0x00E4] = new[] { "a", "ae" }, [0x00C4] = new[] { "A", "Ae" },
            [0x00F6] = new[] { "o", "oe" }, [0x00D6] = new[] { "O", "Oe" },
            [0x00FC] = new[] { "u", "ue" }, [0x00DC] = new[] { "U", "Ue" },
            [0x00DF] = new[] { "ss" }, [0x1E9E] = new[] { "SS" },
            [0x00E6] = new[] { "ae" }, [0x00C6] = new[] { "AE" },
            [0x0153] = new[] { "oe" }, [0x0152] = new[] { "OE" },
            [0x00F8] = new[] { "o", "oe" }, [0x00D8] = new[] { "O", "Oe" },
            [0x00E5] = new[] { "a", "aa" }, [0x00C5] = new[] { "A", "Aa" },
            [0x0142] = new[] { "l" }, [0x0141] = new[] { "L" },
            [0x00F0] = new[] { "d" }, [0x00FE] = new[] { "th" },
            [0x00D7] = new[] { "x" },
        };

        // ── Characters that hide ─────────────────────────────────────────────
        // A name from another tool is shown as it is, unless it holds something nobody can see
        // or that means nothing. A name never needs such a character: mostly it comes from a
        // paste, sometimes from someone making a name look like something it isn't. Either way
        // it is shown. Localized names are left alone, including the joiners, no-break spaces
        // and direction marks their languages use (see Reveal).

        /// <summary>
        /// "ZWSP (U+200B)" for a character that is invisible, controls layout or text direction,
        /// is a space other than U+0020, or has no meaning (private use, unassigned); null for
        /// an ordinary character.
        /// </summary>
        public static string? Hidden(Rune r)
        {
            var v = r.Value;
            var code = $"U+{v:X4}";
            string? name = v switch
            {
                0x09 => "TAB", 0x0A => "LF", 0x0D => "CR", 0x7F => "DEL",
                < 0x20 => "C0 control",
                >= 0x80 and <= 0x9F => "C1 control",
                0xA0 => "NBSP", 0xAD => "SHY", 0x061C => "ALM", 0x180E => "MVS",
                0x115F or 0x1160 or 0x3164 or 0xFFA0 => "HANGUL FILLER", 0x2800 => "BRAILLE BLANK",
                >= 0x2000 and <= 0x200A => "SPACE", 0x202F => "NNBSP", 0x205F => "MMSP", 0x3000 => "IDSP",
                0x200B => "ZWSP", 0x200C => "ZWNJ", 0x200D => "ZWJ", 0x2060 => "WJ", 0xFEFF => "ZWNBSP/BOM",
                0x200E => "LRM", 0x200F => "RLM",
                0x202A => "LRE", 0x202B => "RLE", 0x202C => "PDF", 0x202D => "LRO", 0x202E => "RLO",
                0x2066 => "LRI", 0x2067 => "RLI", 0x2068 => "FSI", 0x2069 => "PDI",
                0x2028 => "LINE SEPARATOR", 0x2029 => "PARAGRAPH SEPARATOR",
                >= 0x2061 and <= 0x2064 => "INVISIBLE OPERATOR",
                >= 0xFFF9 and <= 0xFFFB => "ANNOTATION",
                >= 0xFE00 and <= 0xFE0F => $"VS{v - 0xFE00 + 1}",
                >= 0xE0100 and <= 0xE01EF => $"VS{v - 0xE0100 + 17}",
                >= 0xE0000 and <= 0xE007F => "TAG",
                0xFFFD => "REPLACEMENT",
                _ => null,
            };
            if (name != null) return $"{name} ({code})";
            return Rune.GetUnicodeCategory(r) switch
            {
                UnicodeCategory.Control or UnicodeCategory.Format => $"invisible ({code})",
                UnicodeCategory.SpaceSeparator when v != 0x20 => $"SPACE ({code})",
                UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator => $"separator ({code})",
                UnicodeCategory.PrivateUse => $"private use ({code})",
                UnicodeCategory.OtherNotAssigned => $"unassigned ({code})",
                _ => null,
            };
        }

        /// <summary>
        /// A name for display: each hidden character shown as ⟨ZWSP U+200B⟩, plus what is wrong
        /// with the name, one line each (hidden characters; letters of another script inside a
        /// Latin word, the classic look-alike). No findings: the name comes back unchanged.
        /// </summary>
        public static (string Shown, List<string> Findings) Reveal(string? name)
        {
            var findings = new List<string>();
            if (string.IsNullOrEmpty(name)) return (name ?? "", findings);

            var shown = new StringBuilder(name.Length);
            var runes = name.EnumerateRunes().ToList();
            var rtl = runes.Any(IsRtlLetter);
            for (var i = 0; i < runes.Count; i++)
            {
                var r = runes[i];
                if (Hidden(r) is { } hidden && !UsedByLanguage(runes, i, rtl))
                {
                    // "ZWSP (U+200B)" shows as ⟨ZWSP U+200B⟩.
                    var cut = hidden.LastIndexOf(" (U+", StringComparison.Ordinal);
                    shown.Append('⟨').Append(hidden[..cut]).Append(' ').Append(hidden[(cut + 2)..^1]).Append('⟩');
                    if (!findings.Contains(hidden)) findings.Add(hidden);
                }
                else shown.Append(r.ToString());
            }

            foreach (var word in Words(name))
            {
                var scripts = word.EnumerateRunes().Select(ScriptOf).Where(x => x != null).Distinct().ToList();
                if (!scripts.Contains("Latin") || scripts.Count < 2) continue;
                foreach (var r in word.EnumerateRunes().Where(r => ScriptOf(r) is "Cyrillic" or "Greek").Distinct())
                {
                    var line = $"{r} (U+{r.Value:X4}, {ScriptOf(r)}) among Latin letters in \"{word}\"";
                    if (!findings.Contains(line)) findings.Add(line);
                }
            }
            return (findings.Count == 0 ? name : shown.ToString(), findings);
        }

        /// <summary>
        /// A name for plain text (Copy for AI and the like): the shown form, then what was found,
        /// hidden characters and look-alike letters kept apart, since a look-alike is visible.
        /// </summary>
        public static string ForText(string? name)
        {
            var (shown, findings) = Reveal(name);
            if (findings.Count == 0) return shown;
            var lookAlike = findings.Where(f => f.Contains(" among Latin letters", StringComparison.Ordinal)).ToList();
            var hidden = findings.Except(lookAlike).ToList();
            var parts = new List<string>();
            if (hidden.Count > 0) parts.Add("hidden characters: " + string.Join(", ", hidden));
            if (lookAlike.Count > 0) parts.Add("look-alike letters: " + string.Join(", ", lookAlike));
            return $"{shown} ({string.Join("; ", parts)})";
        }

        // Characters some languages put in ordinary words, in the place they use them: a joiner
        // between two letters of a non-Latin script (Persian, Indic), a no-break space next to
        // punctuation (French), a direction mark in a name with right-to-left letters.
        private static bool UsedByLanguage(List<Rune> runes, int i, bool rtl)
        {
            var v = runes[i].Value;
            Rune? before = i > 0 ? runes[i - 1] : null, after = i + 1 < runes.Count ? runes[i + 1] : null;
            if (v is 0x200C or 0x200D)
                return before is { } b && after is { } a && Rune.IsLetter(b) && Rune.IsLetter(a) &&
                       ScriptOf(b) != "Latin" && ScriptOf(a) != "Latin";
            if (v is 0xA0 or 0x202F)
                return (before is { } b2 && Rune.IsPunctuation(b2)) || (after is { } a2 && Rune.IsPunctuation(a2));
            if (v is 0x200E or 0x200F or 0x061C) return rtl;
            return false;
        }

        private static bool IsRtlLetter(Rune r) => Rune.IsLetter(r) && r.Value is
            (>= 0x0590 and <= 0x08FF) or (>= 0xFB1D and <= 0xFDFF) or (>= 0xFE70 and <= 0xFEFF);

        private static IEnumerable<string> Words(string text)
        {
            var word = new StringBuilder();
            foreach (var r in text.EnumerateRunes())
            {
                if (Rune.IsLetter(r) || Rune.GetUnicodeCategory(r) is UnicodeCategory.NonSpacingMark) { word.Append(r.ToString()); continue; }
                if (word.Length > 0) { yield return word.ToString(); word.Clear(); }
            }
            if (word.Length > 0) yield return word.ToString();
        }

        // Only the scripts that share look-alike letters with Latin.
        private static string? ScriptOf(Rune r)
        {
            if (!Rune.IsLetter(r)) return null;
            var v = r.Value;
            if (v is (>= 0x41 and <= 0x5A) or (>= 0x61 and <= 0x7A) or (>= 0xC0 and <= 0x24F) or (>= 0x1E00 and <= 0x1EFF)) return "Latin";
            if (v is (>= 0x370 and <= 0x3FF) or (>= 0x1F00 and <= 0x1FFF)) return "Greek";
            if (v is (>= 0x400 and <= 0x52F) or (>= 0x1C80 and <= 0x1C8F) or (>= 0x2DE0 and <= 0x2DFF) or (>= 0xA640 and <= 0xA69F)) return "Cyrillic";
            return "other";
        }
    }
}
