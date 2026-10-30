using System;
using System.IO;
using System.Linq;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  LookAlike — programs named to pass for one of the programs malware likes to
    //  imitate. People read a word by its first and last letters; a swapped, doubled,
    //  dropped or changed letter in the middle goes unnoticed. Such a name has no
    //  business on a normal system, so it is an off case (amber), shown, never blocked.
    //
    //  • A name one letter off one on the list (two for names of eight letters or more;
    //    a swap of two neighbouring letters counts as one): "scvhost.exe looks like
    //    svchost.exe". Windows' own files are exempt (taskhost.exe is real, and one
    //    letter from taskhostw.exe).
    //  • The exact name, but not where Windows keeps it, or not signed as expected:
    //    a svchost.exe outside System32, or not signed by Microsoft Windows; a
    //    firefox.exe not signed by Mozilla. Browsers live in many places (a portable
    //    copy is fine), so for them only the signer counts.
    // ─────────────────────────────────────────────────────────────────────────
    internal static class LookAlike
    {
        private sealed record Known(string Name, string? Folder, string Signer, bool Windows);

        private static readonly Known[] List = Build();

        private static Known[] Build()
        {
            var system32 = Environment.SystemDirectory;
            var windows  = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            Known Win(string name, string folder) => new(name, folder, "Microsoft Windows", true);
            return new[]
            {
                Win("svchost", system32),  Win("lsass", system32),   Win("csrss", system32),
                Win("services", system32), Win("winlogon", system32), Win("smss", system32),
                Win("spoolsv", system32),  Win("taskhostw", system32), Win("rundll32", system32),
                Win("dllhost", system32),  Win("mstsc", system32),   Win("conhost", system32),
                Win("wininit", system32),  Win("explorer", windows),
                new("firefox", null, "Mozilla Corporation", false),
                new("chrome",  null, "Google LLC", false),
                new("msedge",  null, "Microsoft Corporation", false),
            };
        }

        /// <summary>Why this program looks like one it isn't, or null.</summary>
        public static string? Check(string path, FileTrust.Result trust)
        {
            // One spelling for the folder test: \\?\ and .. resolved.
            try
            {
                if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) path = @"\\" + path[8..];
                else if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path[4..];
                path = Path.GetFullPath(path);
            }
            catch { }
            var file = Path.GetFileName(path);
            var name = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
            if (name.Length == 0) return null;

            if (List.FirstOrDefault(k => k.Name == name) is { } same)
            {
                if (same.Folder != null && !InFolder(path, same.Folder))
                    return $"{file} belongs in {same.Folder}; this one is in {Path.GetDirectoryName(path)}.";
                var expected = same.Windows ? trust.Kind == FileTrust.Kind.WindowsOwn
                                            : (trust.Kind is FileTrust.Kind.Signed or FileTrust.Kind.WindowsOwn) &&
                                              trust.Signer.Equals(same.Signer, StringComparison.OrdinalIgnoreCase);
                if (!expected && trust.Kind != FileTrust.Kind.Unchecked)
                    return $"{file} is normally signed by {same.Signer}; this one " + trust.Kind switch
                    {
                        FileTrust.Kind.Unsigned => "is not signed.",
                        FileTrust.Kind.Invalid  => "has a signature that doesn't hold.",
                        _                       => $"is signed by {(trust.Signer.Length > 0 ? trust.Signer : "someone else")}.",
                    };
                return null;
            }

            // Windows' own files are what they say they are, even when their name is close to
            // another's, and so are Microsoft's (ssms.exe, SQL Server's, is one swap from smss.exe).
            if (trust.Kind == FileTrust.Kind.WindowsOwn) return null;
            if (trust.Kind == FileTrust.Kind.Signed && trust.MicrosoftRoot &&
                trust.Signer.StartsWith("Microsoft ", StringComparison.Ordinal)) return null;
            foreach (var k in List)
            {
                var limit = k.Name.Length <= 7 ? 1 : 2;
                if (Math.Abs(k.Name.Length - name.Length) > limit) continue;
                var distance = Distance(name, k.Name);
                if (distance > 0 && distance <= limit)
                    return $"{file} looks like {k.Name}.exe but isn't: check the name letter by letter.";
            }
            return null;
        }

        // Windows keeps 32-bit copies of many of these in SysWOW64 (explorer.exe too), its own as well.
        private static bool InFolder(string path, string folder)
        {
            var dir = Path.TrimEndingDirectorySeparator(Path.GetDirectoryName(path) ?? "");
            if (dir.Equals(Path.TrimEndingDirectorySeparator(folder), StringComparison.OrdinalIgnoreCase)) return true;
            var wow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
            return dir.Equals(wow, StringComparison.OrdinalIgnoreCase);
        }

        // Edits between two names: a letter changed, added or dropped, or two neighbours
        // swapped, each counting one (optimal string alignment distance).
        private static int Distance(string a, string b)
        {
            var d = new int[a.Length + 1, b.Length + 1];
            for (var i = 0; i <= a.Length; i++) d[i, 0] = i;
            for (var j = 0; j <= b.Length; j++) d[0, j] = j;
            for (var i = 1; i <= a.Length; i++)
                for (var j = 1; j <= b.Length; j++)
                {
                    var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                    if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                        d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
                }
            return d[a.Length, b.Length];
        }
    }
}
