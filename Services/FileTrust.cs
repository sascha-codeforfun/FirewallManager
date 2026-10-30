using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  FileTrust — who signed a program file, and whether it is unchanged since.
    //
    //  Windows checks it (WinVerifyTrust): first a signature inside the file, then,
    //  for Windows' own files, which mostly carry none, Windows' catalog files.
    //  Offline only: whether a certificate was revoked can only be asked online, and on
    //  a deny-by-default machine that would fail or wait, so it isn't asked.
    //
    //  What it states, and nothing more: a signature proves the file is unchanged since
    //  the signer signed it, and names the signer as the certificate does. Who to trust
    //  stays the user's call. "Windows' own" is a file Microsoft signed as Windows
    //  (signer Microsoft Windows, chain ending in a Microsoft root).
    // ─────────────────────────────────────────────────────────────────────────
    internal static class FileTrust
    {
        public enum Kind
        {
            /// <summary>Not looked at: no such file, or it couldn't be opened.</summary>
            Unchecked,
            /// <summary>No signature in the file and none in Windows' catalogs.</summary>
            Unsigned,
            /// <summary>Signed, and unchanged since.</summary>
            Signed,
            /// <summary>Signed by Microsoft as part of Windows, and unchanged since.</summary>
            WindowsOwn,
            /// <summary>A signature is there, but doesn't hold (file changed, untrusted, expired…).</summary>
            Invalid,
        }

        /// <param name="Signer">The certificate's name for the signer; empty when there is none.</param>
        /// <param name="Catalog">The signature came from one of Windows' catalog files.</param>
        /// <param name="Problem">For <see cref="Kind.Invalid"/>: what doesn't hold, in words.</param>
        /// <param name="MicrosoftRoot">The signer's certificate chain ends in a Microsoft root.</param>
        public sealed record Result(Kind Kind, string Signer, bool Catalog, string? Problem, bool MicrosoftRoot = false);

        public static Result Check(string path)
        {
            if (!File.Exists(path)) return new Result(Kind.Unchecked, "", false, null);

            var embedded = Verify(path, catalog: null);
            if (embedded.Kind != Kind.Unsigned) return embedded;

            // No signature inside: Windows' own files are vouched for in its catalogs, by
            // SHA-256 on current Windows, by SHA-1 in older catalogs. A file whose hash is in no
            // catalog (or doesn't verify there) stays unsigned: a tampered system file has a
            // hash no catalog lists, and shows as such.
            foreach (var algorithm in new[] { "SHA256", "SHA1" })
            {
                try
                {
                    if (WithCatalog(path, algorithm, member => Verify(path, member)) is { Kind: Kind.WindowsOwn or Kind.Signed } vouched)
                        return vouched;
                }
                catch { /* no catalog answer for this hash */ }
            }
            return embedded;
        }

        // ── WinVerifyTrust ────────────────────────────────────────────────────

        private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_CHOICE_CATALOG = 2;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
        private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

        private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
        private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
        private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
        private const uint TRUST_E_BAD_DIGEST = 0x80096010;
        private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
        private const uint CERT_E_EXPIRED = 0x800B0101;
        private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
        private const uint CERT_E_CHAINING = 0x800B010A;
        private const uint CERT_E_REVOKED = 0x800B010C;

        // The catalog admin context stays open while the member is verified: for any hash but
        // SHA-1, WinVerifyTrust needs it, and the hash itself.
        private sealed record CatalogMember(string CatalogFile, string MemberTag, IntPtr Admin, byte[] Hash);

        private static Result Verify(string path, CatalogMember? catalog)
        {
            var filePtr = Marshal.StringToCoTaskMemUni(path);
            IntPtr catFile = IntPtr.Zero, tag = IntPtr.Zero, union = IntPtr.Zero, hash = IntPtr.Zero;
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };
            try
            {
                if (catalog == null)
                {
                    var info = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = filePtr };
                    union = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                    Marshal.StructureToPtr(info, union, false);
                    data.dwUnionChoice = WTD_CHOICE_FILE;
                }
                else
                {
                    catFile = Marshal.StringToCoTaskMemUni(catalog.CatalogFile);
                    tag = Marshal.StringToCoTaskMemUni(catalog.MemberTag);
                    hash = Marshal.AllocHGlobal(catalog.Hash.Length);
                    Marshal.Copy(catalog.Hash, 0, hash, catalog.Hash.Length);
                    var info = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                        pcwszCatalogFilePath = catFile,
                        pcwszMemberTag = tag,
                        pcwszMemberFilePath = filePtr,
                        pbCalculatedFileHash = hash,
                        cbCalculatedFileHash = (uint)catalog.Hash.Length,
                        hCatAdmin = catalog.Admin,
                    };
                    union = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                    Marshal.StructureToPtr(info, union, false);
                    data.dwUnionChoice = WTD_CHOICE_CATALOG;
                }
                data.pUnion = union;

                var action = GenericVerifyV2;
                var hr = unchecked((uint)WinVerifyTrust(IntPtr.Zero, ref action, ref data));
                // "No signature" also comes back for a signature that is there but malformed; the
                // error code beside it tells the two apart.
                var detail = unchecked((uint)Marshal.GetLastPInvokeError());
                try
                {
                    var signer = SignerOf(data.hWVTStateData, out var microsoftRoot);
                    switch (hr)
                    {
                        case 0:
                            var windows = microsoftRoot &&
                                          (signer == "Microsoft Windows" || signer == "Microsoft Windows Publisher");
                            return new Result(windows ? Kind.WindowsOwn : Kind.Signed, signer, catalog != null, null, microsoftRoot);
                        case TRUST_E_NOSIGNATURE when detail is 0u or TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN:
                        case TRUST_E_SUBJECT_FORM_UNKNOWN:
                        case TRUST_E_PROVIDER_UNKNOWN:
                            return new Result(Kind.Unsigned, "", false, null);
                        case TRUST_E_NOSIGNATURE:
                            return new Result(Kind.Invalid, signer, catalog != null, "a signature is there but can't be read");
                        default:
                            return new Result(Kind.Invalid, signer, catalog != null, Describe(hr));
                    }
                }
                finally
                {
                    data.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                }
            }
            finally
            {
                if (union != IntPtr.Zero) Marshal.FreeHGlobal(union);
                if (hash != IntPtr.Zero) Marshal.FreeHGlobal(hash);
                Marshal.FreeCoTaskMem(filePtr);
                if (catFile != IntPtr.Zero) Marshal.FreeCoTaskMem(catFile);
                if (tag != IntPtr.Zero) Marshal.FreeCoTaskMem(tag);
            }
        }

        private static string Describe(uint hr) => hr switch
        {
            TRUST_E_BAD_DIGEST        => "the file was changed after it was signed",
            TRUST_E_EXPLICIT_DISTRUST => "the certificate is marked as not trusted on this machine",
            CERT_E_EXPIRED            => "the certificate had expired when it was signed",
            CERT_E_UNTRUSTEDROOT      => "the certificate leads to an authority this machine doesn't trust",
            CERT_E_CHAINING           => "the certificate can't be traced to a trusted authority",
            CERT_E_REVOKED            => "the certificate was revoked",
            _                         => $"Windows doesn't accept the signature (0x{hr:X8})",
        };

        // The signer's name as its certificate gives it, and whether its chain ends in a
        // Microsoft root (the last certificate in the chain).
        private static string SignerOf(IntPtr state, out bool microsoftRoot)
        {
            microsoftRoot = false;
            if (state == IntPtr.Zero) return "";
            try
            {
                var provData = WTHelperProvDataFromStateData(state);
                if (provData == IntPtr.Zero) return "";
                var signer = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
                if (signer == IntPtr.Zero) return "";
                var leaf = WTHelperGetProvCertFromChain(signer, 0);
                if (leaf == IntPtr.Zero) return "";
                // CRYPT_PROVIDER_SGNR: cbStruct (4), sftVerifyAsOf (8), csCertChain (4) → offset 12.
                var chainLength = Marshal.ReadInt32(signer, 12);
                if (chainLength > 0 && WTHelperGetProvCertFromChain(signer, (uint)(chainLength - 1)) is var root && root != IntPtr.Zero)
                    microsoftRoot = NameOf(CertContext(root)).StartsWith("Microsoft Root", StringComparison.Ordinal);
                return NameOf(CertContext(leaf));
            }
            catch { return ""; }
        }

        // CRYPT_PROVIDER_CERT: cbStruct (4, padded to 8), then the certificate context.
        private static IntPtr CertContext(IntPtr providerCert) => Marshal.ReadIntPtr(providerCert, IntPtr.Size);

        private static string NameOf(IntPtr certContext)
        {
            if (certContext == IntPtr.Zero) return "";
            const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
            var size = CertGetNameString(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, null, 0);
            if (size <= 1) return "";
            var sb = new StringBuilder((int)size);
            CertGetNameString(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, sb, size);
            return sb.ToString().Trim();
        }

        // ── Windows' catalogs ─────────────────────────────────────────────────

        // Finds the catalog that lists this file's hash and verifies the file against it, with
        // the catalog context open throughout. Null: no catalog lists it.
        private static Result? WithCatalog(string path, string algorithm, Func<CatalogMember, Result> verify)
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) return null;
            try
            {
                byte[] hash;
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var handle = stream.SafeFileHandle.DangerousGetHandle();
                    uint size = 0;
                    CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, null, 0);
                    if (size == 0) return null;
                    hash = new byte[size];
                    if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0)) return null;
                }

                var previous = IntPtr.Zero;
                var context = CryptCATAdminEnumCatalogFromHash(admin, hash, (uint)hash.Length, 0, ref previous);
                if (context == IntPtr.Zero) return null;
                try
                {
                    var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (!CryptCATCatalogInfoFromContext(context, ref info, 0) || string.IsNullOrEmpty(info.wszCatalogFile)) return null;
                    return verify(new CatalogMember(info.wszCatalogFile, Convert.ToHexString(hash), admin, hash));
                }
                finally { CryptCATAdminReleaseCatalogContext(admin, context, 0); }
            }
            finally { CryptCATAdminReleaseContext(admin, 0); }
        }

        // ── interop ───────────────────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public IntPtr pcwszCatalogFilePath;
            public IntPtr pcwszMemberTag;
            public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pUnion;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string? wszCatalogFile;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner,
            [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, EntryPoint = "CertGetNameStringW")]
        private static extern uint CertGetNameString(IntPtr pCertContext, uint dwType, uint dwFlags, IntPtr pvTypePara,
                                                     StringBuilder? pszNameString, uint cchNameString);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
            string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile,
            ref uint pcbHash, byte[]? pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash,
            uint dwFlags, ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
    }
}
