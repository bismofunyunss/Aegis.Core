using Aegis.Contracts;

namespace Aegis.Core.Storage;

public sealed class KeyBlobHex
{
    public int Version { get; set; } = 1;

    public KeyBlob.KdfAlgorithm Kdf { get; init; }

    public KeyBlob.CipherSuite CipherSuite { get; init; }

    public string? DeviceName { get; init; }

    public string HmacKeyCipher { get; init; } = "";
    public string HmacKeyNonce { get; init; } = "";
    public string HmacKeyTag { get; init; } = "";


    public string SealedKekPrivate { get; init; } = "";
    public string SealedKekPublic { get; init; } = "";

    public uint[] Pcrs { get; init; } = Array.Empty<uint>();

    public string TpmSalt { get; init; } = "";


    public string PasswordSalt { get; init; } = "";

    public string PasswordHkdfSalt { get; init; } = "";


    public int ArgonParallelism { get; init; }

    public int ArgonIterations { get; init; }

    public int ArgonMemory { get; init; }

    public int ArgonVersion { get; init; } = 0x13;


    public string HelloKeyName { get; init; } = "";

    public string HelloEncryptedKey { get; init; } = "";

    public string HelloSalt { get; init; } = "";


    public string EncryptedKeyHierarchy { get; init; } = "";


    public string ChainCipher { get; init; } = "";

    public string ChainNonce { get; init; } = "";

    public string ChainTag { get; init; } = "";


    public string GcmNonce { get; init; } = "";

    public string GcmTag { get; init; } = "";

    public string GcmSalt { get; init; } = "";


    public string HkdfSalt { get; init; } = "";

    public string SessionSalt { get; init; } = "";

    public string CombinedKdfSalt { get; init; } = "";

    public string FileRootSalt { get; init; } = "";

    public string MemorySalt { get; init; } = "";

    public string IpcSalt { get; init; } = "";


    public static KeyBlobHex From(KeyBlob b)
    {
        return new KeyBlobHex
        {
            Version = b.Version,
            Kdf = b.Kdf,
            CipherSuite = b.cipherSuite,
            DeviceName = b.DeviceName,

            HmacKeyCipher = Convert.ToHexString(b.HmacKeyCipher),
            HmacKeyNonce = Convert.ToHexString(b.HmacKeyNonce),
            HmacKeyTag = Convert.ToHexString(b.HmacKeyTag),

            SealedKekPrivate =
                Convert.ToHexString(
                    b.SealedKekPrivate),
            SealedKekPublic =
                Convert.ToHexString(
                    b.SealedKekPublic),
            Pcrs = b.Pcrs,
            TpmSalt =
                Convert.ToHexString(
                    b.TpmSalt),

            PasswordSalt =
                Convert.ToHexString(
                    b.PasswordSalt),

            PasswordHkdfSalt =
                Convert.ToHexString(
                    b.PasswordHkdfSalt),

            ArgonParallelism =
                b.ArgonParallelism,
            ArgonIterations =
                b.ArgonIterations,
            ArgonMemory =
                b.ArgonMemory,
            ArgonVersion =
                b.ArgonVersion,

            HelloKeyName =
                b.HelloKeyName,
            HelloEncryptedKey =
                Convert.ToHexString(
                    b.HelloEncryptedKey),
            HelloSalt =
                Convert.ToHexString(
                    b.HelloSalt),

            EncryptedKeyHierarchy =
                Convert.ToHexString(
                    b.EncryptedKeyHierarchy),

            ChainCipher =
                Convert.ToHexString(
                    b.ChainCipher),
            ChainNonce =
                Convert.ToHexString(
                    b.ChainNonce),
            ChainTag =
                Convert.ToHexString(
                    b.ChainTag),

            GcmNonce =
                Convert.ToHexString(
                    b.GcmNonce),
            GcmTag =
                Convert.ToHexString(
                    b.GcmTag),
            GcmSalt =
                Convert.ToHexString(
                    b.GcmSalt),

            HkdfSalt =
                Convert.ToHexString(
                    b.HkdfSalt),
            SessionSalt =
                Convert.ToHexString(
                    b.SessionSalt),
            CombinedKdfSalt =
                Convert.ToHexString(
                    b.CombinedKdfSalt),
            FileRootSalt =
                Convert.ToHexString(
                    b.FileRootSalt),
            MemorySalt =
                Convert.ToHexString(
                    b.MemorySalt),
            IpcSalt =
                Convert.ToHexString(
                    b.IpcSalt)
        };
    }


    public KeyBlob ToKeyBlob()
    {
        return new KeyBlob
        {
            Version = Version,
            Kdf = Kdf,
            cipherSuite = CipherSuite,
            DeviceName = DeviceName,

            SealedKekPrivate =
                Convert.FromHexString(
                    SealedKekPrivate),
            SealedKekPublic =
                Convert.FromHexString(
                    SealedKekPublic),
            Pcrs = Pcrs,
            TpmSalt =
                Convert.FromHexString(
                    TpmSalt),

            PasswordSalt =
                Convert.FromHexString(
                    PasswordSalt),
            PasswordHkdfSalt =
                Convert.FromHexString(
                    PasswordHkdfSalt),

            ArgonParallelism =
                ArgonParallelism,
            ArgonIterations =
                ArgonIterations,
            ArgonMemory =
                ArgonMemory,
            ArgonVersion =
                ArgonVersion,

            HmacKeyCipher = Convert.FromHexString(HmacKeyCipher),
            HmacKeyNonce = Convert.FromHexString(HmacKeyNonce),
            HmacKeyTag = Convert.FromHexString(HmacKeyTag),

            HelloKeyName =
                HelloKeyName,
            HelloEncryptedKey =
                Convert.FromHexString(
                    HelloEncryptedKey),
            HelloSalt =
                Convert.FromHexString(
                    HelloSalt),

            EncryptedKeyHierarchy =
                Convert.FromHexString(
                    EncryptedKeyHierarchy),

            ChainCipher =
                Convert.FromHexString(
                    ChainCipher),
            ChainNonce =
                Convert.FromHexString(
                    ChainNonce),
            ChainTag =
                Convert.FromHexString(
                    ChainTag),

            GcmNonce =
                Convert.FromHexString(
                    GcmNonce),
            GcmTag =
                Convert.FromHexString(
                    GcmTag),
            GcmSalt =
                Convert.FromHexString(
                    GcmSalt),

            HkdfSalt =
                Convert.FromHexString(
                    HkdfSalt),
            SessionSalt =
                Convert.FromHexString(
                    SessionSalt),
            CombinedKdfSalt =
                Convert.FromHexString(
                    CombinedKdfSalt),
            FileRootSalt =
                Convert.FromHexString(
                    FileRootSalt),
            MemorySalt =
                Convert.FromHexString(
                    MemorySalt),
            IpcSalt =
                Convert.FromHexString(
                    IpcSalt)
        };
    }
}