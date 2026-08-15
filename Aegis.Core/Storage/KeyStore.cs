using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aegis.Contracts;
using Aegis.Core.Crypto;

namespace Aegis.Core.Storage;

public sealed class KeyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };


    private readonly string _path;
    private readonly object _sync = new();

    private bool _disposed;

    private HmacKey? _hmacKey;

    private StoreModel _store;


    public KeyStore(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException(nameof(username));


        Username = username;


        var folder =
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "Aegis",
                "Users",
                username);


        Directory.CreateDirectory(folder);


        _path =
            Path.Combine(
                folder,
                "keystore.json");


        _store = LoadUnverified();
    }


    public string Username { get; }


    public bool IsAuthenticated =>
        _hmacKey != null;

    public void AttachHmacKey(HmacKey key)
    {
        if (key == null)
            throw new ArgumentNullException(
                nameof(key));

        if (_disposed)
            throw new ObjectDisposedException(
                nameof(KeyStore));

        _hmacKey = key;
    }

    // =========================================================
    // KEYBLOB
    // =========================================================


    public void SaveKeyBlob(KeyBlob blob)
    {
        EnsureAuthenticated();


        lock (_sync)
        {
            _store.KeyBlob =
                KeyBlobHex.From(blob);

            SaveInternal();
        }
    }


    public KeyBlob LoadKeyBlob()
    {
        if (_store.KeyBlob == null)
            throw new InvalidDataException(
                "Missing key blob");


        return _store.KeyBlob.ToKeyBlob();
    }

    // =========================================================
    // TOTP
    // =========================================================

    public bool HasTotp
    {
        get
        {
            EnsureAuthenticated();

            return _store.Totp != null;
        }
    }

    public void ConfirmTotpEnrollment(
        long step)
    {
        EnsureAuthenticated();

        lock (_sync)
        {
            if (_store.Totp == null)
            {
                throw new SecurityException(
                    "TOTP is not enrolled.");
            }

            if (step <= _store.Totp.LastUsedStep)
            {
                throw new SecurityException(
                    "Authentication code has already been used.");
            }

            _store.Totp.LastUsedStep = step;
            _store.Totp.IsEnrolled = true;

            SaveInternal();
        }
    }

    public bool VerifyTotp(
        string code)
    {
        EnsureAuthenticated();

        if (_store.Totp == null)
        {
            throw new SecurityException(
                "TOTP not enrolled.");
        }

        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        code = code.Trim();

        if (code.Length != 6 ||
            !code.All(char.IsDigit))
        {
            return false;
        }

        byte[] secret =
            LoadTotpSecret();

        try
        {
            var totp =
                new OtpNet.Totp(
                    secret,
                    step: 30,
                    mode: OtpNet.OtpHashMode.Sha1,
                    totpSize: 6);

            bool valid =
                totp.VerifyTotp(
                    code,
                    out long matchedStep,
                    new OtpNet.VerificationWindow(
                        previous: 1,
                        future: 1));

            if (!valid)
            {
                return false;
            }

            // Prevent reuse of the same TOTP time-step.
            if (matchedStep <=
                _store.Totp.LastUsedStep)
            {
                return false;
            }

            _store.Totp.LastUsedStep =
                matchedStep;

            SaveInternal();

            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                secret);
        }
    }

    public void SaveTotpSecret(
        string account,
        byte[] secret)
    {
        if (string.IsNullOrWhiteSpace(account))
            throw new ArgumentException(
                "TOTP account is required.",
                nameof(account));

        if (secret == null)
            throw new ArgumentNullException(
                nameof(secret));

        EnsureAuthenticated();

        byte[] entropy =
            RandomNumberGenerator.GetBytes(32);

        byte[] protectedSecret = Array.Empty<byte>();

        try
        {
            protectedSecret =
                ProtectedData.Protect(
                    secret,
                    entropy,
                    DataProtectionScope.CurrentUser);

            lock (_sync)
            {
                _store.Totp =
                    new TotpData
                    {
                        Account = account,

                        SecretHex = 
                            Convert.ToHexString(
                                protectedSecret),

                        EntropyHex = 
                            Convert.ToHexString(
                                entropy),

                        LastUsedStep = -1,

                        IsEnrolled = false
                    };

                SaveInternal();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                entropy);

            if (protectedSecret.Length > 0)
            {
                CryptographicOperations.ZeroMemory(
                    protectedSecret);
            }
        }
    }


    public byte[] LoadTotpSecret()
    {
        EnsureAuthenticated();

        TotpData totp;

        lock (_sync)
        {
            totp =
                _store.Totp
                ?? throw new SecurityException(
                    "TOTP is not enrolled.");
        }

        byte[] protectedSecret =
            Convert.FromHexString(
                totp.SecretHex);

        byte[] entropy =
            Convert.FromHexString(
                totp.EntropyHex);

        try
        {
            return ProtectedData.Unprotect(
                protectedSecret,
                entropy,
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                protectedSecret);

            CryptographicOperations.ZeroMemory(
                entropy);
        }
    }


    public long GetLastUsedTotpStep()
    {
        if (_store.Totp == null)
            throw new SecurityException(
                "TOTP not enrolled.");

        return _store.Totp.LastUsedStep;
    }


    public void UpdateLastUsedTotpStep(
        long step)
    {
        EnsureAuthenticated();

        if (_store.Totp == null)
            throw new SecurityException(
                "TOTP not enrolled.");

        lock (_sync)
        {
            _store.Totp.LastUsedStep = step;

            SaveInternal();
        }
    }


    public string GetTotpAccount()
    {
        if (_store.Totp == null)
            throw new SecurityException(
                "TOTP not enrolled.");

        return _store.Totp.Account;
    }
    


    // =========================================================
    // HMAC
    // =========================================================


    private void SaveInternal()
    {
        EnsureAuthenticated();


        var payload =
            JsonSerializer.SerializeToUtf8Bytes(
                _store,
                JsonOptions);


        var mac =
            _hmacKey!
                .ComputeHash(payload);


        var envelope =
            new KeyStoreEnvelope
            {
                Version = 1,

                Hmac =
                    Convert.ToHexString(mac),

                Data = _store
            };


        var json =
            JsonSerializer.Serialize(
                envelope,
                JsonOptions);


        var temp =
            _path + ".tmp";


        File.WriteAllText(
            temp,
            json,
            Encoding.UTF8);


        File.Move(
            temp,
            _path,
            true);


        CryptographicOperations.ZeroMemory(
            mac);
    }


    private StoreModel LoadUnverified()
    {
        if (!File.Exists(_path))
            return new StoreModel();


        var json =
            File.ReadAllText(
                _path,
                Encoding.UTF8);


        var envelope =
            JsonSerializer.Deserialize<KeyStoreEnvelope>(
                json)
            ?? throw new InvalidDataException();


        return envelope.Data;
    }


    public void VerifyIntegrity(HmacKey key)
    {
        if (key == null)
            throw new InvalidOperationException();


        var json =
            File.ReadAllText(
                _path,
                Encoding.UTF8);


        var envelope =
            JsonSerializer.Deserialize<KeyStoreEnvelope>(
                json)
            ?? throw new InvalidDataException();


        var payload =
            JsonSerializer.SerializeToUtf8Bytes(
                envelope.Data,
                JsonOptions);


        var expected =
            Convert.FromHexString(
                envelope.Hmac);


        if (!key.Verify(
                payload,
                expected))
            throw new CryptographicException(
                "Keystore integrity failure");


        _store =
            envelope.Data;
    }


    private void EnsureAuthenticated()
    {
        if (_hmacKey == null)
            throw new SecurityException(
                "Keystore not authenticated");
    }


    // =========================================================
    // MODELS
    // =========================================================


    private sealed class StoreModel
    {
        public KeyBlobHex? KeyBlob { get; set; }

        public TotpData? Totp { get; set; }

        public Dictionary<string, LockoutState>
            Lockouts { get; set; }
            = new();
    }


    private sealed class KeyStoreEnvelope
    {
        public int Version { get; set; }

        public string Hmac { get; set; } = "";

        public StoreModel Data { get; set; } = new();
    }


    public sealed class TotpData
    {
        public string Account { get; set; } = "";

        public string SecretHex { get; set; } = "";

        public string EntropyHex { get; set; } = "";

        public long LastUsedStep { get; set; } = -1;

        public bool IsEnrolled { get; set; } = false;
    }


    public sealed class LockoutState
    {
        public int Failures { get; set; }

        public DateTime? LockedUntilUtc { get; set; }
    }
}