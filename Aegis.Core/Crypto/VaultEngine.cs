using Aegis.Contracts;
using Aegis.Core.Authentication;
using Aegis.Core.Crypto.SecureKey;
using Aegis.Core.FileEncryption;
using Aegis.Core.Progress;
using Aegis.Core.Storage;
using Aegis.Core.Tpm;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Utilities.Collections;
using OtpNet;
using System.Security;
using System.Security.Cryptography;
using KeyBlob = Aegis.Contracts.KeyBlob;
using TotpEnrollment = Aegis.Contracts.TotpEnrollment;

namespace Aegis.Core.Crypto;

internal sealed class VaultEngine
{
    private readonly TpmSealService _tpm;

    private readonly FileEncryptionService _fileEncryptionService;

    private readonly PendingAuthenticationStore
        _pendingAuthentications = new();

    private readonly PendingTotpEnrollmentStore
        _pendingTotpEnrollmentStore;

    internal PendingTotpEnrollmentStore
        PendingTotpEnrollmentStore =>
        _pendingTotpEnrollmentStore;

    private readonly PendingLoginAuthenticationStore
        _pendingLoginAuthentications = new();

    internal PendingLoginAuthenticationStore
        PendingLoginAuthenticationStore =>
        _pendingLoginAuthentications;

    internal VaultEngine(
        TpmSealService tpm)
    {
        _tpm =
            tpm
            ?? throw new ArgumentNullException(nameof(tpm));

        _fileEncryptionService =
            new FileEncryptionService();

        _pendingTotpEnrollmentStore =
            new PendingTotpEnrollmentStore();
    }

    internal async Task<TotpEnrollment> RegisterAccount(
        byte[] userPassword,
        uint[] pcrs,
        string username,
        CryptoSettings cryptoConfig)
    {
        var result =
            await Register.RegisterAccount(
                _tpm,
                userPassword,
                pcrs,
                username,
                cryptoConfig);

        var keyStore =
            new KeyStore(username);

        keyStore.AttachHmacKey(
            result.HmacKey);

        keyStore.SaveKeyBlob(
            result.Blob);

        keyStore.VerifyIntegrity(result.HmacKey);

        byte[] totpSecret =
            RandomNumberGenerator.GetBytes(20);

        try
        {

            string enrollmentId =
                _pendingTotpEnrollmentStore.Add(
                    username,
                    result.HmacKey,
                    TimeSpan.FromMinutes(5));

            string base32Secret =
                Base32Encoding.ToString(
                    totpSecret);

            string issuer =
                "Aegis";

            string account =
                $"{issuer}:{username}";

            string encodedIssuer =
                Uri.EscapeDataString(
                    issuer);

            string encodedAccount =
                Uri.EscapeDataString(
                    account);

            string totpUri =
                $"otpauth://totp/{encodedAccount}" +
                $"?secret={base32Secret}" +
                $"&issuer={encodedIssuer}" +
                $"&algorithm=SHA1" +
                $"&digits=6" +
                $"&period=30";

            keyStore.SaveTotpSecret(
                username,
                totpSecret);

            if (!_pendingTotpEnrollmentStore.TryGet(
                    enrollmentId,
                    out var pending) ||
                pending == null)
            {
                throw new SecurityException(
                    "TOTP enrollment is invalid or expired.");
            }

            return new TotpEnrollment
            {
               EnrollmentId = enrollmentId,
               Uri = totpUri
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                totpSecret);
        }
    }

    internal async Task<string?> BeginLogin(
        byte[] userPassword,
        string username)
    {
        var keyStore =
            new KeyStore(username);

        PrimaryAuthenticationResult? result = null;
        PendingLoginAuthentication? pending = null;

        try
        {
            KeyBlob blob =
                keyStore.LoadKeyBlob();

            result =
                await Login.LoginAccount(
                    _tpm,
                    userPassword,
                    blob,
                    keyStore,
                    username);

            // =====================================================
            // AUTHENTICATE KEYSTORE
            // =====================================================

            keyStore.VerifyIntegrity(
                result.HmacKey);

            // =====================================================
            // CREATE PENDING LOGIN
            // =====================================================

            pending =
                new PendingLoginAuthentication(
                    username,
                    result.AccountRootKey,
                    result.FileRootKey,
                    result.MemoryProtectionKey,
                    result.IpcWrappingKey,
                    result.HmacKey,
                    TimeSpan.FromMinutes(5));

            string authenticationId =
                _pendingLoginAuthentications.Add(
                    pending);

            // Ownership transferred.
            result = null;
            pending = null;

            return authenticationId;
        }
        catch
        {
            result?.Dispose();

            throw;
        }
    }

    internal ServerCryptoSession ConfirmLoginTotp(
     string authenticationId,
     string code)
    {
        Console.WriteLine(
            "SERVER: ConfirmLoginTotp entered.");

        if (!_pendingLoginAuthentications.TryGet(
                authenticationId,
                out var pending) ||
            pending == null)
        {
            throw new SecurityException(
                "Authentication is invalid or expired.");
        }

        if (pending.IsExpired)
        {
            _pendingLoginAuthentications
                .Remove(
                    authenticationId);

            throw new SecurityException(
                "Authentication is invalid or expired.");
        }

        var keyStore =
            new KeyStore(
                pending.Username);

        byte[] secret = Array.Empty<byte>();

        try
        {
            // =====================================================
            // VERIFY TOTP
            // =====================================================

            keyStore.VerifyIntegrity(
                pending.HmacKey);

            secret =
                keyStore.LoadTotpSecret();

            var totp =
                new OtpNet.Totp(
                    secret,
                    step: 30,
                    mode: OtpNet.OtpHashMode.Sha1,
                    totpSize: 6);

            bool verified =
                totp.VerifyTotp(
                    code,
                    out long step,
                    new OtpNet.VerificationWindow(
                        previous: 1,
                        future: 1));

            if (!verified)
            {
                throw new SecurityException(
                    "Invalid authentication code.");
            }

            long lastUsedStep =
                keyStore.GetLastUsedTotpStep();

            if (step <= lastUsedStep)
            {
                throw new SecurityException(
                    "Authentication code has already been used.");
            }

            keyStore.UpdateLastUsedTotpStep(
                step);

            // =====================================================
            // TOTP PASSED
            // =====================================================

            Console.WriteLine(
                "SERVER: TOTP authentication successful.");

            // =====================================================
            // CREATE NEW RAM-ONLY PROTECTED KEY SET
            // =====================================================

            // =====================================================
            // CREATE NEW RAM-ONLY PROTECTED KEY SET
            // =====================================================

            ProtectedSessionKeys protectedKeys = null!;

            try
            {
                using TpmRsaKeyProtector keyProtector =
                    TpmRsaKeyProtector.OpenOrCreate();

                protectedKeys =
                    ProtectedSessionKeys.Create(
                        keyProtector,
                        pending.AccountRootKey,
                        pending.FileRootKey,
                        pending.MemoryProtectionKey,
                        pending.IpcWrappingKey,
                        pending.HmacKey);
            }
            catch
            {
                protectedKeys?.Dispose();
                throw;
            }

            // =====================================================
            // CREATE EPHEMERAL IPC SESSION KEY
            // =====================================================

            IpcSessionKey ipcSessionKey = null!;

            try
            {
                ipcSessionKey =
                    IpcSessionKey.CreateEphemeralIpcKey();

                var session =
                    new ServerCryptoSession(
                        pending.Username,
                        protectedKeys,
                        ipcSessionKey);

                protectedKeys = null!;
                ipcSessionKey = null!;

                // =================================================
                // REMOVE PENDING AUTH
                //
                // This disposes the plaintext SecureBuffers.
                // =================================================

                bool removed =
                    _pendingLoginAuthentications
                        .Remove(
                            authenticationId);

                if (!removed)
                {
                    session.Dispose();

                    throw new SecurityException(
                        "Authentication state could not be finalized.");
                }

                return session;
            }
            catch
            {
                ipcSessionKey?.Dispose();
                protectedKeys?.Dispose();

                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                secret);
        }
    }

    public async Task<FileOperationResult> EncryptFileAsync(
        string inputPath,
        ServerCryptoSession session,
        string sessionId)
    {
        var progress = new Progress<double>(p =>
        {
            IpcProgressHub.Report(sessionId, p);
        });

        return await _fileEncryptionService.EncryptAsync(
            inputPath,
            session,
            progress);
    }

    public async Task<FileOperationResult> DecryptFileAsync(
        string inputPath,
        ServerCryptoSession session,
        IProgress<double>? progress = null)
    {
        return await _fileEncryptionService.DecryptAsync(
            inputPath,
            session,
            progress);
    }
}