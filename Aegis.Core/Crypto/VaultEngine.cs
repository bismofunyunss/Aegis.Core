using System.Security;
using System.Security.Cryptography;
using Aegis.Contracts;
using Aegis.Core.Authentication;
using Aegis.Core.Crypto.SecureKey;
using Aegis.Core.FileEncryption;
using Aegis.Core.Progress;
using Aegis.Core.Storage;
using Aegis.Core.Tpm;
using OtpNet;
using TotpEnrollment = Aegis.Contracts.TotpEnrollment;

namespace Aegis.Core.Crypto;

internal sealed class VaultEngine
{
    private readonly FileEncryptionService _fileEncryptionService;

    private readonly PendingAuthenticationStore
        _pendingAuthentications = new();

    private readonly TpmSealService _tpm;

    private ServerCryptoSession? _currentSession;

    internal VaultEngine(
        TpmSealService tpm)
    {
        _tpm =
            tpm
            ?? throw new ArgumentNullException(nameof(tpm));

        _fileEncryptionService =
            new FileEncryptionService();

        PendingTotpEnrollmentStore =
            new PendingTotpEnrollmentStore();
    }

    internal PendingTotpEnrollmentStore
        PendingTotpEnrollmentStore { get; }

    internal PendingLoginAuthenticationStore
        PendingLoginAuthenticationStore { get; } = new();

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

        var totpSecret =
            RandomNumberGenerator.GetBytes(20);

        try
        {
            var enrollmentId =
                PendingTotpEnrollmentStore.Add(
                    username,
                    result.HmacKey,
                    TimeSpan.FromMinutes(5));

            var base32Secret =
                Base32Encoding.ToString(
                    totpSecret);

            var issuer =
                "Aegis";

            var account =
                $"{issuer}:{username}";

            var encodedIssuer =
                Uri.EscapeDataString(
                    issuer);

            var encodedAccount =
                Uri.EscapeDataString(
                    account);

            var totpUri =
                $"otpauth://totp/{encodedAccount}" +
                $"?secret={base32Secret}" +
                $"&issuer={encodedIssuer}" +
                $"&algorithm=SHA1" +
                $"&digits=6" +
                $"&period=30";

            keyStore.SaveTotpSecret(
                username,
                totpSecret);

            if (!PendingTotpEnrollmentStore.TryGet(
                    enrollmentId,
                    out var pending) ||
                pending == null)
                throw new SecurityException(
                    "TOTP enrollment is invalid or expired.");

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
            var blob =
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

            var authenticationId =
                PendingLoginAuthenticationStore.Add(
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
        if (string.IsNullOrWhiteSpace(authenticationId))
            throw new SecurityException(
                "Authentication is invalid or expired.");

        if (string.IsNullOrWhiteSpace(code))
            throw new SecurityException(
                "Invalid authentication code.");

        if (!PendingLoginAuthenticationStore.TryGet(
                authenticationId,
                out var pending) ||
            pending == null)
            throw new SecurityException(
                "Authentication is invalid or expired.");

        var keyStore =
            new KeyStore(
                pending.Username);

        byte[]? secret = null;

        try
        {
            // =====================================================
            // AUTHENTICATE KEYSTORE
            // =====================================================

            keyStore.AttachHmacKey(
                pending.HmacKey);

            keyStore.VerifyIntegrity(
                pending.HmacKey);

            // =====================================================
            // LOAD TOTP SECRET
            // =====================================================

            secret =
                keyStore.LoadTotpSecret();

            // =====================================================
            // VERIFY TOTP
            // =====================================================

            var totp =
                new Totp(
                    secret);

            if (!totp.VerifyTotp(
                    code,
                    out var step,
                    new VerificationWindow(
                        1,
                        1)))
                throw new SecurityException(
                    "Invalid authentication code.");

            // =====================================================
            // PREVENT TOTP REUSE
            // =====================================================

            if (step <=
                keyStore.GetLastUsedTotpStep())
                throw new SecurityException(
                    "Authentication code has already been used.");

            keyStore.UpdateLastUsedTotpStep(
                step);

            // =====================================================
            // TAKE PENDING AUTHENTICATION
            // =====================================================

            PendingLoginAuthentication? taken = null;

            try
            {
                if (!PendingLoginAuthenticationStore.Take(
                        authenticationId,
                        out taken) ||
                    taken == null)
                    throw new SecurityException(
                        "Authentication is no longer valid.");

                // =================================================
                // CREATE PROTECTED SESSION KEYS
                // =================================================

                ProtectedSessionKeys? protectedKeys = null;
                IpcSessionKey? ipcSession = null;

                try
                {
                    using var keyProtector =
                        TpmRsaKeyProtector.OpenOrCreate();

                    protectedKeys =
                        ProtectedSessionKeys.Create(
                            keyProtector,
                            taken.AccountRootKey,
                            taken.FileRootKey,
                            taken.MemoryProtectionKey,
                            taken.IpcWrappingKey,
                            taken.HmacKey);

                    // =============================================
                    // CREATE EPHEMERAL IPC SESSION KEY
                    // =============================================

                    ipcSession =
                        IpcSessionKey.CreateEphemeralIpcKey();

                    // =============================================
                    // CREATE SERVER CRYPTO SESSION
                    // =============================================

                    var session =
                        new ServerCryptoSession(
                            taken.Username,
                            protectedKeys,
                            ipcSession);

                    // =============================================
                    // OWNERSHIP TRANSFER
                    // =============================================

                    protectedKeys = null;
                    ipcSession = null;

                    taken.Dispose();
                    taken = null;

                    return session;
                }
                finally
                {
                    protectedKeys?.Dispose();
                    ipcSession?.Dispose();
                }
            }
            catch
            {
                taken?.Dispose();
                throw;
            }
        }
        finally
        {
            if (secret != null)
                CryptographicOperations.ZeroMemory(
                    secret);
        }
    }

    internal async Task<FileOperationResult> EncryptFileAsync(
        string inputPath,
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        var sessionState =
            ServerCryptoSessionStore.Get(
                sessionId);

        var session =
            sessionState.Session;

        if (session == null)
            throw new SecurityException(
                "No authenticated crypto session.");

        var progress =
            new Progress<double>(p =>
            {
                IpcProgressHub.Report(
                    sessionId,
                    p);
            });

        var fileKeySalt =
            RandomNumberGenerator.GetBytes(128);

        try
        {
            using var fileKey =
                session.CreateFileKey(
                    fileKeySalt);

            return await _fileEncryptionService.EncryptAsync(
                inputPath,
                fileKey,
                fileKeySalt,
                session.Username,
                sessionId,
                progress,
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                fileKeySalt);
        }
    }


    internal async Task<FileOperationResult> DecryptFileAsync(
        string inputPath,
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        var sessionState =
            ServerCryptoSessionStore.Get(
                sessionId);

        var session =
            sessionState.Session;

        if (session == null)
            throw new SecurityException(
                "No authenticated crypto session.");

        var progress =
            new Progress<double>(p =>
            {
                IpcProgressHub.Report(
                    sessionId,
                    p);
            });

        return await _fileEncryptionService.DecryptAsync(
            inputPath,
            salt =>
                session.CreateFileKey(salt),
            session.Username,
            progress,
            cancellationToken);
    }
}