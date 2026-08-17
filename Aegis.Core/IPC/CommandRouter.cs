using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using Aegis.Contracts;
using Aegis.Core.Authentication;
using Aegis.Core.Crypto;
using Aegis.Core.Crypto.SecureKey;
using Aegis.Core.Storage;
using Aegis.Core.Tpm;
using OtpNet;
using VaultCore.IPC;
using ConfirmLoginTotpRequest = Aegis.Contracts.ConfirmLoginTotpRequest;

namespace Aegis.Core.IPC;

public sealed class CommandRouter
{
    private readonly VaultEngine _vault;

    public CommandRouter()
    {
        var tpm = new TpmSealService(OpenTpm.CreateTpm());
        _vault = new VaultEngine(tpm);
    }

    private static T Deserialize<T>(byte[] payload)
    {
        return JsonSerializer.Deserialize<T>(payload)
               ?? throw new SecurityException(
                   $"Invalid payload for {typeof(T).Name}");
    }

    public async Task<IpcResponse> HandleAsync(
        IpcRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            var command =
                request.Command?
                    .Trim()
                    .ToLowerInvariant()
                ?? string.Empty;

            // =========================================
            // SESSION VALIDATION
            // =========================================

            var requiresSession =
                command != "login" &&
                command != "register" &&
                command != "confirm-totp-enrollment" &&
                command != "confirm-login-totp";

            if (requiresSession)
                if (string.IsNullOrWhiteSpace(
                        request.SessionId))
                    return Error(
                        "Session is required.");

            // =========================================
            // ROUTING
            // =========================================

            return command switch
            {
                "login" =>
                    await HandleLogin(
                        Deserialize<LoginRequest>(
                            request.Payload)),

                "register" =>
                    await HandleRegister(
                        Deserialize<RegisterRequest>(
                            request.Payload)),

                "confirm-totp-enrollment" =>
                    await HandleConfirmTotpEnrollment(
                        Deserialize<ConfirmTotpEnrollmentRequest>(
                            request.Payload)),

                "confirm-login-totp" =>
                    HandleConfirmLoginTotpDebug(
                        Deserialize<ConfirmLoginTotpRequest>(
                            request.Payload)),

                "encrypt" =>
                    await HandleEncryption(
                        request,
                            Deserialize<EncryptFileRequest>(
                                request.Payload)),

                "decrypt" =>
                    await HandleDecryption(
                        request,
                        Deserialize<DecryptFileRequest>(
                            request.Payload)),

                "logout" =>
                    await HandleLogout(request),

                _ =>
                    Error(
                        "Unknown command.")
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                "ROUTER EXCEPTION:");

            Console.WriteLine(
                ex);

            Console.WriteLine(
                $"ROUTER EXCEPTION TYPE: {ex.GetType().FullName}");

            Console.WriteLine(
                $"ROUTER EXCEPTION MESSAGE: {ex.Message}");

            return Error(
                ex.Message);
        }
    }

    private IpcResponse HandleConfirmLoginTotpDebug(
        ConfirmLoginTotpRequest req)
    {
        Console.WriteLine(
            "ROUTER: *** CONFIRM LOGIN TOTP HANDLER REACHED ***");

        return HandleConfirmLoginTotp(req);
    }

    private async Task<IpcResponse> HandleConfirmTotpEnrollment(
        ConfirmTotpEnrollmentRequest req)
    {
        Console.WriteLine(
            "SERVER: Entered HandleConfirmTotpEnrollment.");

        Console.WriteLine(
            $"SERVER: EnrollmentId={req.EnrollmentId}");

        Console.WriteLine(
            $"SERVER: Code length={req.Code?.Length}");

        if (string.IsNullOrWhiteSpace(req.Code) ||
            req.Code.Length != 6 ||
            !req.Code.All(char.IsDigit))
        {
            Console.WriteLine(
                "SERVER: Invalid TOTP code.");

            return Error(
                "Invalid authentication code.");
        }

        try
        {
            Console.WriteLine(
                "SERVER: Before ConfirmTotpEnrollment.");

            ConfirmTotpEnrollment(
                req.EnrollmentId,
                req.Code);

            Console.WriteLine(
                "SERVER: After ConfirmTotpEnrollment.");

            return Success();
        }
        catch (SecurityException ex)
        {
            Console.WriteLine(
                $"SERVER: TOTP security failure: {ex.Message}");

            return Error(
                ex.Message);
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"SERVER: TOTP exception: {ex}");

            return Error(
                "TOTP enrollment confirmation failed.");
        }
    }

    private IpcResponse HandleConfirmLoginTotp(
        ConfirmLoginTotpRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.AuthenticationId) ||
            string.IsNullOrWhiteSpace(req.Code))
        {
            Console.WriteLine(
                "TOTP: Missing authentication ID or code.");

            return Error(
                "Invalid authentication request.");
        }

        Console.WriteLine(
            $"TOTP: AuthenticationId={req.AuthenticationId}");

        Console.WriteLine(
            $"TOTP: Code length={req.Code.Length}");

        try
        {
            Console.WriteLine(
                "TOTP: Calling vault ConfirmLoginTotp.");

            var session =
                _vault.ConfirmLoginTotp(
                    req.AuthenticationId,
                    req.Code);

            Console.WriteLine(
                "TOTP: Verification succeeded.");

            Console.WriteLine(
                $"TOTP: SessionId={session.SessionId}");

            var state =
                ServerCryptoSessionStore.Register(
                    session.Username,
                    session,
                    TimeSpan.FromMinutes(30));

            Console.WriteLine(
                "TOTP: Session registered.");

            var result =
                new LoginResult
                {
                    Username =
                        state.Username,

                    SessionId =
                        state.SessionId,

                    SessionKey =
                        session.IpcSessionKey.Export(),

                    CreatedUtc =
                        state.CreatedUtc,

                    ExpiresUtc =
                        state.ExpiresUtc,

                    ProtocolVersion =
                        "1"
                };

            Console.WriteLine(
                "TOTP: LoginResult created.");

            return Success(result);
        }
        catch (SecurityException ex)
        {
            Console.WriteLine(
                $"TOTP SECURITY FAILURE: {ex}");

            return Error(
                "Invalid authentication code.");
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"TOTP UNEXPECTED FAILURE: {ex}");

            return Error(
                "Login failed.");
        }
    }

    internal void ConfirmTotpEnrollment(
        string enrollmentId,
        string code)
    {
        Console.WriteLine(
            "SERVER: ConfirmTotpEnrollment entered.");

        Console.WriteLine(
            $"SERVER: Enrollment ID={enrollmentId}");

        if (!_vault.PendingTotpEnrollmentStore.TryGet(
                enrollmentId,
                out var pending) ||
            pending == null)
            throw new SecurityException(
                "TOTP enrollment is invalid or expired.");

        Console.WriteLine(
            $"SERVER: Pending enrollment found for {pending.Username}.");

        var keyStore =
            new KeyStore(
                pending.Username);

        keyStore.AttachHmacKey(
            pending.HmacKey);

        Console.WriteLine(
            "SERVER: KeyStore authenticated.");

        var secret =
            keyStore.LoadTotpSecret();

        try
        {
            Console.WriteLine(
                "SERVER: TOTP secret loaded.");

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

            Console.WriteLine(
                $"SERVER: TOTP verified. Step={step}");

            keyStore.ConfirmTotpEnrollment(
                step);

            Console.WriteLine(
                "SERVER: Enrollment marked confirmed.");

            _vault.PendingTotpEnrollmentStore.Remove(
                enrollmentId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                secret);
        }
    }

    // =========================================================
    // REGISTER
    // =========================================================

    private async Task<IpcResponse> HandleRegister(
        RegisterRequest req)
    {
        try
        {
            if (req.Username == null ||
                req.Password == null ||
                req.CryptoConfig == null)
                return Error(
                    "Missing username or password");

            var result = await _vault.RegisterAccount(
                req.Password,
                req.Pcrs ?? Array.Empty<uint>(),
                req.Username,
                req.CryptoConfig);

            return Success(result);
        }
        finally
        {
            if (req.Password != null)
                CryptographicOperations.ZeroMemory(
                    req.Password);
        }
    }

    // =========================================================
    // LOGIN
    // =========================================================

    private async Task<IpcResponse> HandleLogin(
        LoginRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Username) ||
            req.Password == null ||
            req.Password.Length == 0)
            return Error(
                "Invalid credentials");

        try
        {
            // =====================================================
            // PASSWORD + TPM + WINDOWS HELLO
            //
            // This does NOT create a ServerCryptoSession.
            // It creates temporary pending authentication state.
            // =====================================================

            var authenticationId =
                await _vault.BeginLogin(
                    req.Password,
                    req.Username);

            // =====================================================
            // RETURN AUTHENTICATION ID
            //
            // Client must now provide the TOTP code.
            // =====================================================

            var result =
                new LoginBeginResult
                {
                    AuthenticationId =
                        authenticationId
                };

            return Success(result);
        }
        catch (SecurityException)
        {
            return Error(
                "Invalid credentials");
        }
        catch (CryptographicException)
        {
            return Error(
                "Invalid credentials");
        }
        catch (Exception)
        {
            return Error(
                "Login failed");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                req.Password);
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

        if (!_vault.PendingLoginAuthenticationStore.TryGet(
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
                if (!_vault.PendingLoginAuthenticationStore.Take(
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

    private async Task<IpcResponse> HandleEncryptionDebug(
        IpcRequest request)
    {
        Console.WriteLine(
            "ROUTER: Entered encrypt handler.");

        EncryptFileRequest req;

        try
        {
            Console.WriteLine(
                "ROUTER: Deserializing EncryptFileRequest.");

            req =
                Deserialize<EncryptFileRequest>(
                    request.Payload);

            Console.WriteLine(
                $"ROUTER: InputPath={req.InputPath}");

            Console.WriteLine(
                $"ROUTER: Request.SessionId={request.SessionId}");

            Console.WriteLine(
                $"ROUTER: Payload.SessionId={req.SessionId}");
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"ROUTER: Encrypt request deserialization failed: {ex}");

            throw;
        }

        return await HandleEncryption(
            request,
            req);
    }

    private async Task<IpcResponse> HandleEncryption(
        IpcRequest request,
        EncryptFileRequest req)
    {
        Console.WriteLine(
            "SERVER: Starting encryption");

        Console.WriteLine(
            $"SERVER: Request SessionId={request.SessionId}");

        Console.WriteLine(
            $"SERVER: Request InputPath={req.InputPath}");

        var state =
            ServerCryptoSessionStore.Get(
                request.SessionId);

        Console.WriteLine(
            $"SERVER: Session found. " +
            $"Username={state.Username}, " +
            $"SessionId={state.SessionId}");

        var result =
            await _vault.EncryptFileAsync(
                req.InputPath,
                state.SessionId);

        Console.WriteLine(
            "SERVER: Encryption complete");

        var response =
            Success(result);

        Console.WriteLine(
            "SERVER: Response created");

        return response;
    }

    private async Task<IpcResponse> HandleDecryption(
        IpcRequest request,
        DecryptFileRequest req)
    {
        try
        {
            Console.WriteLine("SERVER: Starting decryption");

            if (string.IsNullOrWhiteSpace(request.SessionId))
                throw new SecurityException(
                    "Missing session id.");


            var state =
                ServerCryptoSessionStore.Get(
                    request.SessionId);


            Console.WriteLine("SERVER: Session loaded");


            var result =
                await _vault.DecryptFileAsync(
                    req.InputPath,
                    state.Session.SessionId);


            Console.WriteLine("SERVER: Decryption complete");


            return Success(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                "SERVER: DECRYPT FAILURE");

            Console.WriteLine(
                ex.ToString());

            throw;
        }
    }

    private Task<IpcResponse>? HandleLogout(
        IpcRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.SessionId))
            {
                return Task.FromResult(
                    Error("Session is required."));
            }

            if (ServerCryptoSessionStore.TryGet(
                    request.SessionId,
                    out var state) &&
                state != null)
            {
                ServerCryptoSessionStore.Remove(
                    request.SessionId);
            }
            else
            {
                return null;
            }

            return Task.FromResult(
                Success(null));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                Error("Logout failed."));
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static T Deserialize<T>(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new SecurityException("Missing payload");

        return JsonSerializer.Deserialize<T>(json)
               ?? throw new SecurityException("Invalid payload");
    }

    private static IpcResponse Success(object? data)
    {
        return new IpcResponse
        {
            Success = true,
            Data = JsonSerializer.Serialize(data)
        };
    }

    private static IpcResponse Success()
    {
        return new IpcResponse
        {
            Success = true,
            Data = null
        };
    }

    private static IpcResponse Error(string error)
    {
        return new IpcResponse
        {
            Success = false,
            Error = error
        };
    }
}