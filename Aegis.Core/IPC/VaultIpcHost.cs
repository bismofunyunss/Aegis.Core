using Aegis.Core.Crypto;
using System.IO.Pipes;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Aegis.Core.Helpers;
using VaultCore.IPC;

namespace Aegis.Core.IPC;

public sealed class VaultIpcHost
{
    private const string PipeName = "AegisVaultPipe";

    private readonly CommandRouter _router;
    private const int MaxMessageSize = 4 * 1024 * 1024;

    public VaultIpcHost(CommandRouter router)
    {
        _router = router;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var security = new PipeSecurity();

                security.AddAccessRule(
                    new PipeAccessRule(
                        WindowsIdentity.GetCurrent().User!,
                        PipeAccessRights.FullControl,
                        AccessControlType.Allow));

                security.AddAccessRule(
                    new PipeAccessRule(
                        new SecurityIdentifier(
                            WellKnownSidType.WorldSid,
                            null),
                        PipeAccessRights.FullControl,
                        AccessControlType.Allow));

                var pipe = NamedPipeServerStreamAcl.Create(
                    PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    0,
                    0,
                    security);

                try
                {
                    // Wait here instead of spawning infinite tasks
                    await pipe.WaitForConnectionAsync(ct);

                    // Once connected, immediately detach handling
                    _ = HandleClientDetached(pipe, ct);
                }
                catch (OperationCanceledException)
                {
                    pipe.Dispose();
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("PIPE ACCEPT ERROR: " + ex);
                    pipe.Dispose();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("IPC HOST ERROR: " + ex);

                // prevent hot spin if repeated failure
                await Task.Delay(1000, ct);
            }
        }
    }

    private async Task HandleClientDetached(
        NamedPipeServerStream pipe,
        CancellationToken ct)
    {
        try
        {
            await HandleClient(pipe, ct);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Console.WriteLine("PIPE CLIENT ERROR: " + ex);
        }
        finally
        {
            pipe.Dispose();
        }
    }

    private async Task HandleClient(
    NamedPipeServerStream pipe,
    CancellationToken ct)
    {
        byte[] buffer = Array.Empty<byte>();
        byte[] outBytes = Array.Empty<byte>();

        try
        {
            // =====================================================
            // READ REQUEST LENGTH
            // =====================================================

            byte[] lengthBuffer = new byte[4];

            await ReadExact.ReadExactAsync(
                pipe,
                lengthBuffer,
                4,
                ct);

            int len =
                BitConverter.ToInt32(
                    lengthBuffer,
                    0);

            if (len <= 0 ||
                len > MaxMessageSize)
            {
                throw new SecurityException(
                    "Invalid IPC message size.");
            }


            // =====================================================
            // READ REQUEST BODY
            // =====================================================

            buffer =
                new byte[len];

            await ReadExact.ReadExactAsync(
                pipe,
                buffer,
                len,
                ct);


            // =====================================================
            // DESERIALIZE REQUEST
            //
            // We deserialize IpcRequest first so we can determine
            // whether this is a bootstrap command.
            // =====================================================

            var request =
                JsonSerializer.Deserialize<IpcRequest>(
                    buffer)
                ?? throw new SecurityException(
                    "Invalid IPC request.");

            Console.WriteLine(
                $"SERVER: Incoming command=[{request.Command ?? "<NULL>"}]");

            Console.WriteLine(
                $"SERVER: Command length={request.Command?.Length ?? -1}");

            bool isBootstrap =
                IsBootstrapRequest(
                    buffer);

            Console.WriteLine(
                $"SERVER: Is bootstrap={isBootstrap}");

            if (isBootstrap)
            {
                Console.WriteLine(
                    "SERVER: Entering bootstrap path.");

                var response =
                    await _router.HandleAsync(
                        request);

                Console.WriteLine(
                    "SERVER: After router.");

                outBytes =
                    JsonSerializer.SerializeToUtf8Bytes(
                        response);

                Console.WriteLine(
                    $"SERVER: Response serialized: {outBytes.Length} bytes.");

                await WriteMessageAsync(
                    pipe,
                    outBytes,
                    ct);

                Console.WriteLine(
                    "SERVER: Bootstrap response sent.");

                return;
            }


            // =====================================================
            // SECURE REQUESTS ONLY
            // =====================================================

            Console.WriteLine(
                "SERVER: Entering secure request path.");

            var envelope =
                JsonSerializer.Deserialize<SecureEnvelope>(
                    buffer)
                ?? throw new SecurityException(
                    "Invalid secure envelope.");

            var state =
                ServerCryptoSessionStore.Validate(
                    envelope.SessionId,
                    envelope.Counter);


            // =====================================================
            // DECRYPT REQUEST
            // =====================================================

            byte[] plaintext =
                VaultTransport.DecryptIncoming(
                    state.Session.IpcSessionKey.Export(),
                    envelope,
                    envelope.SessionId,
                    envelope.Counter,
                    envelope.Command);

            try
            {
                var secureRequest =
                    JsonSerializer.Deserialize<IpcRequest>(
                        plaintext)
                    ?? throw new SecurityException(
                        "Invalid decrypted request.");

                Console.WriteLine(
                    "SERVER: Request decrypted.");

                Console.WriteLine(
                    $"SERVER: Command={secureRequest.Command}");


                // =================================================
                // HANDLE SECURE REQUEST
                // =================================================

                var secureResponse =
                    await _router.HandleAsync(
                        secureRequest);


                // =================================================
                // SERIALIZE RESPONSE
                // =================================================

                Console.WriteLine(
                    "SERVER: Before response serialization.");

                byte[] responsePlaintext =
                    JsonSerializer.SerializeToUtf8Bytes(
                        secureResponse);

                try
                {
                    Console.WriteLine(
                        $"SERVER: Response plaintext size={responsePlaintext.Length}");


                    // =============================================
                    // ENCRYPT RESPONSE
                    // =============================================

                    Console.WriteLine(
                        "SERVER: Before response encryption.");

                    var responseEnvelope =
                        VaultTransport.EncryptOutgoing(
                            state.Session.IpcSessionKey.Export(),
                            responsePlaintext,
                            envelope.SessionId,
                            envelope.Counter,
                            envelope.Command);

                    Console.WriteLine(
                        "SERVER: Response encrypted.");


                    // =============================================
                    // SERIALIZE ENVELOPE
                    // =============================================

                    outBytes =
                        JsonSerializer.SerializeToUtf8Bytes(
                            responseEnvelope);

                    Console.WriteLine(
                        $"SERVER: Response bytes={outBytes.Length}");


                    // =============================================
                    // WRITE RESPONSE
                    // =============================================

                    Console.WriteLine(
                        "SERVER: Before pipe write.");

                    await WriteMessageAsync(
                        pipe,
                        outBytes,
                        ct);

                    Console.WriteLine(
                        "SERVER: After pipe write.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        responsePlaintext);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    plaintext);
            }
        }
        finally
        {
            // =====================================================
            // SECURE CLEANUP
            // =====================================================

            if (buffer.Length > 0)
            {
                CryptographicOperations.ZeroMemory(
                    buffer);
            }

            if (outBytes.Length > 0)
            {
                CryptographicOperations.ZeroMemory(
                    outBytes);
            }

            try
            {
                pipe.Disconnect();
            }
            catch
            {
            }

            pipe.Dispose();
        }
    }

    private static async Task WriteMessageAsync(
        Stream stream,
        byte[] data,
        CancellationToken ct)
    {
        byte[] length =
            BitConverter.GetBytes(
                data.Length);


        await stream.WriteAsync(
            length,
            ct);


        await stream.WriteAsync(
            data,
            ct);


        await stream.FlushAsync(
            ct);
    }

    private static bool IsBootstrapRequest(
        byte[] buffer)
    {
        try
        {
            var request =
                JsonSerializer.Deserialize<IpcRequest>(
                    buffer);

            if (request == null)
                return false;

            return request.Command switch
            {
                "login" =>
                    true,

                "register" =>
                    true,

                "confirm-totp-enrollment" =>
                    true,

                "confirm-login-totp" =>
                    true,

                _ =>
                    false
            };
        }
        catch
        {
            return false;
        }
    }
}