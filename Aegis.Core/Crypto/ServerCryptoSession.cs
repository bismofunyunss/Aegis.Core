using Aegis.Core.Crypto.SecureKey;
using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto;

internal sealed class ServerCryptoSession : IDisposable
{
    private ProtectedSessionKeys? _protectedKeys;

    private IpcSessionKey? _ipcSessionKey;

    private bool _disposed;

    public string SessionId { get; }

    public DateTime CreatedUtc { get; }

    public string Username { get; }


    internal ServerCryptoSession(
        string username,
        ProtectedSessionKeys protectedKeys,
        IpcSessionKey ipcSessionKey)
    {
        Username = username;

        SessionId =
            Convert.ToHexString(
                RandomNumberGenerator.GetBytes(16));

        _protectedKeys =
            protectedKeys
            ?? throw new ArgumentNullException(
                nameof(protectedKeys));

        _ipcSessionKey =
            ipcSessionKey
            ?? throw new ArgumentNullException(
                nameof(ipcSessionKey));

        CreatedUtc =
            DateTime.UtcNow;
    }

    internal FileKey CreateFileKey(
        ReadOnlySpan<byte> fileSalt)
    {
        ThrowIfDisposed();

        using FileRootKey fileRootKey =
            _protectedKeys!
                .UnwrapFileRootKey();

        byte[] salt =
            fileSalt.ToArray();

        try
        {
            return fileRootKey.DeriveFileKey(
                salt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                salt);
        }
    }

    internal IpcSessionKey IpcSessionKey
    {
        get
        {
            ThrowIfDisposed();

            return _ipcSessionKey!;
        }
    }

    private ServerCryptoSession GetAuthenticatedSession(ServerCryptoSession currentSession)
    {
        return currentSession
               ?? throw new SecurityException(
                   "No authenticated crypto session exists.");
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        _ipcSessionKey?.Dispose();
        _protectedKeys?.Dispose();

        _ipcSessionKey = null;
        _protectedKeys = null;

        GC.SuppressFinalize(this);
    }


    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(
            _disposed,
            this);
    }
}
