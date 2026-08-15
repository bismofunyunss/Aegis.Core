using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Buffers;
using Aegis.Core.Crypto.SecureKey;

namespace Aegis.Core.Crypto
{
    public static class SessionKeyFactory
    {
        // =========================================================
        // ACCOUNT ROOT KEY
        // Deterministic across logins
        // Derived from master key
        // =========================================================

        public static AccountRootKey CreateAccountRootKey(
            SecureMasterKey masterKey,
            byte[] sessionSalt)
        {
            byte[] keyBytes =
                masterKey.DeriveKey(
                    sessionSalt,
                    "AEGIS-ACCOUNT-ROOT"u8,
                    64);

            return new AccountRootKey(keyBytes);
        }

        // =========================================================
        // FILE ROOT KEY
        // Deterministic from account root key
        // =========================================================

        public static FileRootKey CreateFileRootKey(
            AccountRootKey accountRoot,
            byte[] fileRootSalt)
        {
            byte[] keyBytes =
                accountRoot.DeriveKey(
                    fileRootSalt,
                    "AEGIS-FILE-ROOT"u8,
                    64);

            return new FileRootKey(
                keyBytes,
                fileRootSalt);
        }

        // =========================================================
        // MEMORY PROTECTION KEY
        // Used for:
        // - in-memory encryption
        // - swap/pagefile protection
        // - secure cache encryption
        // =========================================================

        public static MemoryProtectionKey CreateMemoryProtectionKey(
            AccountRootKey accountRoot,
            byte[] salt)
        {
            byte[] keyBytes =
                accountRoot.DeriveKey(
                    salt,
                    "AEGIS-MEMORY-PROTECTION"u8,
                    32);

            return new MemoryProtectionKey(keyBytes);
        }

        // =========================================================
        // IPC WRAPPING KEY
        // Deterministic derivation branch
        // Used ONLY to wrap ephemeral IPC session keys
        // =========================================================

        public static IpcWrappingKey CreateIpcWrappingKey(
            AccountRootKey accountRoot,
            byte[] salt)
        {
            byte[] keyBytes =
                accountRoot.DeriveKey(
                    salt,
                    "AEGIS-IPC-WRAP"u8,
                    32);

            return new IpcWrappingKey(keyBytes);
        }
    }


    // ============================================================
    // FILE KEY
    //
    // Contains TWO independent secret keys:
    //   - encryption key
    //   - HMAC key
    //
    // Therefore this does NOT inherit SecureKeyBase.
    // ============================================================

    public sealed class FileKey : IDisposable
    {
        private readonly SecureBuffer _encryptionKey;
        private readonly SecureBuffer _hmacKey;

        private bool _disposed;

        public FileKey(
            byte[] rootKey,
            byte[] fileSalt)
        {
            ArgumentNullException.ThrowIfNull(
                rootKey);

            ArgumentNullException.ThrowIfNull(
                fileSalt);

            if (fileSalt.Length < 16)
            {
                throw new ArgumentException(
                    "File salt must be at least 16 bytes.",
                    nameof(fileSalt));
            }

            byte[] material =
                Hkdf.HkdfExpand(
                    rootKey,
                    fileSalt,
                    "AEGIS-FILE-KEY-MATERIAL"u8,
                    64);

            byte[]? encryptionKey = null;
            byte[]? hmacKey = null;

            try
            {
                encryptionKey =
                    Hkdf.HkdfExpand(
                        material,
                        "FILE-ENC-KEY"u8,
                        "ENC"u8,
                        64);

                hmacKey =
                    Hkdf.HkdfExpand(
                        material,
                        "FILE-HMAC-KEY"u8,
                        "HMAC"u8,
                        64);

                _encryptionKey =
                    new SecureBuffer(
                        encryptionKey);

                _hmacKey =
                    new SecureBuffer(
                        hmacKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    material);

                if (encryptionKey != null)
                {
                    CryptographicOperations.ZeroMemory(
                        encryptionKey);
                }

                if (hmacKey != null)
                {
                    CryptographicOperations.ZeroMemory(
                        hmacKey);
                }
            }
        }

        public Span<byte> EncryptionKey
        {
            get
            {
                ThrowIfDisposed();

                return _encryptionKey.AsSpan();
            }
        }

        public Span<byte> HmacKey
        {
            get
            {
                ThrowIfDisposed();

                return _hmacKey.AsSpan();
            }
        }

        public byte[] ExportEncryptionKey()
        {
            ThrowIfDisposed();

            return _encryptionKey.ToArrayCopy();
        }

        public byte[] ExportHmacKey()
        {
            ThrowIfDisposed();

            return _hmacKey.ToArrayCopy();
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            _encryptionKey.Dispose();
            _hmacKey.Dispose();

            GC.SuppressFinalize(this);
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);
        }
    }


    // ============================================================
    // FILE ROOT KEY
    // ============================================================

    public sealed class FileRootKey : SecureKeyBase
    {
        private readonly byte[] _salt;

        internal FileRootKey(
            byte[] key,
            byte[] salt)
            : base(key)
        {
            ArgumentNullException.ThrowIfNull(
                salt);

            _salt =
                salt.ToArray();
        }

        public static FileRootKey FromSession(
            SessionKey sessionKey,
            byte[] fileRootSalt)
        {
            ArgumentNullException.ThrowIfNull(
                sessionKey);

            ArgumentNullException.ThrowIfNull(
                fileRootSalt);

            byte[] key =
                sessionKey.DeriveKey(
                    fileRootSalt,
                    "AEGIS-FILE-ROOT-KEY"u8,
                    64);

            try
            {
                return new FileRootKey(
                    key,
                    fileRootSalt);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }

        public FileKey DeriveFileKey(
            byte[] salt)
        {
            ThrowIfDisposed();

            ArgumentNullException.ThrowIfNull(
                salt);

            byte[] key =
                Hkdf.HkdfExpand(
                    KeyReadOnly,
                    salt,
                    "AEGIS-FILE-KEY"u8,
                    64);

            try
            {
                return new FileKey(
                    key,
                    salt);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }

        public byte[] ExportSalt()
        {
            ThrowIfDisposed();

            return _salt.ToArray();
        }

        protected override void Dispose(
            bool disposing)
        {
            if (disposing)
            {
                CryptographicOperations.ZeroMemory(
                    _salt);
            }

            base.Dispose(disposing);
        }
    }


    // ============================================================
    // IPC SESSION KEY
    // ============================================================

    public sealed class IpcSessionKey : SecureKeyBase
    {
        public IpcSessionKey(
            byte[] key)
            : base(key)
        {
            ArgumentNullException.ThrowIfNull(
                key);
        }

        public byte[] Export()
        {
            ThrowIfDisposed();

            return Buffer.ToArrayCopy();
        }

        public static IpcSessionKey CreateEphemeralIpcKey()
        {
            byte[] keyBytes =
                RandomNumberGenerator.GetBytes(32);

            try
            {
                return new IpcSessionKey(
                    keyBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    keyBytes);
            }
        }
    }


    // ============================================================
    // IPC WRAPPING KEY
    // ============================================================

    public sealed class IpcWrappingKey : SecureKeyBase
    {
        public IpcWrappingKey(
            byte[] key)
            : base(key)
        {
            ArgumentNullException.ThrowIfNull(
                key);
        }

        public byte[] WrapKey(
            byte[] plaintextKey)
        {
            ThrowIfDisposed();

            ArgumentNullException.ThrowIfNull(
                plaintextKey);

            byte[] nonce =
                RandomNumberGenerator.GetBytes(12);

            byte[] ciphertext =
                new byte[plaintextKey.Length];

            byte[] tag =
                new byte[16];

            try
            {
                using var aes =
                    new AesGcm(
                        KeyReadOnly,
                        tagSizeInBytes: 16);

                aes.Encrypt(
                    nonce,
                    plaintextKey,
                    ciphertext,
                    tag);

                using var ms =
                    new MemoryStream(
                        12 +
                        16 +
                        ciphertext.Length);

                ms.Write(nonce);
                ms.Write(tag);
                ms.Write(ciphertext);

                return ms.ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    nonce);

                CryptographicOperations.ZeroMemory(
                    tag);

                CryptographicOperations.ZeroMemory(
                    ciphertext);
            }
        }

        public byte[] UnwrapKey(
            byte[] wrapped)
        {
            ThrowIfDisposed();

            ArgumentNullException.ThrowIfNull(
                wrapped);

            if (wrapped.Length < 28)
            {
                throw new ArgumentException(
                    "Wrapped key is too short.",
                    nameof(wrapped));
            }

            ReadOnlySpan<byte> nonce =
                wrapped.AsSpan(
                    0,
                    12);

            ReadOnlySpan<byte> tag =
                wrapped.AsSpan(
                    12,
                    16);

            ReadOnlySpan<byte> ciphertext =
                wrapped.AsSpan(
                    28);

            byte[] plaintext =
                new byte[ciphertext.Length];

            try
            {
                using var aes =
                    new AesGcm(
                        KeyReadOnly,
                        tagSizeInBytes: 16);

                aes.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    plaintext);

                return plaintext;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(
                    plaintext);

                throw;
            }
        }
    }


    // ============================================================
    // MEMORY PROTECTION KEY
    // ============================================================

    public sealed class MemoryProtectionKey : SecureKeyBase
    {
        public MemoryProtectionKey(
            byte[] key)
            : base(key)
        {
            ArgumentNullException.ThrowIfNull(
                key);
        }
    }


    // ============================================================
    // ACCOUNT ROOT KEY
    // ============================================================

    public sealed class AccountRootKey : SecureKeyBase
    {
        public AccountRootKey(
            byte[] key)
            : base(key)
        {
            ArgumentNullException.ThrowIfNull(
                key);
        }

        public byte[] DeriveKey(
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int length)
        {
            ThrowIfDisposed();

            var key = Hkdf.HkdfExpand(
                KeyReadOnly,
                salt,
                info,
                length);

            var protectedKey = new SecureBuffer(key);

            return protectedKey.ToArrayCopy();
        }
    }
}

