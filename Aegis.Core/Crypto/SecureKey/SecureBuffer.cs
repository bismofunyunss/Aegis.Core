using System;
using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal sealed unsafe class SecureBuffer : IDisposable
    {
        private sealed class SecureMemoryHandle : SafeHandle
        {
            private readonly nuint _size;

            public SecureMemoryHandle(
                nuint size)
                : base(
                    IntPtr.Zero,
                    ownsHandle: true)
            {
                _size = size;

                if (_size == 0)
                    return;

                SetHandle(
                    VirtualAlloc(
                        IntPtr.Zero,
                        _size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE));

                if (IsInvalid)
                {
                    int error =
                        Marshal.GetLastWin32Error();

                    throw new System.ComponentModel.Win32Exception(
                        error,
                        "VirtualAlloc failed.");
                }

                // Best effort only.
                VirtualLock(
                    handle,
                    _size);
            }

            public override bool IsInvalid =>
                handle == IntPtr.Zero ||
                handle == new IntPtr(-1);

            protected override bool ReleaseHandle()
            {
                if (IsInvalid)
                    return true;

                CryptographicOperations.ZeroMemory(
                    new Span<byte>(
                        (void*)handle,
                        checked((int)_size)));

                VirtualUnlock(
                    handle,
                    _size);

                return VirtualFree(
                    handle,
                    UIntPtr.Zero,
                    MEM_RELEASE);
            }

            [DllImport(
                "kernel32.dll",
                SetLastError = true)]
            private static extern IntPtr VirtualAlloc(
                IntPtr lpAddress,
                nuint dwSize,
                uint flAllocationType,
                uint flProtect);

            [DllImport(
                "kernel32.dll",
                SetLastError = true)]
            private static extern bool VirtualFree(
                IntPtr lpAddress,
                UIntPtr dwSize,
                uint dwFreeType);

            [DllImport(
                "kernel32.dll",
                SetLastError = true)]
            private static extern bool VirtualLock(
                IntPtr lpAddress,
                nuint dwSize);

            [DllImport(
                "kernel32.dll",
                SetLastError = true)]
            private static extern bool VirtualUnlock(
                IntPtr lpAddress,
                nuint dwSize);

            private const uint MEM_COMMIT = 0x1000;
            private const uint MEM_RESERVE = 0x2000;
            private const uint MEM_RELEASE = 0x8000;
            private const uint PAGE_READWRITE = 0x04;
        }

        private readonly SecureMemoryHandle _handle;
        private readonly int _length;

        private bool _disposed;

        public SecureBuffer(
            ReadOnlySpan<byte> source)
        {
            _length = source.Length;

            _handle =
                new SecureMemoryHandle(
                    checked((nuint)_length));

            if (_length != 0)
            {
                source.CopyTo(
                    new Span<byte>(
                        (void*)_handle.DangerousGetHandle(),
                        _length));
            }
        }

        public int Length
        {
            get
            {
                ThrowIfDisposed();

                return _length;
            }
        }

        public Span<byte> AsSpan()
        {
            ThrowIfDisposed();

            return new Span<byte>(
                (void*)_handle.DangerousGetHandle(),
                _length);
        }

        public ReadOnlySpan<byte> AsReadOnlySpan()
        {
            ThrowIfDisposed();

            return new ReadOnlySpan<byte>(
                (void*)_handle.DangerousGetHandle(),
                _length);
        }

        public byte[] ToArrayCopy()
        {
            ThrowIfDisposed();

            byte[] result =
                new byte[_length];

            AsReadOnlySpan().CopyTo(result);

            return result;
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            _handle.Dispose();

            GC.SuppressFinalize(this);
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);
        }
    }
}
