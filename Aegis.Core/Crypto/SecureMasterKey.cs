using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
    internal static class NativeMemory
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualLock(
            IntPtr lpAddress,
            UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualUnlock(
            IntPtr lpAddress,
            UIntPtr dwSize);
    }


    public sealed class SecureMasterKey : IDisposable
    {
        private IntPtr _ptr;
        private int _len;
        private bool _disposed;


        public SecureMasterKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length == 0)
                throw new ArgumentException(
                    "Master key cannot be empty.",
                    nameof(key));


            _len = key.Length;

            try
            {
                _ptr = Marshal.AllocHGlobal(_len);

                Marshal.Copy(
                    key,
                    0,
                    _ptr,
                    _len);


                if (!NativeMemory.VirtualLock(
                        _ptr,
                        (UIntPtr)_len))
                {
                    Marshal.FreeHGlobal(_ptr);
                    _ptr = IntPtr.Zero;

                    throw new CryptographicException(
                        "Unable to lock master key memory.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }


        public byte[] DeriveKey(
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int length)
        {
            EnsureAlive();

            unsafe
            {
                var masterSpan =
                    new ReadOnlySpan<byte>(
                        (void*)_ptr,
                        _len);

                return Hkdf.HkdfExpand(
                    masterSpan,
                    salt,
                    info,
                    length);
            }
        }


        public byte[] Export()
        {
            EnsureAlive();

            byte[] result = new byte[_len];

            Marshal.Copy(
                _ptr,
                result,
                0,
                _len);

            return result;
        }


        private void EnsureAlive()
        {
            if (_disposed ||
                _ptr == IntPtr.Zero)
            {
                throw new ObjectDisposedException(
                    nameof(SecureMasterKey));
            }
        }


        public void Dispose()
        {
            Dispose(true);

            GC.SuppressFinalize(this);
        }


        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            _disposed = true;


            if (_ptr != IntPtr.Zero)
            {
                unsafe
                {
                    CryptographicOperations.ZeroMemory(
                        new Span<byte>(
                            (void*)_ptr,
                            _len));
                }


                NativeMemory.VirtualUnlock(
                    _ptr,
                    (UIntPtr)_len);


                Marshal.FreeHGlobal(_ptr);


                _ptr = IntPtr.Zero;
            }


            _len = 0;
        }


        ~SecureMasterKey()
        {
            Dispose(false);
        }
    }
}
