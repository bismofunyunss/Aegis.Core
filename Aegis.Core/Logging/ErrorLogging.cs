using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Channels;

namespace Aegis.Core.Logging
{
    internal static class Logging
    {
        private static readonly Channel<string> _logChannel =
            Channel.CreateBounded<string>(
                new BoundedChannelOptions(10000)
                {
                    SingleReader = true,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait
                });

        private static readonly CancellationTokenSource _cts = new();
        private static readonly Task _writerTask;

        public static bool Enabled { get; set; } = true;
        public static bool EnableTrace { get; set; } = false;
        public static bool EnableTiming { get; set; } = true;
        public static bool EnableMemoryTrace { get; set; } = false;

        static Logging()
        {
            _writerTask = Task.Run(async () =>
            {
                await foreach (var msg in _logChannel.Reader.ReadAllAsync(_cts.Token))
                {
                    Console.WriteLine(msg);
                }
            });
        }

        // =========================
        // ASYNC CORE LOG (NO BLOCKING)
        // =========================
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Log(string stage, string message)
        {
            if (!Enabled) return;

            string line =
                $"[{DateTime.UtcNow:HH:mm:ss.fff}] " +
                $"[T{Environment.CurrentManagedThreadId}] " +
                $"[{stage}] {message}";

            if (!_logChannel.Writer.TryWrite(line))
            {
                _logChannel.Writer.WriteAsync(line).AsTask().Wait();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Log(string message)
        {
            if (!Enabled) return;

            string line =
                $"[{DateTime.UtcNow:HH:mm:ss.fff}] " +
                $"[T{Environment.CurrentManagedThreadId}] {message}";

            if (!_logChannel.Writer.TryWrite(line))
            {
                _logChannel.Writer.WriteAsync(line).AsTask().Wait();
            }
        }

        internal static void LogEx(string stage, string message, Exception ex)
        {
            if (!Enabled) return;

            string line =
                $"[{DateTime.UtcNow:HH:mm:ss.fff}] " +
                $"[T{Environment.CurrentManagedThreadId}] " +
                $"[{stage}] {message}\n{ex}";

            _logChannel.Writer.TryWrite(line);
        }

        // =========================
        // BYTE LOGGING (ASYNC SAFE)
        // =========================
        public static void LogBytes(string label, ReadOnlySpan<byte> data, int maxBytes = 128)
        {
            if (!Enabled) return;

            if (data.IsEmpty)
            {
                Log($"{label}: <EMPTY>");
                return;
            }

            int len = Math.Min(data.Length, maxBytes);

            char[] rented = ArrayPool<char>.Shared.Rent(len * 2);

            try
            {
                const string map = "0123456789ABCDEF";

                for (int i = 0; i < len; i++)
                {
                    byte b = data[i];
                    rented[i * 2] = map[b >> 4];
                    rented[i * 2 + 1] = map[b & 0xF];
                }

                string hex = new string(rented, 0, len * 2);

                Log($"{label}: {hex}" +
                    (len < data.Length ? $" ... (+{data.Length - len} bytes)" : ""));
            }
            finally
            {
                ArrayPool<char>.Shared.Return(rented);
            }
        }

        // =========================
        // OPTIONAL: FLUSH (for shutdown)
        // =========================
        public static async Task FlushAsync()
        {
            _logChannel.Writer.Complete();
            await _writerTask;
        }
    }

    public static class ExceptionLogger
    {
        private static readonly object LockObject = new();

        public static void Log(
            Exception ex,
            string context, string username)
        {
            try
            {
                var folder =
                    Path.Combine(
                        Environment.GetFolderPath(
                            Environment.SpecialFolder.LocalApplicationData),
                        "Aegis",
                        "Users",
                        username);

                Directory.CreateDirectory(folder);

                var path =
                    Path.Combine(
                        folder,
                        "ExceptionLog.txt");

                lock (LockObject)
                {
                    using var writer =
                        new StreamWriter(
                            path,
                            append: true);

                    writer.WriteLine(
                        "====================================================");

                    writer.WriteLine(
                        $"UTC Time : {DateTime.UtcNow:O}");

                    writer.WriteLine(
                        $"Context  : {context}");

                    writer.WriteLine(
                        $"Type     : {ex.GetType().FullName}");

                    writer.WriteLine(
                        $"Message  : {ex.Message}");

                    writer.WriteLine();

                    writer.WriteLine(
                        ex.ToString());

                    writer.WriteLine();
                }
            }
            catch
            {
                //
                // Never allow logging to crash encryption.
                //
            }
        }
    }
}
