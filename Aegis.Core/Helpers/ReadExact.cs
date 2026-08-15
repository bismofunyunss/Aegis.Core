using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Helpers
{
    internal class ReadExact
    {
        public static async Task<byte[]> ReadExactAsync(
            Stream s,
            int length,
            int maxAllowed = 100 * 1024 * 1024,
            CancellationToken ct = default)
        {
            if (length <= 0 || length > maxAllowed)
                throw new InvalidDataException($"Invalid read length: {length}");

            byte[] buffer = new byte[length];
            int read = 0;

            while (read < length)
            {
                int n = await s.ReadAsync(buffer.AsMemory(read, length - read), ct);

                if (n == 0)
                    throw new EndOfStreamException("Unexpected EOF while reading exact data.");

                read += n;
            }

            return buffer;
        }

        public static async Task ReadExactAsync(
            Stream stream,
            byte[] buffer,
            int length,
            CancellationToken ct)
        {
            int offset = 0;

            while (offset < length)
            {
                int read =
                    await stream.ReadAsync(
                        buffer.AsMemory(
                            offset,
                            length - offset),
                        ct);


                if (read == 0)
                    throw new EndOfStreamException(
                        "Pipe closed unexpectedly.");


                offset += read;
            }
        }
    }
}
