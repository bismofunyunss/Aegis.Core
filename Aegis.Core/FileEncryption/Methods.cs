using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Aegis.Core.Crypto;
using Aegis.Core.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Sodium;
using Buffer = System.Buffer;

namespace Aegis.Core.FileEncryption;

internal class Methods
{
    private const long FAILURE_BUDGET_TICKS = 1_500_000;

    public static async Task RunRoundTripTest(
        DerivedKeys keys,
        long dataSize)
    {
        var originalPath =
            Path.Combine(
                Path.GetTempPath(),
                $"orig_{Guid.NewGuid():N}.bin");

        var encryptedPath =
            Path.Combine(
                Path.GetTempPath(),
                $"enc_{Guid.NewGuid():N}.bin");

        var decryptedPath =
            Path.Combine(
                Path.GetTempPath(),
                $"dec_{Guid.NewGuid():N}.bin");

        try
        {
            // =========================
            // GENERATE ORIGINAL FILE
            // =========================

            Logging.Logging.Log(
                "ROUNDTRIP",
                $"GENERATE START Size={dataSize:N0}");

            await using (var originalOut =
                         new FileStream(
                             originalPath,
                             FileMode.Create,
                             FileAccess.Write,
                             FileShare.None,
                             1024 * 1024,
                             FileOptions.SequentialScan))
            {
                await using var source =
                    new CryptoAttackCampaign.DeterministicRandomStream(dataSize);

                await source.CopyToAsync(originalOut);
            }

            Logging.Logging.Log(
                "ROUNDTRIP",
                "GENERATE COMPLETE");

            // =========================
            // ENCRYPT
            // =========================

            Logging.Logging.Log(
                "ROUNDTRIP",
                $"ENCRYPT START Size={dataSize:N0}");

            await using (var original =
                         new FileStream(
                             originalPath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.Read,
                             1024 * 1024,
                             FileOptions.SequentialScan))
            await using (var encrypted =
                         new FileStream(
                             encryptedPath,
                             FileMode.Create,
                             FileAccess.Write,
                             FileShare.None,
                             1024 * 1024,
                             FileOptions.SequentialScan))
            {
                await Encrypt(
                    original,
                    encrypted,
                    keys,
                    new CryptoPipelineOptions());
            }

            var encryptedSize =
                new FileInfo(encryptedPath).Length;

            Logging.Logging.Log(
                "ROUNDTRIP",
                $"ENCRYPT COMPLETE Size={encryptedSize:N0}");

            // =========================
            // DECRYPT
            // =========================

            Logging.Logging.Log(
                "ROUNDTRIP",
                "DECRYPT START");

            await using (var encrypted =
                         new FileStream(
                             encryptedPath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.Read,
                             1024 * 1024,
                             FileOptions.SequentialScan))
            await using (var decrypted =
                         new FileStream(
                             decryptedPath,
                             FileMode.Create,
                             FileAccess.Write,
                             FileShare.None,
                             1024 * 1024,
                             FileOptions.SequentialScan))
            {
                await Decrypt(
                    encrypted,
                    decrypted,
                    keys,
                    new CryptoPipelineOptions());
            }

            Logging.Logging.Log(
                "ROUNDTRIP",
                "DECRYPT COMPLETE");

            // =========================
            // VERIFY
            // =========================

            await using var expected =
                new CryptoAttackCampaign.DeterministicRandomStream(dataSize);

            await using var actual =
                new FileStream(
                    decryptedPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    1024 * 1024,
                    FileOptions.SequentialScan);

            var match =
                await StreamsMatchAsync(
                    expected,
                    actual,
                    CancellationToken.None);

            Logging.Logging.Log(
                "ROUNDTRIP",
                $"MATCH={match}");

            if (!match)
                throw new CryptographicException(
                    "Round-trip verification failed.");

            Logging.Logging.Log(
                "ROUNDTRIP",
                "PASS");
        }
        finally
        {
            try
            {
                if (File.Exists(originalPath))
                    await FileEraser.SecureDeleteAsync(originalPath);
            }
            catch
            {
            }

            try
            {
                if (File.Exists(encryptedPath))
                    await FileEraser.SecureDeleteAsync(encryptedPath);
            }
            catch
            {
            }

            try
            {
                if (File.Exists(decryptedPath))
                    await FileEraser.SecureDeleteAsync(decryptedPath);
            }
            catch
            {
            }
        }
    }

    private static async Task<bool> StreamsMatchAsync(
        Stream a,
        Stream b,
        CancellationToken ct)
    {
        const int bufferSize = 1024 * 1024; // 1MB

        var bufA = new byte[bufferSize];
        var bufB = new byte[bufferSize];

        while (true)
        {
            var readA = await a.ReadAsync(bufA, ct);
            var readB = await b.ReadAsync(bufB, ct);

            if (readA != readB)
                return false;

            if (readA == 0)
                return true;

            if (!bufA.AsSpan(0, readA)
                    .SequenceEqual(bufB.AsSpan(0, readB)))
                return false;
        }
    }

    public static async Task Encrypt(
        Stream input,
        Stream output,
        DerivedKeys keys,
        CryptoPipelineOptions opt)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(opt);


        const int CHUNK_SIZE = 64 * 1024;

        const long MAX_FILE_SIZE =
            4L * 1024 * 1024 * 1024 * 1024;


        const ushort FORMAT_VERSION = 3;

        const int HMAC_SIZE = 64;


        if (!input.CanRead)
            throw new ArgumentException(
                "Input stream must be readable.",
                nameof(input));


        if (!output.CanWrite)
            throw new ArgumentException(
                "Output stream must be writable.",
                nameof(output));


        if (!input.CanSeek)
            throw new NotSupportedException(
                "Encryption requires a seekable stream.");


        if (opt.ChannelCapacity <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(opt.ChannelCapacity));


        if (opt.ThreefishWorkers <= 0 ||
            opt.SerpentWorkers <= 0 ||
            opt.AesWorkers <= 0 ||
            opt.XChaChaWorkers <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(opt),
                "Worker counts must be greater than zero.");


        var totalTimer =
            Stopwatch.StartNew();


        using var pipelineCts =
            CancellationTokenSource.CreateLinkedTokenSource(
                opt.CancellationToken);


        var ct =
            pipelineCts.Token;


        byte[]? xNonce;
        byte[]? tNonce;
        byte[]? sNonce;
        byte[]? aNonce;


        byte[]? xSalt;
        byte[]? tSalt;
        byte[]? sSalt;
        byte[]? aSalt;


        static void CleanupChunk(
            CryptoChunk chunk)
        {
            if (chunk.Buffer != null)
            {
                var clearLength =
                    Math.Min(
                        chunk.Length,
                        chunk.Buffer.Length);


                if (clearLength > 0)
                    CryptographicOperations.ZeroMemory(
                        chunk.Buffer.AsSpan(
                            0,
                            clearLength));


                if (chunk.BufferPooled)
                {
                    ArrayPool<byte>.Shared.Return(
                        chunk.Buffer,
                        true);


                    chunk.BufferPooled = false;
                }


                chunk.Buffer = null;
            }


            if (chunk.AeadTag != null)
            {
                CryptographicOperations.ZeroMemory(
                    chunk.AeadTag);


                chunk.AeadTag = null;
            }
        }

        Exception? pipelineFailure = null;

        var failureState = 0;


        void Fail(
            Exception ex)
        {
            if (ex is OperationCanceledException)
                return;


            if (Interlocked.CompareExchange(
                    ref failureState,
                    1,
                    0) != 0)
                return;


            Interlocked.CompareExchange(
                ref pipelineFailure,
                ex,
                null);

            pipelineCts.Cancel();
        }


        try
        {
            //
            // FIRST PASS
            //

            long plaintextLength = 0;

            long expectedChunkCount = 0;


            var scanBuffer =
                ArrayPool<byte>.Shared.Rent(
                    CHUNK_SIZE);


            try
            {
                while (true)
                {
                    ct.ThrowIfCancellationRequested();


                    var read =
                        await input.ReadAsync(
                            scanBuffer.AsMemory(
                                0,
                                CHUNK_SIZE),
                            ct);


                    if (read == 0)
                        break;


                    plaintextLength += read;

                    expectedChunkCount++;


                    if (plaintextLength > MAX_FILE_SIZE)
                        throw new CryptographicException(
                            "Maximum plaintext size exceeded.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    scanBuffer);


                ArrayPool<byte>.Shared.Return(
                    scanBuffer,
                    true);
            }


            if (plaintextLength <= 0)
                throw new CryptographicException(
                    "Zero length files are not supported.");


            input.Seek(
                0,
                SeekOrigin.Begin);


            //
            // HEADER MATERIAL
            //

            xNonce = new byte[16];

            tNonce = new byte[8];

            sNonce = new byte[8];

            aNonce = new byte[8];


            xSalt = new byte[128];

            tSalt = new byte[128];

            sSalt = new byte[128];

            aSalt = new byte[128];


            RandomNumberGenerator.Fill(
                xNonce);

            RandomNumberGenerator.Fill(
                tNonce);

            RandomNumberGenerator.Fill(
                sNonce);

            RandomNumberGenerator.Fill(
                aNonce);


            RandomNumberGenerator.Fill(
                xSalt);

            RandomNumberGenerator.Fill(
                tSalt);

            RandomNumberGenerator.Fill(
                sSalt);

            RandomNumberGenerator.Fill(
                aSalt);

            Logging.Logging.Log(
                $"Initial output position={output.Position}");

            //
            // BUILD HEADER
            //

            byte[]? header;

            using (var ms = new MemoryStream())
            {
                Span<byte> buffer =
                    stackalloc byte[8];


                Span<byte> version =
                    stackalloc byte[2];


                BinaryPrimitives.WriteUInt16LittleEndian(
                    version,
                    FORMAT_VERSION);


                ms.Write(
                    version);


                BinaryPrimitives.WriteUInt64LittleEndian(
                    buffer,
                    ulong.MaxValue);


                ms.Write(
                    buffer);


                ms.Write(
                    xNonce);

                ms.Write(
                    tNonce);

                ms.Write(
                    sNonce);

                ms.Write(
                    aNonce);


                ms.Write(
                    xSalt);

                ms.Write(
                    tSalt);

                ms.Write(
                    sSalt);

                ms.Write(
                    aSalt);


                BinaryPrimitives.WriteInt64LittleEndian(
                    buffer,
                    plaintextLength);


                ms.Write(
                    buffer);


                BinaryPrimitives.WriteInt64LittleEndian(
                    buffer,
                    expectedChunkCount);


                ms.Write(
                    buffer);


                header =
                    ms.ToArray();
            }

            //
            // HEADER MAC
            //

            byte[]? headerMac;

            using (var hmac =
                   new HMACSHA3_512(
                       keys.HeaderHmacKey))
            {
                headerMac =
                    hmac.ComputeHash(
                        header);
            }


            await output.WriteAsync(
                header,
                ct);


            await output.WriteAsync(
                headerMac,
                ct);

            // =====================================================
            // CHANNEL CREATION
            // =====================================================

            Channel<CryptoChunk> CreateChannel()
            {
                return Channel.CreateBounded<CryptoChunk>(
                    new BoundedChannelOptions(
                        opt.ChannelCapacity)
                    {
                        FullMode =
                            BoundedChannelFullMode.Wait,

                        SingleReader = false,
                        SingleWriter = false,

                        AllowSynchronousContinuations = false
                    });
            }


            var c0 = CreateChannel();
            var c1 = CreateChannel();
            var c2 = CreateChannel();
            var c3 = CreateChannel();
            var c4 = CreateChannel();

            // =====================================================
            // PRODUCER STAGE
            // =====================================================

            async Task ProducerAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                var readBuffer =
                    ArrayPool<byte>.Shared.Rent(
                        CHUNK_SIZE);


                long index = 0;
                long offset = 0;
                long bytesProduced = 0;


                try
                {
                    while (true)
                    {
                        ct.ThrowIfCancellationRequested();


                        var read =
                            await input.ReadAsync(
                                readBuffer.AsMemory(
                                    0,
                                    CHUNK_SIZE),
                                ct);


                        if (read == 0)
                            break;


                        var buffer =
                            ArrayPool<byte>.Shared.Rent(
                                CHUNK_SIZE);


                        var transferred = false;


                        try
                        {
                            Buffer.BlockCopy(
                                readBuffer,
                                0,
                                buffer,
                                0,
                                read);


                            var chunk =
                                new CryptoChunk
                                {
                                    Index =
                                        index,

                                    ByteOffset =
                                        offset,

                                    Buffer =
                                        buffer,

                                    Length =
                                        read,

                                    BufferPooled =
                                        true
                                };


                            await c0.Writer.WriteAsync(
                                chunk,
                                ct);


                            transferred = true;


                            index++;

                            offset += read;

                            bytesProduced += read;
                        }
                        finally
                        {
                            if (!transferred)
                            {
                                CryptographicOperations.ZeroMemory(
                                    buffer.AsSpan(
                                        0,
                                        read));


                                ArrayPool<byte>.Shared.Return(
                                    buffer,
                                    true);
                            }
                        }
                    }


                    if (index != expectedChunkCount)
                        throw new CryptographicException(
                            $"Producer chunk mismatch. " +
                            $"Expected={expectedChunkCount:N0} " +
                            $"Actual={index:N0}");
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        readBuffer);


                    ArrayPool<byte>.Shared.Return(
                        readBuffer,
                        true);


                    c0.Writer.TryComplete(
                        pipelineFailure);
                }
            }

            // =====================================================
            // THREEFISH STAGE
            // =====================================================

            var threefishSalt = tSalt;

            var threefishNonce = tNonce;

            async Task<byte[]> ThreefishStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                try
                {
                    var tag =
                        await CtrEncrypt(
                            c0.Reader,
                            c1.Writer,
                            keys.ThreefishKey,
                            keys.ThreefishHmacKey,
                            () =>
                                new ThreefishEngine(
                                    1024),
                            threefishNonce,
                            threefishSalt,
                            128,
                            "THREEFISH-1024",
                            opt.ThreefishWorkers,
                            opt.ChannelCapacity,
                            expectedChunkCount,
                            null,
                            ct);

                    return tag;
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    c1.Writer.TryComplete(
                        pipelineFailure);
                }
            }


            // =====================================================
            // SERPENT STAGE
            // =====================================================

            var serpentSalt = sSalt;

            async Task<byte[]> SerpentStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                try
                {
                    var tag =
                        await CtrEncrypt(
                            c1.Reader,
                            c2.Writer,
                            keys.SerpentKey,
                            keys.SerpentHmacKey,
                            () =>
                                new SerpentEngine(),
                            sNonce,
                            serpentSalt,
                            16,
                            "SERPENT-256",
                            opt.SerpentWorkers,
                            opt.ChannelCapacity,
                            expectedChunkCount,
                            null,
                            ct);

                    return tag;
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    c2.Writer.TryComplete(
                        pipelineFailure);
                }
            }


            // =====================================================
            // AES STAGE
            // =====================================================

            var aesSalt = aSalt;

            var aesNonce = aNonce;

            async Task<byte[]> AesStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                try
                {
                    var tag =
                        await CtrEncrypt(
                            c2.Reader,
                            c3.Writer,
                            keys.AesKey,
                            keys.AesHmacKey,
                            () =>
                                new AesEngine(),
                            aesNonce,
                            aesSalt,
                            16,
                            "AES-256",
                            opt.AesWorkers,
                            opt.ChannelCapacity,
                            expectedChunkCount,
                            null,
                            ct);

                    return tag;
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    c3.Writer.TryComplete(
                        pipelineFailure);
                }
            }


            // =====================================================
            // XCHACHA20-POLY1305 STAGE
            // =====================================================

            var xchachaNonce = xNonce;

            var xchachaSalt = xSalt;

            async Task XChaChaStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                try
                {
                    await XChaChaEncryptStage(
                        c3.Reader,
                        c4.Writer,
                        keys.XChaChaKey,
                        xchachaNonce,
                        xchachaSalt,
                        "XCHACHA20-POLY1305",
                        24,
                        opt.XChaChaWorkers,
                        opt.ChannelCapacity,
                        expectedChunkCount,
                        ct);
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    c4.Writer.TryComplete(
                        pipelineFailure);
                }
            }

            // =====================================================
            // OUTPUT WRITER STAGE
            // =====================================================

            async Task WriterStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                long chunksWritten = 0;
                long bytesWritten = 0;
                long lastIndex = -1;


                var chunkHeader =
                    new byte[24];


                try
                {
                    await foreach (var chunk in
                                   c4.Reader.ReadAllAsync(ct))
                        try
                        {
                            if (chunk.Buffer == null)
                                throw new CryptographicException(
                                    $"[WRITER] Missing buffer. Index={chunk.Index}");


                            if (chunk.Length <= 0 ||
                                chunk.Length > chunk.Buffer.Length)
                                throw new CryptographicException(
                                    $"[WRITER] Invalid length. " +
                                    $"Index={chunk.Index} " +
                                    $"Length={chunk.Length}");


                            if (chunk.AeadTag == null ||
                                chunk.AeadTag.Length != 16)
                                throw new CryptographicException(
                                    $"[WRITER] Missing AEAD tag. Index={chunk.Index}");


                            if (chunk.Index != lastIndex + 1)
                                throw new CryptographicException(
                                    $"[WRITER] Ordering violation. " +
                                    $"Expected={lastIndex + 1} " +
                                    $"Actual={chunk.Index}");


                            BinaryPrimitives.WriteUInt64LittleEndian(
                                chunkHeader.AsSpan(0, 8),
                                (ulong)chunk.Index);

                            BinaryPrimitives.WriteUInt64LittleEndian(
                                chunkHeader.AsSpan(8, 8),
                                (ulong)chunk.Length);

                            BinaryPrimitives.WriteUInt64LittleEndian(
                                chunkHeader.AsSpan(16, 8),
                                0);


                            await output.WriteAsync(
                                chunkHeader,
                                ct);

                            if (chunk.Index >= expectedChunkCount - 3)
                                Logging.Logging.Log(
                                    $"LAST CHUNKS Index={chunk.Index} Length={chunk.Length}");

                            await output.WriteAsync(
                                chunk.Buffer.AsMemory(
                                    0,
                                    chunk.Length),
                                ct);


                            await output.WriteAsync(
                                chunk.AeadTag,
                                ct);

                            if (chunk.Index >= expectedChunkCount - 3)
                                Logging.Logging.Log(
                                    $"WROTE CHUNK Index={chunk.Index}");


                            lastIndex =
                                chunk.Index;


                            chunksWritten++;

                            bytesWritten +=
                                chunk.Length;
                        }
                        finally
                        {
                            CleanupChunk(
                                chunk);
                        }


                    if (chunksWritten != expectedChunkCount)
                        throw new CryptographicException(
                            $"[WRITER] Chunk count mismatch. " +
                            $"Expected={expectedChunkCount:N0} " +
                            $"Actual={chunksWritten:N0}");


                    await output.FlushAsync(
                        ct);
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        chunkHeader);
                }
            }


            // =====================================================
            // START PIPELINE
            // =====================================================

            var producer =
                ProducerAsync();


            var threefish =
                ThreefishStageAsync();


            var serpent =
                SerpentStageAsync();


            var aes =
                AesStageAsync();


            var xchacha =
                XChaChaStageAsync();


            var writer =
                WriterStageAsync();

            // =====================================================
            // WAIT FOR PIPELINE
            // =====================================================

            byte[]? threefishTag = null;
            byte[]? serpentTag = null;
            byte[]? aesTag = null;


            var success = false;


            try
            {
                await Task.WhenAll(
                    producer,
                    threefish,
                    serpent,
                    aes,
                    xchacha,
                    writer);


                threefishTag =
                    await threefish;


                serpentTag =
                    await serpent;


                aesTag =
                    await aes;


                if (threefishTag.Length != HMAC_SIZE ||
                    serpentTag.Length != HMAC_SIZE ||
                    aesTag.Length != HMAC_SIZE)
                    throw new CryptographicException(
                        "Invalid authentication tag length.");


                await output.WriteAsync(
                    threefishTag,
                    ct);


                await output.WriteAsync(
                    serpentTag,
                    ct);


                await output.WriteAsync(
                    aesTag,
                    ct);


                await output.FlushAsync(
                    ct);


                success = true;

                Logging.Logging.Log(
                    "Encryption completed successfully.");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Fail(ex);

                throw new CryptographicException(
                    "Encryption pipeline failed.",
                    ex);
            }
            finally
            {
                pipelineCts.Cancel();


                c0.Writer.TryComplete(
                    pipelineFailure);

                c1.Writer.TryComplete(
                    pipelineFailure);

                c2.Writer.TryComplete(
                    pipelineFailure);

                c3.Writer.TryComplete(
                    pipelineFailure);

                c4.Writer.TryComplete(
                    pipelineFailure);


                try
                {
                    await Task.WhenAll(
                            producer,
                            threefish,
                            serpent,
                            aes,
                            xchacha,
                            writer)
                        .WaitAsync(
                            TimeSpan.FromMinutes(5), ct);
                }
                catch
                {
                    // shutdown cleanup only
                }


                static void Zero(
                    ref byte[]? data)
                {
                    if (data == null)
                        return;


                    CryptographicOperations.ZeroMemory(
                        data);


                    data = null;
                }


                Zero(ref header);
                Zero(ref headerMac);

                Zero(ref xNonce);
                Zero(ref tNonce);
                Zero(ref sNonce);
                Zero(ref aNonce);

                Zero(ref xSalt);
                Zero(ref tSalt);
                Zero(ref sSalt);
                Zero(ref aSalt);

                Zero(ref threefishTag);
                Zero(ref serpentTag);
                Zero(ref aesTag);


                static void Drain(
                    Channel<CryptoChunk> channel)
                {
                    while (channel.Reader.TryRead(
                               out var chunk))
                        CleanupChunk(
                            chunk);
                }


                Drain(c0);
                Drain(c1);
                Drain(c2);
                Drain(c3);
                Drain(c4);


                totalTimer.Stop();
            }
        }
        catch (Exception ex)
        {
            Fail(ex);
            throw;
        }
    }

    public static async Task Decrypt(
        Stream input,
        Stream output,
        DerivedKeys keys,
        CryptoPipelineOptions opt)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(opt);


        if (!input.CanRead)
            throw new ArgumentException(
                "Input stream must be readable.",
                nameof(input));


        if (!output.CanWrite)
            throw new ArgumentException(
                "Output stream must be writable.",
                nameof(output));


        if (!input.CanSeek)
            throw new NotSupportedException(
                "Encrypted stream must support seeking.");


        const int chunkSize =
            64 * 1024;


        const int hmacSize =
            64;


        const int aeadTagSize =
            16;


        const ushort formatVersion =
            3;


        const long maxFileSize =
            4L * 1024 * 1024 * 1024 * 1024;


        const int headerSize =
            sizeof(ushort) +
            sizeof(ulong) +
            16 +
            8 +
            8 +
            8 +
            128 +
            128 +
            128 +
            128 +
            sizeof(long) +
            sizeof(long);


        if (opt.ChannelCapacity <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(opt.ChannelCapacity), "Channel capacity was out of bounds.");


        if (opt.XChaChaWorkers <= 0 ||
            opt.AesWorkers <= 0 ||
            opt.SerpentWorkers <= 0 ||
            opt.ThreefishWorkers <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(opt),
                "Worker counts must be greater than zero.");

        static void CleanupChunk(
            CryptoChunk chunk)
        {
            if (chunk.Buffer != null)
            {
                var clearLength =
                    Math.Min(
                        chunk.Length,
                        chunk.Buffer.Length);


                if (clearLength > 0)
                    CryptographicOperations.ZeroMemory(
                        chunk.Buffer.AsSpan(
                            0,
                            clearLength));


                if (chunk.BufferPooled)
                {
                    ArrayPool<byte>.Shared.Return(
                        chunk.Buffer,
                        true);


                    chunk.BufferPooled = false;
                }


                chunk.Buffer = null;
            }


            if (chunk.AeadTag == null)
                return;

            CryptographicOperations.ZeroMemory(
                chunk.AeadTag);


            chunk.AeadTag = null;
        }


        var totalTimer =
            Stopwatch.StartNew();


        using var pipelineCts =
            CancellationTokenSource.CreateLinkedTokenSource(
                opt.CancellationToken);


        var ct =
            pipelineCts.Token;


        Exception? pipelineFailure =
            null;


        var failureState =
            0;


        void Fail(
            Exception ex)
        {
            if (ex is OperationCanceledException)
                return;


            if (Interlocked.CompareExchange(
                    ref failureState,
                    1,
                    0) != 0)
                return;


            Interlocked.CompareExchange(
                ref pipelineFailure,
                ex,
                null);

            pipelineCts.Cancel();
        }


        byte[]? xNonce = null;
        byte[]? tNonce = null;
        byte[]? sNonce = null;
        byte[]? aNonce = null;


        byte[]? xSalt = null;
        byte[]? tSalt = null;
        byte[]? sSalt = null;
        byte[]? aSalt = null;


        long plaintextLength;
        long expectedChunkCount;


        try
        {
            if (input.Length >
                maxFileSize)
                throw new CryptographicException(
                    "Encrypted file exceeds maximum size.");


            //-----------------------------------------------------
            // READ HEADER
            //-----------------------------------------------------

            var header = new byte[headerSize];


            var headerMac = new byte[hmacSize];


            await input.ReadExactlyAsync(
                header,
                ct);


            await input.ReadExactlyAsync(
                headerMac,
                ct);


            //-----------------------------------------------------
            // VERIFY HEADER MAC
            //-----------------------------------------------------

            using (var hmac =
                   new HMACSHA3_512(
                       keys.HeaderHmacKey))
            {
                var computed =
                    hmac.ComputeHash(
                        header);


                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(
                            computed,
                            headerMac))
                        throw new CryptographicException(
                            "Header authentication failed.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        computed);
                }
            }

            var payloadStart =
                input.Position;

            //-----------------------------------------------------
            // PARSE HEADER
            //-----------------------------------------------------

            var offset = 0;


            var version =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    header.AsSpan(
                        offset,
                        2));


            offset += 2;


            if (version != formatVersion)
                throw new CryptographicException(
                    $"Unsupported format version {version}");


            var reserved =
                BinaryPrimitives.ReadUInt64LittleEndian(
                    header.AsSpan(
                        offset,
                        8));


            offset += 8;


            if (reserved != ulong.MaxValue)
                throw new CryptographicException(
                    "Invalid header reserved field.");


            xNonce =
                header.AsSpan(
                        offset,
                        16)
                    .ToArray();


            offset += 16;


            tNonce =
                header.AsSpan(
                        offset,
                        8)
                    .ToArray();


            offset += 8;


            sNonce =
                header.AsSpan(
                        offset,
                        8)
                    .ToArray();


            offset += 8;


            aNonce =
                header.AsSpan(
                        offset,
                        8)
                    .ToArray();


            offset += 8;


            xSalt =
                header.AsSpan(
                        offset,
                        128)
                    .ToArray();


            offset += 128;


            tSalt =
                header.AsSpan(
                        offset,
                        128)
                    .ToArray();


            offset += 128;


            sSalt =
                header.AsSpan(
                        offset,
                        128)
                    .ToArray();


            offset += 128;


            aSalt =
                header.AsSpan(
                        offset,
                        128)
                    .ToArray();


            offset += 128;


            plaintextLength =
                BinaryPrimitives.ReadInt64LittleEndian(
                    header.AsSpan(
                        offset,
                        8));


            offset += 8;


            expectedChunkCount =
                BinaryPrimitives.ReadInt64LittleEndian(
                    header.AsSpan(
                        offset,
                        8));


            offset += 8;


            if (plaintextLength <= 0 ||
                plaintextLength > maxFileSize)
                throw new CryptographicException(
                    "Invalid plaintext length.");


            var calculatedChunks =
                (plaintextLength +
                 chunkSize -
                 1) /
                chunkSize;


            if (expectedChunkCount != calculatedChunks)
                throw new CryptographicException(
                    "Chunk count mismatch.");

            // =====================================================
            // LOCATE PAYLOAD AND READ FINAL TAGS
            // =====================================================

            long trailingTags =
                hmacSize * 3;

            if (input.Length <
                payloadStart + trailingTags)
                throw new CryptographicException(
                    "Encrypted file truncated.");


            var payloadEnd =
                input.Length -
                trailingTags;


            var threefishTag =
                new byte[hmacSize];


            var serpentTag =
                new byte[hmacSize];


            var aesTag =
                new byte[hmacSize];


            input.Seek(
                -trailingTags,
                SeekOrigin.End);


            await input.ReadExactlyAsync(
                threefishTag,
                ct);


            await input.ReadExactlyAsync(
                serpentTag,
                ct);


            await input.ReadExactlyAsync(
                aesTag,
                ct);


            input.Seek(
                payloadStart,
                SeekOrigin.Begin);

            // =====================================================
            // CHANNEL CREATION
            // =====================================================

            Channel<CryptoChunk> CreateChannel()
            {
                return Channel.CreateBounded<CryptoChunk>(
                    new BoundedChannelOptions(
                        opt.ChannelCapacity)
                    {
                        FullMode =
                            BoundedChannelFullMode.Wait,

                        SingleReader = false,
                        SingleWriter = false,

                        AllowSynchronousContinuations = false
                    });
            }


            var c0 =
                CreateChannel();

            var c1 =
                CreateChannel();

            var c2 =
                CreateChannel();

            var c3 =
                CreateChannel();

            var c4 =
                CreateChannel();


            Logging.Logging.Log(
                "====================================================");

            Logging.Logging.Log(
                "DECRYPT PIPELINE CREATED");

            Logging.Logging.Log(
                "Reader -> XChaCha -> AES -> Serpent -> Threefish -> Writer");

            Logging.Logging.Log(
                "====================================================");


            // =====================================================
            // READER STAGE
            // =====================================================

            async Task ReaderStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                long index = 0;
                long bytesRead = 0;
                long byteOffset = 0;


                var chunkHeader =
                    new byte[24];


                try
                {
                    while (input.Position < payloadEnd)
                    {
                        ct.ThrowIfCancellationRequested();


                        var chunkOffset =
                            input.Position;

                        await input.ReadExactlyAsync(
                            chunkHeader,
                            ct);


                        var rawIndex =
                            BinaryPrimitives.ReadUInt64LittleEndian(
                                chunkHeader.AsSpan(0, 8));

                        var lengthRaw =
                            BinaryPrimitives.ReadUInt64LittleEndian(
                                chunkHeader.AsSpan(8, 8));

                        var reserved =
                            BinaryPrimitives.ReadUInt64LittleEndian(
                                chunkHeader.AsSpan(16, 8));


                        if (reserved != 0)
                            throw new CryptographicException(
                                $"Invalid chunk reserved field. " +
                                $"Index={rawIndex}");


                        if (rawIndex !=
                            unchecked((ulong)index))
                            throw new CryptographicException(
                                $"Chunk ordering error. " +
                                $"Expected={index} " +
                                $"Actual={rawIndex}");


                        if (lengthRaw == 0 ||
                            lengthRaw > chunkSize)
                            throw new CryptographicException(
                                $"Invalid chunk size. " +
                                $"Length={lengthRaw}");


                        var length =
                            checked(
                                (int)lengthRaw);


                        if (input.Position +
                            length +
                            aeadTagSize >
                            payloadEnd)
                            throw new CryptographicException(
                                "Chunk exceeds payload boundary.");


                        var buffer =
                            ArrayPool<byte>.Shared.Rent(
                                chunkSize);


                        var tag =
                            new byte[aeadTagSize];


                        var transferred =
                            false;


                        try
                        {
                            await input.ReadExactlyAsync(
                                buffer.AsMemory(
                                    0,
                                    length),
                                ct);


                            await input.ReadExactlyAsync(
                                tag,
                                ct);


                            var chunk =
                                new CryptoChunk
                                {
                                    Index =
                                        (long)rawIndex,

                                    ByteOffset =
                                        byteOffset,

                                    Buffer =
                                        buffer,

                                    Length =
                                        length,

                                    BufferPooled =
                                        true,

                                    AeadTag =
                                        tag,

                                    AeadCounter =
                                        rawIndex
                                };


                            await c0.Writer.WriteAsync(
                                chunk,
                                ct);


                            transferred = true;


                            index++;

                            bytesRead += length;

                            byteOffset += length;
                        }
                        finally
                        {
                            if (!transferred)
                            {
                                CryptographicOperations.ZeroMemory(
                                    buffer.AsSpan(
                                        0,
                                        Math.Min(
                                            length,
                                            buffer.Length)));


                                ArrayPool<byte>.Shared.Return(
                                    buffer,
                                    true);


                                CryptographicOperations.ZeroMemory(
                                    tag);
                            }
                        }
                    }


                    if (index != expectedChunkCount)
                        throw new CryptographicException(
                            $"Reader chunk mismatch. " +
                            $"Expected={expectedChunkCount} " +
                            $"Actual={index}");


                    if (bytesRead != plaintextLength)
                        throw new CryptographicException(
                            $"Reader byte mismatch. " +
                            $"Expected={plaintextLength} " +
                            $"Actual={bytesRead}");


                    if (input.Position != payloadEnd)
                        throw new CryptographicException(
                            "Payload alignment failure.");


                    Logging.Logging.Log(
                        $"[READER] COMPLETE " +
                        $"Chunks={index:N0} " +
                        $"Bytes={bytesRead:N0} " +
                        $"Elapsed={timer.Elapsed}");
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        chunkHeader);


                    c0.Writer.TryComplete(
                        pipelineFailure);
                }
            }

            // =====================================================
            // XCHACHA DECRYPT STAGE
            // =====================================================

            var xchachaSalt = xSalt;

            async Task XChaChaStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                try
                {
                    await XChaChaDecryptStage(
                        c0.Reader,
                        c1.Writer,
                        keys.XChaChaKey,
                        xNonce,
                        xchachaSalt,
                        "XCHACHA20-POLY1305",
                        24,
                        ct,
                        opt.XChaChaWorkers,
                        opt.ChannelCapacity,
                        expectedChunkCount);
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    c1.Writer.TryComplete(
                        pipelineFailure);
                }
            }

            // =====================================================
            // AES DECRYPT STAGE
            // =====================================================

            var aesSalt = aSalt;

            var expectedAesTag = aesTag;

            async Task AesStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                try
                {
                    await CtrDecrypt(
                        c1.Reader,
                        c2.Writer,
                        keys.AesKey,
                        keys.AesHmacKey,
                        expectedAesTag,
                        () =>
                            new AesEngine(),
                        aNonce,
                        aesSalt,
                        16,
                        "AES-256",
                        opt.AesWorkers,
                        opt.ChannelCapacity,
                        expectedChunkCount,
                        null,
                        ct);


                    Logging.Logging.Log(
                        $"[AES] COMPLETE " +
                        $"Elapsed={timer.Elapsed}");
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    c2.Writer.TryComplete(
                        pipelineFailure);


                    Logging.Logging.Log(
                        "[AES] EXIT");
                }
            }


            // =====================================================
            // SERPENT DECRYPT STAGE
            // =====================================================

            var serpentSalt = sSalt;

            var expectedSerpentTag = serpentTag;

            async Task SerpentStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                try
                {
                    await CtrDecrypt(
                        c2.Reader,
                        c3.Writer,
                        keys.SerpentKey,
                        keys.SerpentHmacKey,
                        expectedSerpentTag,
                        () =>
                            new SerpentEngine(),
                        sNonce,
                        serpentSalt,
                        16,
                        "SERPENT-256",
                        opt.SerpentWorkers,
                        opt.ChannelCapacity,
                        expectedChunkCount,
                        null,
                        ct);
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    c3.Writer.TryComplete(
                        pipelineFailure);
                }
            }


            // =====================================================
            // THREEFISH DECRYPT STAGE
            // =====================================================

            var threefishSalt = tSalt;

            var expectedThreefishTag = threefishTag;

            async Task ThreefishStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                try
                {
                    await CtrDecrypt(
                        c3.Reader,
                        c4.Writer,
                        keys.ThreefishKey,
                        keys.ThreefishHmacKey,
                        expectedThreefishTag,
                        () =>
                            new ThreefishEngine(
                                1024),
                        tNonce,
                        threefishSalt,
                        128,
                        "THREEFISH-1024",
                        opt.ThreefishWorkers,
                        opt.ChannelCapacity,
                        expectedChunkCount,
                        null,
                        ct);
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    c4.Writer.TryComplete(
                        pipelineFailure);
                }
            }

            // =====================================================
            // START CRYPTO PIPELINE
            // =====================================================

            var reader =
                ReaderStageAsync();


            var xchacha =
                XChaChaStageAsync();


            var aes =
                AesStageAsync();


            var serpent =
                SerpentStageAsync();


            var threefish =
                ThreefishStageAsync();


            // =====================================================
            // WRITER STAGE
            // =====================================================

            async Task WriterStageAsync()
            {
                var timer =
                    Stopwatch.StartNew();


                long writtenChunks = 0;
                long writtenBytes = 0;

                long nextIndex = 0;


                using var reorder =
                    new ReorderBuffer(
                        0,
                        512L * 1024 * 1024,
                        opt.ThreefishWorkers * 128,
                        8192);


                async Task WriteChunkAsync(
                    CryptoChunk chunk)
                {
                    try
                    {
                        if (chunk.Buffer == null)
                            throw new CryptographicException(
                                $"Writer received null buffer. " +
                                $"Index={chunk.Index}");


                        if (chunk.Length <= 0 ||
                            chunk.Length > chunk.Buffer.Length)
                            throw new CryptographicException(
                                $"Invalid chunk length. " +
                                $"Index={chunk.Index}");


                        if (chunk.Index != nextIndex)
                            throw new CryptographicException(
                                $"Writer ordering violation. " +
                                $"Expected={nextIndex} " +
                                $"Actual={chunk.Index}");


                        await output.WriteAsync(
                            chunk.Buffer.AsMemory(
                                0,
                                chunk.Length),
                            ct);


                        nextIndex++;

                        writtenChunks++;

                        writtenBytes += chunk.Length;
                    }
                    finally
                    {
                        CleanupChunk(
                            chunk);
                    }
                }


                try
                {
                    await foreach (var chunk in
                                   c4.Reader.ReadAllAsync(ct))
                    {
                        ct.ThrowIfCancellationRequested();


                        try
                        {
                            reorder.Add(
                                chunk);
                        }
                        catch
                        {
                            CleanupChunk(
                                chunk);

                            throw;
                        }


                        while (reorder.TryGetNext(
                                   out var ready))
                            if (ready != null)
                                await WriteChunkAsync(
                                    ready);
                    }


                    while (reorder.TryGetNext(
                               out var ready))
                        if (ready != null)
                            await WriteChunkAsync(
                                ready);


                    if (reorder.PendingCount != 0)
                        throw new CryptographicException(
                            $"Writer reorder incomplete. " +
                            $"Pending={reorder.PendingCount}");


                    if (writtenChunks != expectedChunkCount)
                        throw new CryptographicException(
                            $"Writer chunk count mismatch. " +
                            $"Expected={expectedChunkCount} " +
                            $"Actual={writtenChunks}");


                    if (writtenBytes != plaintextLength)
                        throw new CryptographicException(
                            $"Writer byte mismatch. " +
                            $"Expected={plaintextLength} " +
                            $"Actual={writtenBytes}");


                    await output.FlushAsync(
                        ct);
                }
                catch (Exception ex)
                {
                    Fail(ex);

                    throw;
                }
                finally
                {
                    foreach (var leftover in
                             reorder.DrainPending())
                        CleanupChunk(
                            leftover);
                }
            }


            var writer =
                WriterStageAsync();


            // =====================================================
            // WAIT FOR PIPELINE
            // =====================================================

            var success =
                false;


            try
            {
                await Task.WhenAll(
                    reader,
                    xchacha,
                    aes,
                    serpent,
                    threefish,
                    writer);


                success =
                    true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Fail(ex);

                throw new CryptographicException(
                    "Decryption pipeline failed.",
                    ex);
            }
            finally
            {
                pipelineCts.Cancel();


                c0.Writer.TryComplete(
                    pipelineFailure);

                c1.Writer.TryComplete(
                    pipelineFailure);

                c2.Writer.TryComplete(
                    pipelineFailure);

                c3.Writer.TryComplete(
                    pipelineFailure);

                c4.Writer.TryComplete(
                    pipelineFailure);


                try
                {
                    await Task.WhenAll(
                            reader,
                            xchacha,
                            aes,
                            serpent,
                            threefish,
                            writer)
                        .WaitAsync(
                            TimeSpan.FromMinutes(5), ct);
                }
                catch
                {
                    Logging.Logging.Log(
                        "Pipeline shutdown timeout.");
                }


                static void Zero(
                    ref byte[]? data)
                {
                    if (data == null)
                        return;


                    CryptographicOperations.ZeroMemory(
                        data);


                    data = null;
                }


                Zero(
                    ref header);

                Zero(
                    ref headerMac);


                Zero(
                    ref xNonce);

                Zero(
                    ref tNonce);

                Zero(
                    ref sNonce);

                Zero(
                    ref aNonce);


                Zero(
                    ref xSalt);

                Zero(
                    ref tSalt);

                Zero(
                    ref sSalt);

                Zero(
                    ref aSalt);


                Zero(
                    ref threefishTag);

                Zero(
                    ref serpentTag);

                Zero(
                    ref aesTag);


                while (c0.Reader.TryRead(
                           out var c0Chunk))
                    CleanupChunk(
                        c0Chunk);


                while (c1.Reader.TryRead(
                           out var c1Chunk))
                    CleanupChunk(
                        c1Chunk);


                while (c2.Reader.TryRead(
                           out var c2Chunk))
                    CleanupChunk(
                        c2Chunk);


                while (c3.Reader.TryRead(
                           out var c3Chunk))
                    CleanupChunk(
                        c3Chunk);


                while (c4.Reader.TryRead(
                           out var c4Chunk))
                    CleanupChunk(
                        c4Chunk);


                totalTimer.Stop();
            }
        }
        catch (Exception ex)
        {
            Fail(ex);
            throw;
        }
    }

    private static byte[] BuildAad(ulong ctr, int length)
    {
        var aad = new byte[12];

        BinaryPrimitives.WriteUInt64LittleEndian(aad.AsSpan(0, 8), ctr);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(8, 4), length);

        return aad;
    }

    public static async Task XChaChaEncryptStage(
        ChannelReader<CryptoChunk> input,
        ChannelWriter<CryptoChunk> output,
        byte[] key,
        byte[] baseNonce,
        byte[] nonceSalt,
        string layer,
        int nonceLength,
        int workerCount,
        int capacity,
        long expectedChunkCount,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(baseNonce);
        ArgumentNullException.ThrowIfNull(nonceSalt);

        ArgumentException.ThrowIfNullOrWhiteSpace(layer);


        if (workerCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(workerCount));


        if (nonceLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(nonceLength));


        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(capacity));

        if (expectedChunkCount < 0)
            throw new ArgumentOutOfRangeException(
                nameof(expectedChunkCount));

        Console.WriteLine(
            $"[{layer}] XChaCha Encrypt START " +
            $"Workers={workerCount} " +
            $"Capacity={capacity}");


        using var linked =
            CancellationTokenSource.CreateLinkedTokenSource(ct);


        var token =
            linked.Token;

        //---------------------------------------------------------
        // Internal channels
        //---------------------------------------------------------

        var workChannel =
            Channel.CreateBounded<CryptoChunk>(
                new BoundedChannelOptions(capacity)
                {
                    FullMode =
                        BoundedChannelFullMode.Wait,

                    SingleWriter = true,

                    SingleReader = false,

                    AllowSynchronousContinuations = false
                });


        var completedChannel =
            Channel.CreateBounded<CryptoChunk>(
                new BoundedChannelOptions(capacity)
                {
                    FullMode =
                        BoundedChannelFullMode.Wait,

                    SingleWriter = false,

                    SingleReader = true,

                    AllowSynchronousContinuations = false
                });

        using var reorder =
            new ReorderBuffer(
                0,
                512L * 1024 * 1024,
                workerCount * 256,
                8192);

        Exception? failure = null;

        var failed = 0;

        void Fail(Exception ex)
        {
            if (ex is OperationCanceledException)
                return;


            if (Interlocked.Exchange(
                    ref failed,
                    1) != 0)
                return;


            Volatile.Write(
                ref failure,
                ex);


            Console.WriteLine(
                $"[{layer}] FAILURE");

            Console.WriteLine(
                ex);


            linked.Cancel();


            workChannel.Writer.TryComplete(ex);

            completedChannel.Writer.TryComplete(ex);


            reorder.Abort(ex);
        }

        //---------------------------------------------------------
        // Dispatcher
        //---------------------------------------------------------

        async Task Dispatcher()
        {
            long count = 0;
            long bytes = 0;


            try
            {
                await foreach (var chunk in
                               input.ReadAllAsync(token))
                {
                    token.ThrowIfCancellationRequested();


                    if (chunk.Buffer == null)
                        throw new CryptographicException(
                            $"{layer}: Missing input buffer.");


                    if (chunk.Length <= 0 ||
                        chunk.Length > chunk.Buffer.Length)
                        throw new CryptographicException(
                            $"{layer}: Invalid chunk length.");


                    await workChannel.Writer.WriteAsync(
                        chunk,
                        token);


                    count++;
                    bytes += chunk.Length;


                    if ((count & 8191) == 0)
                        Console.WriteLine(
                            $"[{layer}] DISPATCH " +
                            $"Chunks={count:N0} " +
                            $"Bytes={bytes:N0}");
                }


                workChannel.Writer.TryComplete();


                Console.WriteLine(
                    $"[{layer}] DISPATCH COMPLETE " +
                    $"Chunks={count:N0} " +
                    $"Bytes={bytes:N0}");
            }
            catch (Exception ex)
            {
                Fail(ex);

                workChannel.Writer.TryComplete(
                    ex);

                throw;
            }
        }

        //---------------------------------------------------------
        // Worker
        //---------------------------------------------------------

        async Task Worker(
            int workerId)
        {
            long processed = 0;
            long bytes = 0;


            Console.WriteLine(
                $"[{layer}] Worker {workerId} START");


            var nonce =
                new byte[nonceLength];


            try
            {
                await foreach (var chunk in
                               workChannel.Reader.ReadAllAsync(token))
                {
                    byte[]? fullCipher = null;
                    byte[]? cipherBuffer = null;
                    byte[]? tag = null;
                    byte[]? aad = null;


                    var transferred = false;


                    try
                    {
                        token.ThrowIfCancellationRequested();


                        if (chunk.Buffer == null)
                            throw new CryptographicException(
                                $"{layer}: Missing input buffer.");


                        if (chunk.Length <= 0 ||
                            chunk.Length > chunk.Buffer.Length)
                            throw new CryptographicException(
                                $"{layer}: Invalid input length.");

                        if (chunk.Index < 0 ||
                            chunk.Index == long.MaxValue)
                            throw new CryptographicException(
                                $"{layer}: Invalid chunk index.");


                        //-------------------------------------------------
                        // Derive nonce
                        //-------------------------------------------------

                        DeriveNonce(
                            baseNonce,
                            nonceSalt,
                            layer,
                            chunk.Index,
                            nonce);


                        //-------------------------------------------------
                        // Build AAD
                        //-------------------------------------------------

                        aad =
                            BuildAad(
                                unchecked((ulong)chunk.Index),
                                chunk.Length);


                        //-------------------------------------------------
                        // Encrypt
                        //-------------------------------------------------

                        fullCipher =
                            SecretAeadXChaCha20Poly1305.Encrypt(
                                chunk.Buffer.AsSpan(0, chunk.Length).ToArray(),
                                nonce,
                                key,
                                aad);


                        const int TAG_SIZE = 16;


                        if (fullCipher.Length < TAG_SIZE)
                            throw new CryptographicException(
                                $"{layer}: Invalid AEAD output.");


                        var cipherLength =
                            fullCipher.Length - TAG_SIZE;


                        //-------------------------------------------------
                        // Split ciphertext and tag
                        //-------------------------------------------------

                        cipherBuffer =
                            ArrayPool<byte>.Shared.Rent(
                                cipherLength);


                        Buffer.BlockCopy(
                            fullCipher,
                            0,
                            cipherBuffer,
                            0,
                            cipherLength);


                        tag =
                            new byte[TAG_SIZE];


                        Buffer.BlockCopy(
                            fullCipher,
                            cipherLength,
                            tag,
                            0,
                            TAG_SIZE);


                        //-------------------------------------------------
                        // Create output chunk
                        //-------------------------------------------------

                        var encrypted =
                            new CryptoChunk
                            {
                                Index =
                                    chunk.Index,

                                ByteOffset =
                                    chunk.ByteOffset,

                                Buffer =
                                    cipherBuffer,

                                Length =
                                    cipherLength,

                                BufferPooled =
                                    true,

                                AeadCounter =
                                    unchecked(
                                        (ulong)chunk.Index),

                                AeadTag =
                                    tag
                            };


                        //
                        // Ownership moves to completed channel
                        //

                        await completedChannel.Writer.WriteAsync(
                            encrypted,
                            token);


                        transferred = true;


                        cipherBuffer = null;
                        tag = null;


                        processed++;

                        bytes += cipherLength;


                        if ((processed & 8191) == 0)
                            Console.WriteLine(
                                $"[{layer}] Worker {workerId} " +
                                $"Chunks={processed:N0} " +
                                $"Bytes={bytes:N0}");
                    }
                    finally
                    {
                        //-------------------------------------------------
                        // Cleanup temporary crypto material
                        //-------------------------------------------------

                        if (aad != null)
                            CryptographicOperations.ZeroMemory(
                                aad);


                        if (fullCipher != null)
                            CryptographicOperations.ZeroMemory(
                                fullCipher);

                        //-------------------------------------------------
                        // Release input buffer
                        //-------------------------------------------------

                        CleanupBuffer(
                            ref chunk.Buffer,
                            chunk.Length,
                            chunk.BufferPooled);


                        //-------------------------------------------------
                        // Failed output cleanup
                        //-------------------------------------------------

                        if (!transferred)
                        {
                            if (cipherBuffer != null)
                            {
                                CryptographicOperations.ZeroMemory(
                                    cipherBuffer.AsSpan(
                                        0,
                                        Math.Min(
                                            chunk.Length,
                                            cipherBuffer.Length)));


                                ArrayPool<byte>.Shared.Return(
                                    cipherBuffer,
                                    true);
                            }


                            if (tag != null)
                                CryptographicOperations.ZeroMemory(
                                    tag);
                        }
                    }
                }


                Console.WriteLine(
                    $"[{layer}] Worker {workerId} COMPLETE " +
                    $"Chunks={processed:N0} " +
                    $"Bytes={bytes:N0}");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Fail(ex);

                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    nonce);


                Console.WriteLine(
                    $"[{layer}] Worker {workerId} EXIT");
            }
        }

        //---------------------------------------------------------
        // START WORKERS
        //---------------------------------------------------------

        var workers =
            Enumerable.Range(
                    0,
                    workerCount)
                .Select(Worker)
                .ToArray();


        //---------------------------------------------------------
        // WORKER COMPLETION MONITOR
        //---------------------------------------------------------

        var workersCompletion =
            Task.Run(async () =>
                {
                    Exception? workerFailure = null;


                    try
                    {
                        await Task.WhenAll(
                            workers);
                    }
                    catch (Exception ex)
                    {
                        workerFailure = ex;

                        Fail(ex);
                    }
                    finally
                    {
                        completedChannel.Writer.TryComplete(
                            workerFailure ??
                            Volatile.Read(
                                ref failure));


                        Console.WriteLine(
                            $"[{layer}] ALL WORKERS COMPLETE");
                    }
                },
                CancellationToken.None);


        //---------------------------------------------------------
        // OUTPUT FORWARDER
        //---------------------------------------------------------

        async Task OutputForwarder()
        {
            long count = 0;
            long bytes = 0;


            var timer =
                Stopwatch.StartNew();


            try
            {
                await foreach (var chunk in
                               completedChannel.Reader.ReadAllAsync(token))
                {
                    token.ThrowIfCancellationRequested();


                    if (chunk.Buffer == null)
                        throw new CryptographicException(
                            $"{layer}: Missing output buffer.");


                    reorder.Add(chunk);


                    while (reorder.TryGetNext(
                               out var ready))
                    {
                        if (ready == null)
                            continue;


                        await output.WriteAsync(
                            ready,
                            token);


                        count++;

                        bytes += ready.Length;


                        if ((count & 8191) == 0)
                            Console.WriteLine(
                                $"[{layer}] OUTPUT " +
                                $"Chunks={count:N0} " +
                                $"Bytes={bytes:N0} " +
                                $"Pending={reorder.PendingCount:N0} " +
                                $"Elapsed={timer.Elapsed}");
                    }
                }


                //
                // Drain chunks that arrived after channel completion
                //
                while (reorder.TryGetNext(
                           out var ready))
                {
                    if (ready == null)
                        continue;


                    await output.WriteAsync(
                        ready,
                        token);


                    count++;
                    bytes += ready.Length;
                }


                reorder.Complete();


                if (reorder.PendingCount != 0)
                    throw new CryptographicException(
                        $"{layer}: Reorder incomplete. " +
                        $"Pending={reorder.PendingCount}");


                if (expectedChunkCount == 0)
                {
                    if (reorder.NextExpected != 0)
                        throw new CryptographicException(
                            $"{layer}: Unexpected chunks for empty stream.");
                }
                else
                {
                    if (reorder.NextExpected != expectedChunkCount)
                        throw new CryptographicException(
                            $"{layer}: Chunk count mismatch. " +
                            $"Expected={expectedChunkCount:N0} " +
                            $"Processed={reorder.NextExpected:N0}");
                }


                Console.WriteLine(
                    $"[{layer}] OUTPUT COMPLETE " +
                    $"Chunks={count:N0} " +
                    $"Bytes={bytes:N0}");
            }
            catch (Exception ex)
            {
                Fail(ex);
                throw;
            }
        }


        //---------------------------------------------------------
        // RUN STAGE
        //---------------------------------------------------------

        try
        {
            await Task.WhenAll(
                Dispatcher(),
                workersCompletion,
                OutputForwarder());


            var stageFailure =
                Volatile.Read(
                    ref failure);


            if (stageFailure != null)
                throw new CryptographicException(
                    $"{layer}: XChaCha stage failed.",
                    stageFailure);


            Console.WriteLine(
                $"[{layer}] XChaCha Encrypt SUCCESS");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Fail(ex);

            throw;
        }
        finally
        {
            linked.Cancel();

            try
            {
                await workersCompletion;
            }
            catch
            {
                // failure already captured
            }

            //
            // Cleanup unfinished work items
            //
            //
            // Cleanup unfinished work items
            //
            while (workChannel.Reader.TryRead(
                       out var leftover))
            {
                CleanupBuffer(
                    ref leftover.Buffer,
                    leftover.Length,
                    leftover.BufferPooled);


                if (leftover.AeadTag != null)
                {
                    CryptographicOperations.ZeroMemory(
                        leftover.AeadTag);

                    leftover.AeadTag = null;
                }
            }

            //
            // Cleanup unfinished completed items
            //
            while (completedChannel.Reader.TryRead(
                       out var leftover))
            {
                CleanupBuffer(
                    ref leftover.Buffer,
                    leftover.Length,
                    leftover.BufferPooled);


                if (leftover.AeadTag != null)
                {
                    CryptographicOperations.ZeroMemory(
                        leftover.AeadTag);

                    leftover.AeadTag = null;
                }
            }


            //
            // Cleanup reorder buffer
            //
            foreach (var chunk in reorder.DrainPending())
                try
                {
                    CleanupBuffer(
                        ref chunk.Buffer,
                        chunk.Length,
                        chunk.BufferPooled);


                    if (chunk.AeadTag != null)
                    {
                        CryptographicOperations.ZeroMemory(
                            chunk.AeadTag);

                        chunk.AeadTag = null;
                    }
                }
                catch
                {
                }


            reorder.Dispose();


            output.TryComplete(
                failure);


            Console.WriteLine(
                $"[{layer}] XChaCha Encrypt EXIT");
        }
    }

    public static async Task XChaChaDecryptStage(
        ChannelReader<CryptoChunk> input,
        ChannelWriter<CryptoChunk> output,
        byte[] key,
        byte[] baseNonce,
        byte[] nonceSalt,
        string layer,
        int nonceLength,
        CancellationToken ct,
        int workerCount,
        int capacity,
        long expectedChunkCount)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(baseNonce);
        ArgumentNullException.ThrowIfNull(nonceSalt);

        ArgumentException.ThrowIfNullOrWhiteSpace(layer);


        if (workerCount <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(workerCount));

        if (nonceLength <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(nonceLength));

        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(capacity));

        if (expectedChunkCount < 0)
            throw new ArgumentOutOfRangeException(
                nameof(expectedChunkCount));


        Logging.Logging.Log(
            $"[{layer}] XChaCha Decrypt START " +
            $"Workers={workerCount} " +
            $"Capacity={capacity}");


        using var linked =
            CancellationTokenSource.CreateLinkedTokenSource(ct);


        var token =
            linked.Token;


        //---------------------------------------------------------
        // Internal channels
        //---------------------------------------------------------

        var workChannel =
            Channel.CreateBounded<CryptoChunk>(
                new BoundedChannelOptions(capacity)
                {
                    FullMode =
                        BoundedChannelFullMode.Wait,

                    SingleWriter = true,

                    SingleReader = false,

                    AllowSynchronousContinuations = false
                });


        var completedChannel =
            Channel.CreateBounded<CryptoChunk>(
                new BoundedChannelOptions(capacity)
                {
                    FullMode =
                        BoundedChannelFullMode.Wait,

                    SingleWriter = false,

                    SingleReader = true,

                    AllowSynchronousContinuations = false
                });


        using var reorder =
            new ReorderBuffer(
                0,
                512L * 1024 * 1024,
                workerCount * 256,
                8192);


        Exception? failure = null;

        var failed = 0;


        void Fail(Exception ex)
        {
            if (ex is OperationCanceledException)
                return;


            if (Interlocked.Exchange(
                    ref failed,
                    1) != 0)
                return;


            Volatile.Write(
                ref failure,
                ex);


            Logging.Logging.Log(
                $"[{layer}] FAILURE");

            Logging.Logging.Log(
                ex.ToString());

            workChannel.Writer.TryComplete(ex);

            completedChannel.Writer.TryComplete(ex);


            reorder.Abort(ex);
        }


        //---------------------------------------------------------
        // Dispatcher
        //---------------------------------------------------------

        async Task DispatcherAsync()
        {
            long count = 0;
            long bytes = 0;


            try
            {
                await foreach (var chunk in
                               input.ReadAllAsync(token))
                {
                    token.ThrowIfCancellationRequested();


                    if (chunk.Buffer == null)
                        throw new CryptographicException(
                            $"{layer}: Missing ciphertext buffer.");


                    if (chunk.Length <= 0 ||
                        chunk.Length > chunk.Buffer.Length)
                        throw new CryptographicException(
                            $"{layer}: Invalid ciphertext length.");


                    await workChannel.Writer.WriteAsync(
                        chunk,
                        token);


                    count++;
                    bytes += chunk.Length;


                    if ((count & 8191) == 0)
                        Logging.Logging.Log(
                            $"[{layer}] DISPATCH " +
                            $"Chunks={count:N0} " +
                            $"Bytes={bytes:N0}");
                }


                workChannel.Writer.TryComplete();


                Logging.Logging.Log(
                    $"[{layer}] DISPATCH COMPLETE " +
                    $"Chunks={count:N0} " +
                    $"Bytes={bytes:N0}");
            }
            catch (Exception ex)
            {
                Fail(ex);

                workChannel.Writer.TryComplete(ex);

                throw;
            }
        }

        //---------------------------------------------------------
        // Worker
        //---------------------------------------------------------

        async Task WorkerAsync(
            int workerId)
        {
            long processed = 0;
            long bytes = 0;


            Logging.Logging.Log(
                $"[{layer}] Worker {workerId} START");


            var nonce =
                new byte[nonceLength];


            try
            {
                await foreach (var chunk in
                               workChannel.Reader.ReadAllAsync(token))
                {
                    byte[]? plaintext = null;

                    byte[]? combined = null;

                    byte[]? aad = null;


                    var transferred = false;


                    const int TAG_SIZE = 16;


                    var combinedLength = 0;


                    try
                    {
                        token.ThrowIfCancellationRequested();


                        //-------------------------------------------------
                        // Validate input chunk
                        //-------------------------------------------------

                        if (chunk.Buffer == null)
                            throw new CryptographicException(
                                $"{layer}: Missing ciphertext buffer.");


                        if (chunk.Length <= 0 ||
                            chunk.Length > chunk.Buffer.Length)
                            throw new CryptographicException(
                                $"{layer}: Invalid ciphertext length.");


                        if (chunk.AeadTag == null ||
                            chunk.AeadTag.Length != TAG_SIZE)
                            throw new CryptographicException(
                                $"{layer}: Invalid AEAD tag.");


                        if (chunk.Index < 0 ||
                            chunk.Index == long.MaxValue)
                            throw new CryptographicException(
                                $"{layer}: Invalid chunk index.");


                        if (chunk.AeadCounter !=
                            unchecked((ulong)chunk.Index))
                            throw new CryptographicException(
                                $"{layer}: AEAD counter mismatch.");


                        //-------------------------------------------------
                        // Rebuild ciphertext + tag
                        //-------------------------------------------------

                        combinedLength =
                            checked(
                                chunk.Length + TAG_SIZE);


                        combined =
                            ArrayPool<byte>.Shared.Rent(
                                combinedLength);


                        Buffer.BlockCopy(
                            chunk.Buffer,
                            0,
                            combined,
                            0,
                            chunk.Length);


                        Buffer.BlockCopy(
                            chunk.AeadTag,
                            0,
                            combined,
                            chunk.Length,
                            TAG_SIZE);


                        //-------------------------------------------------
                        // Derive nonce
                        //-------------------------------------------------

                        DeriveNonce(
                            baseNonce,
                            nonceSalt,
                            layer,
                            chunk.Index,
                            nonce);


                        //-------------------------------------------------
                        // Build AAD
                        //-------------------------------------------------

                        aad =
                            BuildAad(
                                unchecked((ulong)chunk.Index),
                                chunk.Length);


                        //-------------------------------------------------
                        // Decrypt
                        //-------------------------------------------------

                        plaintext =
                            SecretAeadXChaCha20Poly1305.Decrypt(
                                combined.AsSpan(
                                        0,
                                        combinedLength)
                                    .ToArray(),
                                nonce,
                                key,
                                aad);


                        //-------------------------------------------------
                        // Create decrypted chunk
                        //-------------------------------------------------

                        var decrypted =
                            new CryptoChunk
                            {
                                Index =
                                    chunk.Index,


                                ByteOffset =
                                    chunk.ByteOffset,


                                Buffer =
                                    plaintext,


                                Length =
                                    plaintext.Length,


                                BufferPooled =
                                    false,


                                AeadCounter =
                                    chunk.AeadCounter
                            };


                        //-------------------------------------------------
                        // Transfer ownership
                        //-------------------------------------------------

                        await completedChannel.Writer.WriteAsync(
                            decrypted,
                            token);


                        transferred = true;


                        plaintext = null;


                        processed++;

                        bytes += decrypted.Length;


                        if ((processed & 8191) == 0)
                            Logging.Logging.Log(
                                $"[{layer}] Worker {workerId} " +
                                $"Chunks={processed:N0} " +
                                $"Bytes={bytes:N0}");
                    }
                    finally
                    {
                        //-------------------------------------------------
                        // Cleanup AAD
                        //-------------------------------------------------

                        if (aad != null)
                            CryptographicOperations.ZeroMemory(
                                aad);


                        //-------------------------------------------------
                        // Cleanup pooled combined buffer
                        //-------------------------------------------------

                        if (combined != null)
                        {
                            CryptographicOperations.ZeroMemory(
                                combined.AsSpan(
                                    0,
                                    Math.Min(
                                        combinedLength,
                                        combined.Length)));


                            ArrayPool<byte>.Shared.Return(
                                combined,
                                true);
                        }


                        //-------------------------------------------------
                        // Cleanup input ciphertext
                        //-------------------------------------------------

                        CleanupBuffer(
                            ref chunk.Buffer,
                            chunk.Length,
                            chunk.BufferPooled);


                        //-------------------------------------------------
                        // Cleanup authentication tag
                        //-------------------------------------------------

                        if (chunk.AeadTag != null)
                        {
                            CryptographicOperations.ZeroMemory(
                                chunk.AeadTag);


                            chunk.AeadTag = null;
                        }


                        //-------------------------------------------------
                        // Cleanup failed plaintext
                        //-------------------------------------------------

                        if (!transferred &&
                            plaintext != null)
                            CryptographicOperations.ZeroMemory(
                                plaintext);
                    }
                }


                Logging.Logging.Log(
                    $"[{layer}] Worker {workerId} COMPLETE " +
                    $"Chunks={processed:N0} " +
                    $"Bytes={bytes:N0}");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Fail(ex);

                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    nonce);


                Logging.Logging.Log(
                    $"[{layer}] Worker {workerId} EXIT");
            }
        }

        //---------------------------------------------------------
        // START WORKERS
        //---------------------------------------------------------

        var workers =
            Enumerable.Range(
                    0,
                    workerCount)
                .Select(WorkerAsync)
                .ToArray();

        //---------------------------------------------------------
        // WORKER COMPLETION MONITOR
        //---------------------------------------------------------

        var workersCompletion =
            Task.Run(async () =>
                {
                    Exception? workerFailure = null;

                    try
                    {
                        await Task.WhenAll(
                            workers);
                    }
                    catch (Exception ex)
                    {
                        workerFailure = ex;

                        Fail(ex);
                    }
                    finally
                    {
                        completedChannel.Writer.TryComplete(
                            workerFailure ??
                            Volatile.Read(
                                ref failure));


                        Logging.Logging.Log(
                            $"[{layer}] ALL WORKERS COMPLETE");
                    }
                },
                CancellationToken.None);


        //---------------------------------------------------------
        // OUTPUT FORWARDER
        //---------------------------------------------------------

        async Task OutputForwarder()
        {
            long count = 0;
            long bytes = 0;


            var timer =
                Stopwatch.StartNew();


            try
            {
                await foreach (var chunk in
                               completedChannel.Reader.ReadAllAsync(token))
                {
                    token.ThrowIfCancellationRequested();


                    if (chunk.Buffer == null)
                        throw new CryptographicException(
                            $"{layer}: Missing decrypted buffer.");


                    reorder.Add(
                        chunk);


                    while (reorder.TryGetNext(
                               out var ready))
                    {
                        if (ready == null)
                            continue;


                        await output.WriteAsync(
                            ready,
                            token);


                        count++;

                        bytes += ready.Length;


                        if ((count & 8191) == 0)
                            Logging.Logging.Log(
                                $"[{layer}] OUTPUT " +
                                $"Chunks={count:N0} " +
                                $"Bytes={bytes:N0} " +
                                $"Pending={reorder.PendingCount:N0} " +
                                $"Elapsed={timer.Elapsed}");
                    }
                }


                //
                // Drain anything that became available
                // after completedChannel finished.
                //

                while (reorder.TryGetNext(
                           out var ready))
                {
                    if (ready == null)
                        continue;


                    await output.WriteAsync(
                        ready,
                        token);


                    count++;

                    bytes += ready.Length;
                }


                reorder.Complete();


                if (reorder.PendingCount != 0)
                    throw new CryptographicException(
                        $"{layer}: Reorder incomplete. " +
                        $"Pending={reorder.PendingCount}");


                if (reorder.NextExpected != expectedChunkCount)
                    throw new CryptographicException(
                        $"{layer}: Chunk count mismatch. " +
                        $"Expected={expectedChunkCount:N0} " +
                        $"Processed={reorder.NextExpected:N0}");


                output.TryComplete();


                Logging.Logging.Log(
                    $"[{layer}] OUTPUT COMPLETE " +
                    $"Chunks={count:N0} " +
                    $"Bytes={bytes:N0}");
            }
            catch (Exception ex)
            {
                Fail(ex);

                output.TryComplete(
                    ex);

                throw;
            }
        }


        //---------------------------------------------------------
        // RUN STAGE
        //---------------------------------------------------------

        try
        {
            await Task.WhenAll(
                DispatcherAsync(),
                workersCompletion,
                OutputForwarder());


            var stageFailure =
                Volatile.Read(
                    ref failure);


            if (stageFailure != null)
                throw new CryptographicException(
                    $"{layer}: XChaCha decrypt failed.",
                    stageFailure);


            Logging.Logging.Log(
                $"[{layer}] XChaCha Decrypt SUCCESS");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Fail(ex);

            throw;
        }
        finally
        {
            linked.Cancel();


            try
            {
                await workersCompletion;
            }
            catch
            {
                // failure already captured
            }


            //-----------------------------------------------------
            // Cleanup queued work
            //-----------------------------------------------------

            while (workChannel.Reader.TryRead(
                       out var leftover))
            {
                CleanupBuffer(
                    ref leftover.Buffer,
                    leftover.Length,
                    leftover.BufferPooled);


                if (leftover.AeadTag != null)
                {
                    CryptographicOperations.ZeroMemory(
                        leftover.AeadTag);

                    leftover.AeadTag = null;
                }
            }


            //-----------------------------------------------------
            // Cleanup completed but unwritten
            //-----------------------------------------------------

            while (completedChannel.Reader.TryRead(
                       out var leftover))
            {
                CleanupBuffer(
                    ref leftover.Buffer,
                    leftover.Length,
                    leftover.BufferPooled);


                if (leftover.AeadTag != null)
                {
                    CryptographicOperations.ZeroMemory(
                        leftover.AeadTag);

                    leftover.AeadTag = null;
                }
            }


            //-----------------------------------------------------
            // Cleanup reorder buffer
            //-----------------------------------------------------

            foreach (var chunk in
                     reorder.DrainPending())
                try
                {
                    CleanupBuffer(
                        ref chunk.Buffer,
                        chunk.Length,
                        chunk.BufferPooled);


                    if (chunk.AeadTag != null)
                    {
                        CryptographicOperations.ZeroMemory(
                            chunk.AeadTag);

                        chunk.AeadTag = null;
                    }
                }
                catch
                {
                    // Never hide original crypto failure
                }


            reorder.Dispose();


            if (failure != null)
                output.TryComplete(
                    failure);
            else
                output.TryComplete();


            Logging.Logging.Log(
                $"[{layer}] XChaCha Decrypt EXIT");
        }
    }

    public static async Task<byte[]> CtrEncrypt(
        ChannelReader<CryptoChunk> input,
        ChannelWriter<CryptoChunk> output,
        byte[] key,
        byte[] hmacKey,
        Func<IBlockCipher> cipherFactory,
        byte[] baseNonce,
        byte[] nonceSalt,
        int nonceLength,
        string layer,
        int workerCount,
        int capacity,
        long expectedChunkCount,
        IProgress<long>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(hmacKey);
        ArgumentNullException.ThrowIfNull(cipherFactory);
        ArgumentNullException.ThrowIfNull(baseNonce);
        ArgumentNullException.ThrowIfNull(nonceSalt);

        ArgumentException.ThrowIfNullOrWhiteSpace(layer);


        if (nonceLength <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(nonceLength));


        if (workerCount <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(workerCount));


        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(capacity));


        if (expectedChunkCount < 0)
            throw new ArgumentOutOfRangeException(
                nameof(expectedChunkCount));


        Console.WriteLine(
            $"[{layer}] CTR Encrypt START " +
            $"Workers={workerCount} " +
            $"Capacity={capacity}");


        using var linked =
            CancellationTokenSource.CreateLinkedTokenSource(ct);


        var token =
            linked.Token;

        //---------------------------------------------------------
        // Channels
        //---------------------------------------------------------

        var workChannel =
            Channel.CreateBounded<CryptoChunk>(
                new BoundedChannelOptions(capacity)
                {
                    FullMode =
                        BoundedChannelFullMode.Wait,

                    SingleWriter = true,

                    SingleReader = false,

                    AllowSynchronousContinuations = false
                });


        var completedChannel =
            Channel.CreateBounded<CryptoChunk>(
                new BoundedChannelOptions(capacity)
                {
                    FullMode =
                        BoundedChannelFullMode.Wait,

                    SingleWriter = false,

                    SingleReader = true,

                    AllowSynchronousContinuations = false
                });


        using var reorder =
            new ReorderBuffer(
                0,
                512L * 1024 * 1024,
                workerCount * 128,
                8192);

        Exception? failure = null;

        var failed = 0;


        void Fail(Exception ex)
        {
            if (ex is OperationCanceledException)
                return;


            if (Interlocked.CompareExchange(
                    ref failed,
                    1,
                    0) != 0)
                return;


            Volatile.Write(
                ref failure,
                ex);


            Console.WriteLine(
                $"[{layer}] FAILED {ex.Message}");


            linked.Cancel();


            workChannel.Writer.TryComplete(ex);

            completedChannel.Writer.TryComplete(ex);


            reorder.Abort(ex);


            output.TryComplete(ex);
        }

        using var hmac =
            new HmacSha3Stream(hmacKey);


        long encryptedChunks = 0;
        long encryptedBytes = 0;


        var timer =
            Stopwatch.StartNew();


        //=====================================================
        // DISPATCHER
        //=====================================================

        async Task Dispatcher()
        {
            long chunks = 0;
            long bytes = 0;


            try
            {
                await foreach (var chunk in
                               input.ReadAllAsync(token))
                {
                    token.ThrowIfCancellationRequested();


                    if (chunk.Buffer == null)
                        throw new CryptographicException(
                            $"{layer}: Missing plaintext buffer.");


                    if (chunk.Length <= 0 ||
                        chunk.Length > chunk.Buffer.Length)
                        throw new CryptographicException(
                            $"{layer}: Invalid plaintext length.");


                    await workChannel.Writer.WriteAsync(
                        chunk,
                        token);


                    chunks++;
                    bytes += chunk.Length;


                    if (chunks % 10000 == 0)
                        Console.WriteLine(
                            $"[{layer}] DISPATCH " +
                            $"Chunks={chunks:N0} " +
                            $"Bytes={bytes:N0}");
                }


                workChannel.Writer.TryComplete();


                Console.WriteLine(
                    $"[{layer}] DISPATCH COMPLETE " +
                    $"Chunks={chunks:N0} " +
                    $"Bytes={bytes:N0}");
            }
            catch (Exception ex)
            {
                Fail(ex);
                throw;
            }
        }


        //=====================================================
        // CTR ENCRYPT WORKER
        //=====================================================

        async Task Worker(int workerId)
        {
            var cipher =
                new BufferedBlockCipher(
                    new SicBlockCipher(
                        cipherFactory()));


            var nonce =
                new byte[nonceLength];


            long workerChunks = 0;
            long workerBytes = 0;


            Console.WriteLine(
                $"[{layer}] Worker {workerId} START");


            try
            {
                await foreach (var chunk in
                               workChannel.Reader.ReadAllAsync(token))
                {
                    byte[]? ciphertext = null;
                    var transferred = false;


                    try
                    {
                        token.ThrowIfCancellationRequested();


                        if (chunk.Buffer == null)
                            throw new CryptographicException(
                                $"{layer}: Missing plaintext buffer.");


                        DeriveNonce(
                            baseNonce,
                            nonceSalt,
                            layer,
                            chunk.Index,
                            nonce);


                        cipher.Reset();


                        var iv =
                            new byte[nonceLength];


                        Buffer.BlockCopy(
                            nonce,
                            0,
                            iv,
                            0,
                            nonceLength);


                        cipher.Init(
                            true,
                            new ParametersWithIV(
                                new KeyParameter(key),
                                iv));


                        ciphertext =
                            ArrayPool<byte>.Shared.Rent(
                                chunk.Length);


                        var written =
                            cipher.ProcessBytes(
                                chunk.Buffer,
                                0,
                                chunk.Length,
                                ciphertext,
                                0);


                        written +=
                            cipher.DoFinal(
                                ciphertext,
                                written);


                        CryptographicOperations.ZeroMemory(
                            iv);


                        if (written != chunk.Length)
                            throw new CryptographicException(
                                $"{layer}: CTR size mismatch.");


                        var encrypted =
                            new CryptoChunk
                            {
                                Index =
                                    chunk.Index,

                                ByteOffset =
                                    chunk.ByteOffset,

                                Buffer =
                                    ciphertext,

                                Length =
                                    written,

                                BufferPooled =
                                    true
                            };

                        if (chunk.Index < 3)
                            Console.WriteLine(
                                $"[{layer}] OUTPUT CHUNK " +
                                $"Index={chunk.Index} " +
                                $"Length={written} " +
                                $"Offset={chunk.ByteOffset}");

                        if (written != chunk.Length)
                            throw new CryptographicException(
                                $"{layer}: CTR changed size. " +
                                $"Input={chunk.Length} " +
                                $"Output={written}");


                        if (ciphertext.Length < written)
                            throw new CryptographicException(
                                $"{layer}: Cipher buffer too small.");

                        await completedChannel.Writer.WriteAsync(
                            encrypted,
                            token);


                        transferred = true;

                        ciphertext = null;


                        workerChunks++;
                        workerBytes += written;


                        Interlocked.Increment(
                            ref encryptedChunks);


                        Interlocked.Add(
                            ref encryptedBytes,
                            written);


                        CleanupBuffer(
                            ref chunk.Buffer,
                            chunk.Length,
                            chunk.BufferPooled);


                        if (workerChunks % 10000 == 0)
                            Console.WriteLine(
                                $"[{layer}] Worker={workerId} " +
                                $"ENCRYPT={workerChunks:N0} " +
                                $"Bytes={workerBytes:N0}");
                    }
                    finally
                    {
                        if (!transferred &&
                            ciphertext != null)
                        {
                            CryptographicOperations.ZeroMemory(
                                ciphertext.AsSpan(
                                    0,
                                    Math.Min(
                                        ciphertext.Length,
                                        chunk.Length)));


                            ArrayPool<byte>.Shared.Return(
                                ciphertext,
                                true);
                        }
                    }
                }


                Console.WriteLine(
                    $"[{layer}] Worker={workerId} COMPLETE " +
                    $"Chunks={workerChunks:N0} " +
                    $"Bytes={workerBytes:N0}");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Fail(ex);
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    nonce);


                Console.WriteLine(
                    $"[{layer}] Worker={workerId} EXIT");
            }
        }

        //=====================================================
        // WORKER COMPLETION
        //=====================================================

        var workers =
            Enumerable.Range(
                    0,
                    workerCount)
                .Select(id => Worker(id))
                .ToArray();


        var workersCompletion =
            Task.Run(async () =>
                {
                    Exception? workerFailure = null;


                    try
                    {
                        await Task.WhenAll(
                            workers);
                    }
                    catch (Exception ex)
                    {
                        workerFailure = ex;

                        Fail(ex);
                    }
                    finally
                    {
                        completedChannel.Writer.TryComplete(
                            workerFailure ??
                            Volatile.Read(
                                ref failure));


                        Console.WriteLine(
                            $"[{layer}] ALL WORKERS COMPLETE " +
                            $"Chunks={encryptedChunks:N0} " +
                            $"Bytes={encryptedBytes:N0}");
                    }
                },
                CancellationToken.None);


        //=====================================================
        // ORDERED OUTPUT WRITER
        //=====================================================

        long outputChunks = 0;
        long outputBytes = 0;


        async Task WriteOrdered()
        {
            long localChunks = 0;
            long localBytes = 0;


            var outputTimer =
                Stopwatch.StartNew();


            try
            {
                await foreach (var chunk in
                               completedChannel.Reader.ReadAllAsync(token))
                {
                    reorder.Add(chunk);


                    while (reorder.TryGetNext(
                               out var ready))
                    {
                        if (ready == null)
                            continue;


                        if (ready.Buffer == null)
                            throw new CryptographicException(
                                $"{layer}: Missing ciphertext buffer.");


                        //
                        // HMAC must follow final output order
                        //
                        hmac.Update(
                            ready.Buffer,
                            0,
                            ready.Length);


                        await output.WriteAsync(
                            ready,
                            token);


                        localChunks++;
                        localBytes += ready.Length;


                        Interlocked.Increment(
                            ref outputChunks);


                        Interlocked.Add(
                            ref outputBytes,
                            ready.Length);


                        progress?.Report(
                            outputBytes);


                        if (localChunks % 10000 == 0)
                            Console.WriteLine(
                                $"[{layer}] OUTPUT " +
                                $"Chunks={localChunks:N0} " +
                                $"Bytes={localBytes:N0} " +
                                $"Pending={reorder.PendingCount:N0} " +
                                $"Elapsed={outputTimer.Elapsed}");
                    }
                }


                //
                // Drain chunks that became available after
                // completedChannel finished.
                //
                while (reorder.TryGetNext(
                           out var ready))
                {
                    if (ready == null)
                        continue;


                    if (ready.Buffer == null)
                        throw new CryptographicException(
                            $"{layer}: Missing final ciphertext buffer.");


                    hmac.Update(
                        ready.Buffer,
                        0,
                        ready.Length);


                    await output.WriteAsync(
                        ready,
                        token);


                    localChunks++;
                    localBytes += ready.Length;


                    Interlocked.Increment(
                        ref outputChunks);


                    Interlocked.Add(
                        ref outputBytes,
                        ready.Length);


                    progress?.Report(
                        outputBytes);
                }


                reorder.Complete();


                if (reorder.PendingCount != 0)
                {
                    reorder.DebugDump(
                        layer);


                    throw new CryptographicException(
                        $"{layer}: Reorder incomplete. " +
                        $"Pending={reorder.PendingCount}");
                }


                if (reorder.NextExpected != expectedChunkCount)
                    throw new CryptographicException(
                        $"{layer}: Chunk count mismatch. " +
                        $"Expected={expectedChunkCount:N0} " +
                        $"Processed={reorder.NextExpected:N0}");
            }
            catch (Exception ex)
            {
                Fail(ex);
                throw;
            }
        }


        //=====================================================
        // RUN PIPELINE
        //=====================================================

        try
        {
            await Task.WhenAll(
                Dispatcher(),
                workersCompletion,
                WriteOrdered());


            var pipelineFailure =
                Volatile.Read(
                    ref failure);


            if (pipelineFailure != null)
                throw new CryptographicException(
                    $"{layer}: CTR encryption failed.",
                    pipelineFailure);


            var hash =
                hmac.Final();


            output.TryComplete();


            Console.WriteLine(
                $"[{layer}] CTR ENCRYPT COMPLETE " +
                $"Chunks={outputChunks:N0} " +
                $"Bytes={outputBytes:N0} " +
                $"Elapsed={timer.Elapsed}");


            return hash;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Fail(ex);


            throw new CryptographicException(
                $"{layer}: CTR encryption failed.",
                ex);
        }
        finally
        {
            linked.Cancel();


            try
            {
                await workersCompletion;
            }
            catch
            {
                // Failure already captured
            }


            //
            // Cleanup abandoned work items
            //
            while (workChannel.Reader.TryRead(
                       out var leftover))
                CleanupBuffer(
                    ref leftover.Buffer,
                    leftover.Length,
                    leftover.BufferPooled);


            //
            // Cleanup completed but unwritten items
            //
            while (completedChannel.Reader.TryRead(
                       out var leftover))
                CleanupBuffer(
                    ref leftover.Buffer,
                    leftover.Length,
                    leftover.BufferPooled);


            //
            // Cleanup reorder buffer
            //
            foreach (var chunk in
                     reorder.DrainPending())
                try
                {
                    CleanupBuffer(
                        ref chunk.Buffer,
                        chunk.Length,
                        chunk.BufferPooled);
                }
                catch
                {
                    // Never hide original failure
                }


            reorder.Dispose();


            output.TryComplete(
                failure);


            Console.WriteLine(
                $"[{layer}] CTR Encrypt EXIT");
        }
    }

    public static async Task CtrDecrypt(
        ChannelReader<CryptoChunk> input,
        ChannelWriter<CryptoChunk> output,
        byte[] key,
        byte[] hmacKey,
        byte[] expectedHmac,
        Func<IBlockCipher> cipherFactory,
        byte[] baseNonce,
        byte[] nonceSalt,
        int nonceLength,
        string layer,
        int workerCount,
        int capacity,
        long expectedChunkCount,
        IProgress<long>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(hmacKey);
        ArgumentNullException.ThrowIfNull(expectedHmac);
        ArgumentNullException.ThrowIfNull(cipherFactory);
        ArgumentNullException.ThrowIfNull(baseNonce);
        ArgumentNullException.ThrowIfNull(nonceSalt);

        ArgumentException.ThrowIfNullOrWhiteSpace(layer);


        if (nonceLength <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(nonceLength));


        if (workerCount <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(workerCount));


        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(capacity));


        if (expectedChunkCount < 0)
            throw new ArgumentOutOfRangeException(
                nameof(expectedChunkCount));


        Console.WriteLine(
            $"[{layer}] CTR Decrypt START " +
            $"Workers={workerCount} " +
            $"Capacity={capacity}");


        using var linked =
            CancellationTokenSource.CreateLinkedTokenSource(ct);


        var token =
            linked.Token;


        Exception? failure = null;

        var failed = 0;


        long decryptedChunks = 0;
        long decryptedBytes = 0;

        long outputChunks = 0;
        long outputBytes = 0;


        var stageTimer =
            Stopwatch.StartNew();


        //---------------------------------------------------------
        // Internal channels
        //---------------------------------------------------------

        var workChannel =
            Channel.CreateBounded<CryptoChunk>(
                new BoundedChannelOptions(capacity)
                {
                    FullMode =
                        BoundedChannelFullMode.Wait,

                    SingleWriter = true,

                    SingleReader = false,

                    AllowSynchronousContinuations = false
                });


        var completedChannel =
            Channel.CreateBounded<CryptoChunk>(
                new BoundedChannelOptions(capacity)
                {
                    FullMode =
                        BoundedChannelFullMode.Wait,

                    SingleWriter = false,

                    SingleReader = true,

                    AllowSynchronousContinuations = false
                });


        //---------------------------------------------------------
        // Ordered output buffer
        //---------------------------------------------------------

        using var reorder =
            new ReorderBuffer(
                0,
                512L * 1024 * 1024,
                workerCount * 128,
                8192);


        //---------------------------------------------------------
        // HMAC over incoming ciphertext
        //---------------------------------------------------------

        using var hmac =
            new HmacSha3Stream(hmacKey);


        void Fail(Exception ex)
        {
            if (ex is OperationCanceledException)
                return;


            if (Interlocked.CompareExchange(
                    ref failed,
                    1,
                    0) != 0)
                return;


            Volatile.Write(
                ref failure,
                ex);


            Console.WriteLine(
                $"[{layer}] FAILED {ex.Message}");


            linked.Cancel();


            workChannel.Writer.TryComplete(ex);

            completedChannel.Writer.TryComplete(ex);


            reorder.Abort(ex);


            output.TryComplete(ex);
        }


        //=====================================================
        // DISPATCHER
        //=====================================================

        async Task Dispatcher()
        {
            long chunks = 0;
            long bytes = 0;


            var timer =
                Stopwatch.StartNew();


            try
            {
                await foreach (var chunk in
                               input.ReadAllAsync(token))
                {
                    token.ThrowIfCancellationRequested();


                    if (chunk.Buffer == null)
                        throw new CryptographicException(
                            $"{layer}: Missing ciphertext buffer.");


                    if (chunk.Length <= 0 ||
                        chunk.Length > chunk.Buffer.Length)
                        throw new CryptographicException(
                            $"{layer}: Invalid ciphertext length.");


                    //
                    // HMAC must match encryption:
                    // ciphertext in chunk order
                    //
                    hmac.Update(
                        chunk.Buffer,
                        0,
                        chunk.Length);


                    await workChannel.Writer.WriteAsync(
                        chunk,
                        token);


                    chunks++;
                    bytes += chunk.Length;


                    if (chunks % 10000 == 0)
                        Console.WriteLine(
                            $"[{layer}] DISPATCH " +
                            $"Chunks={chunks:N0} " +
                            $"Bytes={bytes:N0} " +
                            $"Elapsed={timer.Elapsed}");
                }


                workChannel.Writer.TryComplete();


                Console.WriteLine(
                    $"[{layer}] DISPATCH COMPLETE " +
                    $"Chunks={chunks:N0} " +
                    $"Bytes={bytes:N0}");
            }
            catch (Exception ex)
            {
                Fail(ex);
                throw;
            }
        }

        //=====================================================
        // CTR DECRYPT WORKER
        //=====================================================

        async Task Worker(int workerId)
        {
            var cipher =
                new BufferedBlockCipher(
                    new SicBlockCipher(
                        cipherFactory()));


            var nonce =
                new byte[nonceLength];


            long workerChunks = 0;
            long workerBytes = 0;


            var workerTimer =
                Stopwatch.StartNew();


            Console.WriteLine(
                $"[{layer}] Worker {workerId} START");


            try
            {
                await foreach (var chunk in
                               workChannel.Reader.ReadAllAsync(token))
                {
                    byte[]? plaintext = null;

                    var transferred = false;


                    try
                    {
                        token.ThrowIfCancellationRequested();


                        if (chunk.Buffer == null)
                            throw new CryptographicException(
                                $"{layer}: Missing ciphertext buffer.");


                        if (chunk.Length <= 0 ||
                            chunk.Length > chunk.Buffer.Length)
                            throw new CryptographicException(
                                $"{layer}: Invalid ciphertext length.");


                        //-------------------------------------------------
                        // Derive CTR nonce
                        //-------------------------------------------------

                        DeriveNonce(
                            baseNonce,
                            nonceSalt,
                            layer,
                            chunk.Index,
                            nonce);


                        //-------------------------------------------------
                        // Initialize CTR
                        //-------------------------------------------------

                        cipher.Reset();


                        var iv =
                            new byte[nonceLength];


                        Buffer.BlockCopy(
                            nonce,
                            0,
                            iv,
                            0,
                            nonceLength);


                        cipher.Init(
                            true,
                            new ParametersWithIV(
                                new KeyParameter(key),
                                iv));


                        CryptographicOperations.ZeroMemory(
                            iv);


                        //-------------------------------------------------
                        // Decrypt into pooled buffer
                        //-------------------------------------------------

                        plaintext =
                            ArrayPool<byte>.Shared.Rent(
                                chunk.Length);


                        var written =
                            cipher.ProcessBytes(
                                chunk.Buffer,
                                0,
                                chunk.Length,
                                plaintext,
                                0);


                        written +=
                            cipher.DoFinal(
                                plaintext,
                                written);


                        if (written != chunk.Length)
                            throw new CryptographicException(
                                $"{layer}: CTR size mismatch. " +
                                $"Expected={chunk.Length} " +
                                $"Actual={written}");


                        //-------------------------------------------------
                        // Create plaintext chunk
                        //-------------------------------------------------

                        var decrypted =
                            new CryptoChunk
                            {
                                Index =
                                    chunk.Index,

                                ByteOffset =
                                    chunk.ByteOffset,

                                Buffer =
                                    plaintext,

                                Length =
                                    written,

                                BufferPooled =
                                    true
                            };


                        await completedChannel.Writer.WriteAsync(
                            decrypted,
                            token);


                        transferred = true;

                        plaintext = null;


                        workerChunks++;
                        workerBytes += written;


                        Interlocked.Increment(
                            ref decryptedChunks);


                        Interlocked.Add(
                            ref decryptedBytes,
                            written);


                        //-------------------------------------------------
                        // Ciphertext no longer needed
                        //-------------------------------------------------

                        CleanupBuffer(
                            ref chunk.Buffer,
                            chunk.Length,
                            chunk.BufferPooled);


                        if (workerChunks % 10000 == 0)
                            Console.WriteLine(
                                $"[{layer}] Worker={workerId} " +
                                $"DECRYPT={workerChunks:N0} " +
                                $"Bytes={workerBytes:N0} " +
                                $"Elapsed={workerTimer.Elapsed}");
                    }
                    finally
                    {
                        //-------------------------------------------------
                        // Failed plaintext ownership
                        //-------------------------------------------------

                        if (!transferred &&
                            plaintext != null)
                        {
                            CryptographicOperations.ZeroMemory(
                                plaintext.AsSpan(
                                    0,
                                    Math.Min(
                                        chunk.Length,
                                        plaintext.Length)));


                            ArrayPool<byte>.Shared.Return(
                                plaintext,
                                true);
                        }
                    }
                }


                Console.WriteLine(
                    $"[{layer}] Worker={workerId} COMPLETE " +
                    $"Chunks={workerChunks:N0} " +
                    $"Bytes={workerBytes:N0}");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[{layer}] Worker={workerId} FAILED {ex.Message}");

                Fail(ex);

                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    nonce);


                Console.WriteLine(
                    $"[{layer}] Worker={workerId} EXIT");
            }
        }


        //=====================================================
        // START WORKERS
        //=====================================================

        var workers =
            Enumerable.Range(
                    0,
                    workerCount)
                .Select(id => Worker(id))
                .ToArray();


        //=====================================================
        // WORKER COMPLETION
        //=====================================================

        var workersCompletion =
            Task.Run(async () =>
                {
                    Exception? workerFailure = null;


                    try
                    {
                        await Task.WhenAll(
                            workers);
                    }
                    catch (Exception ex)
                    {
                        workerFailure = ex;

                        Fail(ex);
                    }
                    finally
                    {
                        completedChannel.Writer.TryComplete(
                            workerFailure ??
                            Volatile.Read(
                                ref failure));


                        Console.WriteLine(
                            $"[{layer}] ALL WORKERS COMPLETE " +
                            $"Chunks={decryptedChunks:N0} " +
                            $"Bytes={decryptedBytes:N0}");
                    }
                },
                CancellationToken.None);

        //=====================================================
        // ORDERED OUTPUT WRITER
        //=====================================================

        async Task WriteOrdered()
        {
            long localChunks = 0;
            long localBytes = 0;


            var timer =
                Stopwatch.StartNew();


            try
            {
                await foreach (var chunk in
                               completedChannel.Reader.ReadAllAsync(token))
                {
                    reorder.Add(chunk);


                    while (reorder.TryGetNext(
                               out var ready))
                    {
                        if (ready == null)
                            continue;


                        if (ready.Buffer == null)
                            throw new CryptographicException(
                                $"{layer}: Missing plaintext buffer.");


                        await output.WriteAsync(
                            ready,
                            token);


                        localChunks++;
                        localBytes += ready.Length;


                        Interlocked.Increment(
                            ref outputChunks);


                        Interlocked.Add(
                            ref outputBytes,
                            ready.Length);


                        progress?.Report(
                            outputBytes);


                        if (localChunks % 10000 == 0)
                            Console.WriteLine(
                                $"[{layer}] OUTPUT " +
                                $"Chunks={localChunks:N0} " +
                                $"Bytes={localBytes:N0} " +
                                $"Pending={reorder.PendingCount:N0} " +
                                $"Elapsed={timer.Elapsed}");
                    }
                }


                //
                // Drain any chunks that became available after
                // completedChannel finished.
                //
                while (reorder.TryGetNext(
                           out var ready))
                {
                    if (ready == null)
                        continue;


                    if (ready.Buffer == null)
                        throw new CryptographicException(
                            $"{layer}: Missing final plaintext buffer.");


                    await output.WriteAsync(
                        ready,
                        token);


                    localChunks++;
                    localBytes += ready.Length;

                    if ((localChunks & 8191) == 0)
                        Logging.Logging.Log(
                            $"Writer wrote {localChunks:N0}");

                    Interlocked.Increment(
                        ref outputChunks);


                    Interlocked.Add(
                        ref outputBytes,
                        ready.Length);


                    progress?.Report(
                        outputBytes);
                }


                reorder.Complete();


                if (reorder.PendingCount != 0)
                {
                    reorder.DebugDump(
                        layer);


                    throw new CryptographicException(
                        $"{layer}: Reorder incomplete. " +
                        $"Pending={reorder.PendingCount}");
                }


                if (reorder.NextExpected != expectedChunkCount)
                    throw new CryptographicException(
                        $"{layer}: Chunk count mismatch. " +
                        $"Expected={expectedChunkCount:N0} " +
                        $"Processed={reorder.NextExpected:N0}");
            }
            catch (Exception ex)
            {
                Fail(ex);

                throw;
            }
        }


        //=====================================================
        // RUN PIPELINE
        //=====================================================

        try
        {
            await Task.WhenAll(
                Dispatcher(),
                workersCompletion,
                WriteOrdered());


            var pipelineFailure =
                Volatile.Read(
                    ref failure);


            if (pipelineFailure != null)
                throw new CryptographicException(
                    $"{layer}: CTR decrypt pipeline failed.",
                    pipelineFailure);

            //-------------------------------------------------
            // Verify ciphertext authentication
            //-------------------------------------------------

            var actualHmac =
                hmac.Final();


            var valid =
                CryptographicOperations.FixedTimeEquals(
                    actualHmac,
                    expectedHmac);


            CryptographicOperations.ZeroMemory(
                actualHmac);


            if (!valid)
                throw new CryptographicException(
                    $"{layer}: HMAC verification failed.");


            Console.WriteLine(
                $"[{layer}] CTR DECRYPT COMPLETE " +
                $"Chunks={outputChunks:N0} " +
                $"Bytes={outputBytes:N0} " +
                $"Elapsed={stageTimer.Elapsed}");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Fail(ex);


            throw new CryptographicException(
                $"{layer}: CTR decryption failed.",
                ex);
        }
        finally
        {
            linked.Cancel();


            try
            {
                await workersCompletion;
            }
            catch
            {
                // Failure already recorded
            }


            //-------------------------------------------------
            // Cleanup queued work items
            //-------------------------------------------------

            while (workChannel.Reader.TryRead(
                       out var leftover))
            {
                CleanupBuffer(
                    ref leftover.Buffer,
                    leftover.Length,
                    leftover.BufferPooled);

                if (leftover.AeadTag != null)
                {
                    CryptographicOperations.ZeroMemory(
                        leftover.AeadTag);

                    leftover.AeadTag = null;
                }
            }


            //-------------------------------------------------
            // Cleanup completed but unwritten items
            //-------------------------------------------------

            while (completedChannel.Reader.TryRead(
                       out var leftover))
            {
                CleanupBuffer(
                    ref leftover.Buffer,
                    leftover.Length,
                    leftover.BufferPooled);

                if (leftover.AeadTag != null)
                {
                    CryptographicOperations.ZeroMemory(
                        leftover.AeadTag);

                    leftover.AeadTag = null;
                }
            }


            //-------------------------------------------------
            // Cleanup reorder buffer
            //-------------------------------------------------

            foreach (var chunk in
                     reorder.DrainPending())
                try
                {
                    CleanupBuffer(
                        ref chunk.Buffer,
                        chunk.Length,
                        chunk.BufferPooled);
                }
                catch
                {
                    // Never hide crypto failure
                }

            Console.WriteLine(
                $"[{layer}] CTR Decrypt EXIT");
        }
    }

    // =========================
    // NONCE DERIVATION
    // =========================
    private static void DeriveNonce(
        ReadOnlySpan<byte> baseNonce,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<char> layer,
        long chunkIndex,
        Span<byte> output)
    {
        Span<byte> info = stackalloc byte[512];
        var offset = 0;

        // =====================================================
        // VERSION TAG (CRITICAL FOR LONG-TERM STABILITY)
        // =====================================================
        info[offset++] = 0x05;

        // =====================================================
        // LAYER (NO HEAP ALLOCATION)
        // =====================================================
        Span<byte> layerBuf = stackalloc byte[128];
        var layerLen = Encoding.UTF8.GetBytes(layer, layerBuf);

        BinaryPrimitives.WriteInt32LittleEndian(info[offset..], layerLen);
        offset += 4;

        layerBuf[..layerLen].CopyTo(info[offset..]);
        offset += layerLen;

        // =====================================================
        // SALT
        // =====================================================
        BinaryPrimitives.WriteInt32LittleEndian(info[offset..], salt.Length);
        offset += 4;

        salt.CopyTo(info[offset..]);
        offset += salt.Length;

        // =====================================================
        // CHUNK INDEX (ONLY CTR DOMAIN SEPARATION HERE)
        // =====================================================
        BinaryPrimitives.WriteInt64LittleEndian(info[offset..], chunkIndex);
        offset += 8;

        // =====================================================
        // TERMINATOR
        // =====================================================
        info[offset++] = 0xFF;

        // =====================================================
        // HKDF EXPANSION
        // =====================================================
        Hkdf.HKDFExpandFast(
            baseNonce,
            salt,
            info[..offset],
            output);
    }

    private static async Task NormalizeFailureDelay(
        long startTicks,
        long targetTicks,
        CancellationToken ct)
    {
        var elapsed = Stopwatch.GetTimestamp() - startTicks;

        if (elapsed < targetTicks)
        {
            var remaining = targetTicks - elapsed;

            // Convert ticks → milliseconds
            var ms = remaining * 1000.0 / Stopwatch.Frequency;

            if (ms > 0)
                await Task.Delay(TimeSpan.FromMilliseconds(ms), ct);
        }
    }

    private static void CleanupBuffer(
        ref byte[]? buffer,
        int length,
        bool pooled)
    {
        if (buffer == null)
            return;


        try
        {
            var clearLength =
                Math.Min(
                    length,
                    buffer.Length);


            if (clearLength > 0)
                CryptographicOperations.ZeroMemory(
                    buffer.AsSpan(
                        0,
                        clearLength));


            if (pooled)
                ArrayPool<byte>.Shared.Return(
                    buffer);
        }
        finally
        {
            buffer = null;
        }
    }

    public sealed class ReorderBuffer : IDisposable
    {
        private readonly object _lock = new();

        private readonly long _maxBufferedBytes;
        private readonly long _maxIndexDistance;
        private readonly int _maxPendingChunks;

        private readonly SortedDictionary<long, CryptoChunk> _pending;
        private readonly Stopwatch _waitLogTimer = Stopwatch.StartNew();
        private long _bufferedBytes;

        private bool _completed;
        private bool _disposed;

        private Exception? _failure;

        private long _nextExpected;


        public ReorderBuffer(
            long firstIndex = 0,
            long maxBufferedBytes = 512L * 1024 * 1024,
            int maxPendingChunks = 8192,
            long maxIndexDistance = 65536)
        {
            if (firstIndex < 0)
                throw new ArgumentOutOfRangeException(nameof(firstIndex));

            if (maxBufferedBytes <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxBufferedBytes));

            if (maxPendingChunks <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxPendingChunks));

            if (maxIndexDistance <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxIndexDistance));


            _pending = new SortedDictionary<long, CryptoChunk>();
            _nextExpected = firstIndex;

            _maxBufferedBytes = maxBufferedBytes;
            _maxPendingChunks = maxPendingChunks;
            _maxIndexDistance = maxIndexDistance;
        }

        public long NextExpected
        {
            get
            {
                lock (_lock)
                {
                    return _nextExpected;
                }
            }
        }


        public int PendingCount
        {
            get
            {
                lock (_lock)
                {
                    ThrowIfDisposed();
                    return _pending.Count;
                }
            }
        }


        public long BufferedBytes
        {
            get
            {
                lock (_lock)
                {
                    ThrowIfDisposed();
                    return _bufferedBytes;
                }
            }
        }


        public bool IsFailed
        {
            get
            {
                lock (_lock)
                {
                    return _failure != null;
                }
            }
        }


        public bool IsCompleted
        {
            get
            {
                lock (_lock)
                {
                    return _completed;
                }
            }
        }


        public Exception? Failure
        {
            get
            {
                lock (_lock)
                {
                    return _failure;
                }
            }
        }


        public void Dispose()
        {
            List<CryptoChunk>? cleanup;


            lock (_lock)
            {
                if (_disposed)
                    return;


                _disposed = true;


                cleanup =
                    _pending.Values.ToList();


                _pending.Clear();

                _bufferedBytes = 0;
            }


            foreach (var chunk in cleanup)
                if (chunk.BufferPooled && chunk.Buffer != null)
                    CleanupChunk(chunk);
        }

        private static void CleanupChunk(
            CryptoChunk chunk)
        {
            if (chunk.Buffer != null)
            {
                CryptographicOperations.ZeroMemory(
                    chunk.Buffer.AsSpan(
                        0,
                        Math.Min(
                            chunk.Length,
                            chunk.Buffer.Length)));

                if (chunk.BufferPooled)
                {
                    ArrayPool<byte>.Shared.Return(
                        chunk.Buffer,
                        true);

                    chunk.BufferPooled = false;
                }

                chunk.Buffer = null;
            }


            if (chunk.AeadTag != null)
            {
                CryptographicOperations.ZeroMemory(
                    chunk.AeadTag);

                chunk.AeadTag = null;
            }
        }


        public void Add(
            CryptoChunk chunk)
        {
            ArgumentNullException.ThrowIfNull(chunk);

            ValidateChunk(chunk);


            lock (_lock)
            {
                ThrowIfDisposed();
                ThrowIfFailed();


                if (_completed)
                    throw new CryptographicException(
                        "Cannot add after completion.");


                if (chunk.Index < _nextExpected)
                    throw new CryptographicException(
                        $"Stale chunk {chunk.Index}. Expected {_nextExpected}");


                long distance;

                try
                {
                    distance =
                        checked(
                            chunk.Index -
                            _nextExpected);
                }
                catch (OverflowException ex)
                {
                    throw new CryptographicException(
                        "Chunk index distance overflow.",
                        ex);
                }


                if (distance > _maxIndexDistance)
                    throw new CryptographicException(
                        $"Chunk distance too large. " +
                        $"Received={chunk.Index} Expected={_nextExpected}");


                if (_pending.ContainsKey(chunk.Index))
                    throw new CryptographicException(
                        $"Duplicate chunk {chunk.Index}");


                if (_pending.Count >= _maxPendingChunks)
                    throw new CryptographicException(
                        "Pending chunk limit exceeded.");


                if (chunk.Length >
                    _maxBufferedBytes - _bufferedBytes)
                    throw new CryptographicException(
                        "Buffered memory limit exceeded.");


                _pending.Add(
                    chunk.Index,
                    chunk);


                checked
                {
                    _bufferedBytes += chunk.Length;
                }
            }
        }


        public bool TryGetNext(
            out CryptoChunk? chunk)
        {
            lock (_lock)
            {
                ThrowIfDisposed();
                ThrowIfFailed();


                if (!_pending.TryGetValue(
                        _nextExpected,
                        out chunk))
                {
                    if (_pending.Count > 0)
                    {
                        var lowest =
                            _pending.First().Key;

                        long distance;

                        try
                        {
                            distance = checked(lowest - _nextExpected);
                        }
                        catch (OverflowException)
                        {
                            throw new CryptographicException(
                                "Reorder index distance overflow.");
                        }

                        if (distance > 32 &&
                            _waitLogTimer.ElapsedMilliseconds > 5000)
                        {
                            _pending.Remove(
                                _nextExpected);

                            _waitLogTimer.Restart();

                            Console.WriteLine(
                                $"[REORDER GAP] " +
                                $"Missing={_nextExpected} " +
                                $"Ahead={distance} " +
                                $"Pending={_pending.Count}");
                        }
                    }


                    chunk = null;
                    return false;
                }


                _pending.Remove(
                    _nextExpected);


                checked
                {
                    _bufferedBytes -= chunk.Length;
                }


                if (_nextExpected == long.MaxValue)
                    throw new CryptographicException(
                        "Chunk index overflow.");


                _nextExpected++;


                return true;
            }
        }


        public void Complete()
        {
            lock (_lock)
            {
                ThrowIfDisposed();
                ThrowIfFailed();

                if (_pending.Count != 0)
                    throw new CryptographicException(
                        $"Reorder completed with missing chunks. " +
                        $"NextExpected={_nextExpected}, " +
                        $"Pending={_pending.Count}");

                _completed = true;
            }
        }


        /// <summary>
        ///     Marks failure.
        ///     Does NOT return buffers.
        ///     Caller owns cleanup after pipeline cancellation.
        /// </summary>
        public void Abort(
            Exception ex)
        {
            ArgumentNullException.ThrowIfNull(ex);


            lock (_lock)
            {
                if (_disposed)
                    return;


                if (_failure != null)
                    return;


                _failure = ex;
                _completed = true;
            }
        }


        /// <summary>
        ///     Removes and returns pending chunks.
        ///     Caller owns returned buffers.
        /// </summary>
        public List<CryptoChunk> DrainPending()
        {
            lock (_lock)
            {
                ThrowIfDisposed();

                var result =
                    _pending.Values
                        .OrderBy(x => x.Index)
                        .ToList();

                _pending.Clear();

                _bufferedBytes = 0;

                return result;
            }
        }

        public void Clear()
        {
            var cleanup =
                DrainPending();


            foreach (var chunk in cleanup)
                if (chunk.BufferPooled && chunk.Buffer != null)
                    CleanupChunk(chunk);
        }


        public string GetStatus()
        {
            lock (_lock)
            {
                return
                    $"Pending={_pending.Count:N0} " +
                    $"Bytes={_bufferedBytes:N0} " +
                    $"Next={_nextExpected:N0} " +
                    $"Failed={_failure != null} " +
                    $"Completed={_completed} " +
                    $"Disposed={_disposed}";
            }
        }


        private static void ValidateChunk(
            CryptoChunk chunk)
        {
            if (chunk.Index < 0)
                throw new CryptographicException(
                    "Negative chunk index.");


            if (chunk.Index == long.MaxValue)
                throw new CryptographicException(
                    "Chunk index overflow.");


            if (chunk.Buffer == null)
                throw new CryptographicException(
                    "Chunk buffer missing.");


            if (chunk.Length <= 0)
                throw new CryptographicException(
                    "Invalid chunk length.");


            if (chunk.Length > chunk.Buffer.Length)
                throw new CryptographicException(
                    "Chunk length exceeds buffer.");


            if (chunk.Length > 16 * 1024 * 1024)
                throw new CryptographicException(
                    "Chunk exceeds maximum size.");
        }


        private void ThrowIfFailed()
        {
            if (_failure != null)
                throw new CryptographicException(
                    "Reorder buffer failed.",
                    _failure);
        }

        public void DebugDump(string layer)
        {
            lock (_lock)
            {
                Console.WriteLine(
                    $"[{layer}] REORDER " +
                    $"Next={_nextExpected} " +
                    $"Pending={_pending.Count} " +
                    $"Bytes={_bufferedBytes:N0}");

                if (_pending.Count > 0)
                    Console.WriteLine(
                        $"[{layer}] Lowest={_pending.First().Key} " +
                        $"Highest={_pending.Last().Key}");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(
                    nameof(ReorderBuffer));
        }
    }
}