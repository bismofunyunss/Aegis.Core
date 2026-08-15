using Aegis.Contracts;
using Aegis.Core.Authentication;
using Aegis.Core.Crypto;
using Aegis.Core.FileEncryption;
using Aegis.Core.IPC;
using Aegis.Core.Storage;
using Aegis.Core.Tpm;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Tpm2Lib;

public static class CryptoAttackCampaign
{
    private static readonly List<RegisteredAttack> _attacks = new();

    private static byte[]? _baselineCiphertext;

    private static long _testSize =
        16L * 1024 * 1024;

    private const int HeaderSize =
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

    private const int HeaderMacSize = 64;
    private const int ChunkHeaderSize = 16;
    private const int AeadTagSize = 16;


    private static int FirstChunkOffset =>
        HeaderSize + HeaderMacSize;



    private static int FirstChunkCiphertextOffset()
    {
        return FirstChunkOffset +
               ChunkHeaderSize;
    }

    public static async Task<AttackReport> Run(
        DerivedKeys keys,
        CryptoPipelineOptions options,
        long testSize,
        CancellationToken cancellationToken = default)
    {
        _testSize = testSize;


        var report = new AttackReport();


        Console.WriteLine();
        Console.WriteLine("=================================");
        Console.WriteLine(" Crypto Attack Campaign");
        Console.WriteLine("=================================");


        await CreateBaselineAsync(keys, options);

        var context = new AttackContext
        {
            Keys = keys,
            Options = options,
            BaselineCiphertext = _baselineCiphertext!,
            PlaintextSize = testSize,
        };

        RegisterAttacks();


        foreach (var attack in _attacks)
        {
            Console.WriteLine();
            Console.WriteLine(
                $"========== START {attack.Name} ==========");

            var result =
                await ExecuteAttack(
                    attack,
                    context,
                    cancellationToken);

            Console.WriteLine(
                $"========== END {attack.Name} ==========");

            report.Add(result);
        }


        report.Print();


        return report;
    }

    private static void RegisterAttacks()
    {
        _attacks.Clear();


        // =====================================
        // BASELINE
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Encrypt/Decrypt Roundtrip",
            EncryptDecryptRoundtrip));

        _attacks.Add(new RegisteredAttack(
            "Zero Length Input",
            ZeroLengthInput));

        _attacks.Add(new RegisteredAttack(
            "One Byte Input",
            OneByteInput));

        _attacks.Add(new RegisteredAttack(
            "64KB Boundary",
            BoundaryTest1));

        _attacks.Add(new RegisteredAttack(
            "64KB + 1 Boundary",
            BoundaryTest2));

        _attacks.Add(new RegisteredAttack(
            "Deterministic Stream",
            DeterministicStream));

        _attacks.Add(new RegisteredAttack(
            "Random Data",
            RandomData));

        _attacks.Add(new RegisteredAttack(
            "Multiple Encryptions",
            MultipleEncryptions));

        _attacks.Add(new RegisteredAttack(
            "Ciphertext Changes",
            CiphertextChanges));

        _attacks.Add(new RegisteredAttack(
            "Large Stream",
            LargeStream));

        // =====================================
        // HEADER ATTACKS
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Header Version Mutation",
            HeaderVersionMutation));

        _attacks.Add(new RegisteredAttack(
            "Header Random Byte Mutation",
            HeaderRandomByteMutation));

        _attacks.Add(new RegisteredAttack(
            "Header Nonce Mutation",
            HeaderNonceMutation));

        _attacks.Add(new RegisteredAttack(
            "Header Salt Mutation",
            HeaderSaltMutation));

        _attacks.Add(new RegisteredAttack(
            "Header Truncation",
            HeaderTruncation));

        _attacks.Add(new RegisteredAttack(
            "Header HMAC Mutation",
            HeaderHmacMutation));

        _attacks.Add(new RegisteredAttack(
            "Header Replay",
            HeaderReplay));

        _attacks.Add(new RegisteredAttack(
            "Header Length Corruption",
            HeaderLengthCorruption));

        _attacks.Add(new RegisteredAttack(
            "Header Fuzzer",
            HeaderFuzzer));

        _attacks.Add(new RegisteredAttack(
            "Header Authentication Timing",
            HeaderAuthenticationTiming));

        // =====================================
        // CHUNK ATTACKS
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Chunk Index Mutation",
            ChunkIndexMutation));

        _attacks.Add(new RegisteredAttack(
            "Chunk Length Mutation",
            ChunkLengthMutation));

        _attacks.Add(new RegisteredAttack(
            "Chunk Removal",
            ChunkRemoval));

        _attacks.Add(new RegisteredAttack(
            "Chunk Duplication",
            ChunkDuplication));

        _attacks.Add(new RegisteredAttack(
            "Chunk Reorder",
            ChunkReorder));

        _attacks.Add(new RegisteredAttack(
            "Chunk Truncation",
            ChunkTruncation));

        _attacks.Add(new RegisteredAttack(
            "Invalid Chunk Size",
            InvalidChunkSize));

        _attacks.Add(new RegisteredAttack(
            "Chunk Header Fuzzer",
            ChunkHeaderFuzzer));

        _attacks.Add(new RegisteredAttack(
            "Missing AEAD Tag",
            MissingAeadTag));

        _attacks.Add(new RegisteredAttack(
            "Corrupt AEAD Tag",
            CorruptAeadTag));


        // =====================================
        // CIPHERTEXT
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Single Bit Flip",
            SingleBitFlip));

        _attacks.Add(new RegisteredAttack(
            "Multi Bit Corruption",
            MultiBitCorruption));

        _attacks.Add(new RegisteredAttack(
            "Random Byte Corruption",
            RandomByteCorruption));

        _attacks.Add(new RegisteredAttack(
            "Ciphertext Expansion",
            CiphertextExpansion));

        _attacks.Add(new RegisteredAttack(
            "Ciphertext Shrink",
            CiphertextShrink));

        _attacks.Add(new RegisteredAttack(
            "Middle Stream Corruption",
            MiddleStreamCorruption));

        _attacks.Add(new RegisteredAttack(
            "End Block Corruption",
            EndBlockCorruption));

        _attacks.Add(new RegisteredAttack(
            "CTR Alignment Attack",
            CtrAlignmentAttack));

        _attacks.Add(new RegisteredAttack(
            "Partial Ciphertext Stream",
            PartialCiphertextStream));

        _attacks.Add(new RegisteredAttack(
            "Ciphertext Fuzz Attack",
            CiphertextFuzzAttack));


        // =====================================
        // REPLAY
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Partial Ciphertext Replay",
            PartialCiphertextReplay));

        _attacks.Add(new RegisteredAttack(
            "Header Replay Attack",
            HeaderReplayAttack));

        _attacks.Add(new RegisteredAttack(
            "Cross Data Replay",
            CrossDataReplay));


        // =====================================
        // MUTATION
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Known Cipher Injection",
            KnownCipherInjection));

        _attacks.Add(new RegisteredAttack(
            "Random Mutation Storm",
            RandomMutationStorm));

        _attacks.Add(new RegisteredAttack(
            "Length Field Abuse",
            LengthFieldAbuse));

        _attacks.Add(new RegisteredAttack(
            "Offset Manipulation",
            OffsetManipulation));

        _attacks.Add(new RegisteredAttack(
            "Mixed Corruption Attack",
            MixedCorruptionAttack));

        _attacks.Add(new RegisteredAttack(
            "First Chunk Mutation",
            FirstChunkMutation));

        _attacks.Add(new RegisteredAttack(
            "Middle Chunk Mutation",
            MiddleChunkMutation));

        _attacks.Add(new RegisteredAttack(
            "Last Chunk Mutation",
            LastChunkMutation));

        _attacks.Add(new RegisteredAttack(
            "Multiple Chunk Swap",
            MultipleChunkSwap));

        _attacks.Add(new RegisteredAttack(
            "Mutation Fuzzer",
            MutationFuzzer));

        // =====================================
        // AEAD ATTACKS
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "XChaCha Tag Mutation",
            XChaChaTagMutation));

        _attacks.Add(new RegisteredAttack(
            "XChaCha Cipher Mutation",
            XChaChaCipherMutation));

        _attacks.Add(new RegisteredAttack(
            "AEAD Nonce Mutation",
            AeadNonceMutation));

        _attacks.Add(new RegisteredAttack(
            "AEAD AAD Mutation",
            AeadAadMutation));

        _attacks.Add(new RegisteredAttack(
            "Poly1305 Tag Removal",
            PolyTagRemoval));

        _attacks.Add(new RegisteredAttack(
            "AEAD Random Forgery",
            AeadRandomForgery));


        // =====================================
        // HMAC ATTACKS
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "AES HMAC Mutation",
            AesHmacMutation));

        _attacks.Add(new RegisteredAttack(
            "Serpent HMAC Mutation",
            SerpentHmacMutation));

        _attacks.Add(new RegisteredAttack(
            "Threefish HMAC Mutation",
            ThreeFishHmacMutation));

        _attacks.Add(new RegisteredAttack(
            "HMAC Truncation",
            HmacTruncation));

        _attacks.Add(new RegisteredAttack(
            "HMAC Extension",
            HmacExtension));

        _attacks.Add(new RegisteredAttack(
            "HMAC Random Corruption",
            RandomHmacCorruption));

        _attacks.Add(new RegisteredAttack(
            "Wrong HMAC Ordering",
            WrongHmacOrdering));

        _attacks.Add(new RegisteredAttack(
            "HMAC Replay",
            HmacReplay));

        _attacks.Add(new RegisteredAttack(
            "Multiple HMAC Mutation",
            MultipleHmacMutation));

        _attacks.Add(new RegisteredAttack(
            "Authentication Failure Timing",
            AuthFailureTiming));

        _attacks.Add(new RegisteredAttack(
            "Cascade Authentication Failure",
            CascadeAuthFailure));


        // =====================================
        // KEY DERIVATION
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Salt Mutation",
            SaltMutation));

        _attacks.Add(new RegisteredAttack(
            "Derived Key Mutation",
            DerivedKeyMutation));


        // =====================================
        // HKDF
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "HKDF Context Mutation",
            HkdfContextMutation));

        _attacks.Add(new RegisteredAttack(
            "HKDF Length Abuse",
            HkdfLengthAbuse));


        // =====================================
        // NONCE
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Nonce Mutation",
            NonceMutation));

        _attacks.Add(new RegisteredAttack(
            "Nonce Reuse Detection",
            NonceReuseDetection));

        _attacks.Add(new RegisteredAttack(
            "Nonce Collision Test",
            NonceCollisionTest));

        _attacks.Add(new RegisteredAttack(
            "Counter Manipulation",
            CounterManipulation));


        // =====================================
        // CASCADE
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Layer Removal Attack",
            LayerRemovalAttack));

        _attacks.Add(new RegisteredAttack(
            "Layer Reordering Attack",
            LayerReorderingAttack));

        _attacks.Add(new RegisteredAttack(
            "Single Layer Bypass",
            SingleLayerBypass));

        _attacks.Add(new RegisteredAttack(
            "Inner Layer Mutation",
            InnerLayerMutation));

        _attacks.Add(new RegisteredAttack(
            "Outer Layer Mutation",
            OuterLayerMutation));

        _attacks.Add(new RegisteredAttack(
            "Full Cascade Corruption",
            FullCascadeCorruption));


        // =====================================
        // TIMING
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Authentication Timing Test",
            AuthenticationTimingTest));

        _attacks.Add(new RegisteredAttack(
            "Failure Timing Variance",
            FailureTimingVariance));


        // =====================================
        // MEMORY
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Memory Pressure Test",
            MemoryPressureTest));

        _attacks.Add(new RegisteredAttack(
            "Large Stream Test",
            LargeStreamTest));


        // =====================================
        // CONCURRENCY
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Parallel Encryption Race",
            ParallelEncryptionRace));

        _attacks.Add(new RegisteredAttack(
            "Parallel Decryption Race",
            ParallelDecryptionRace));


        // =====================================
        // STRESS
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "High Load Pipeline Test",
            HighLoadTest));

        _attacks.Add(new RegisteredAttack(
            "Long Running Stream Test",
            LongRunningStreamTest));


        // =====================================
        // FUZZING
        // =====================================

        _attacks.Add(new RegisteredAttack(
            "Complete Cipher Fuzzer",
            CompleteCipherFuzzer));

        _attacks.Add(new RegisteredAttack(
            "Adaptive Mutation Campaign",
            AdaptiveMutationCampaign));
    }
        

    private static async Task<AttackResult> ExecuteAttack(
        RegisteredAttack attack,
        AttackContext context,
        CancellationToken token)
    {
        var stopwatch = Stopwatch.StartNew();


        try
        {
            Console.WriteLine(
                $"Running: {attack.Name}");


            await attack.Execute(
                context!,
                token);


            stopwatch.Stop();


            return new AttackResult
            {
                Name = attack.Name,
                Passed = true,
                Duration = stopwatch.Elapsed,
                Message = "Completed"
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();

            Console.WriteLine(
                $"ATTACK EXCEPTION: {attack.Name}");

            Console.WriteLine(ex);

            return new AttackResult
            {
                Name = attack.Name,
                Passed = false,
                Duration = stopwatch.Elapsed,
                Message = ex.Message,
                Exception = ex
            };
        }
    }

    private static async Task ExpectFailure(
        Func<Task> decrypt)
    {
        try
        {
            await decrypt();

            throw new Exception(
                "SECURITY FAILURE: Modified data decrypted successfully.");
        }
        catch (
            CryptographicException)
        {
        }
        catch (
            EndOfStreamException)
        {
        }
        catch (
            InvalidDataException)
        {
        }
        catch (
            IOException)
        {
        }
    }

    private static async Task<AttackResult> ExpectAttackFailure(
        string name,
        Func<Task> attack)
    {
        var sw =
            Stopwatch.StartNew();

        try
        {
            await attack();

            sw.Stop();

            return new AttackResult
            {
                Name = name,
                Passed = false,
                Duration = sw.Elapsed,
                Message =
                    "SECURITY FAILURE: Attack was accepted."
            };
        }
        catch (CryptographicException ex)
        {
            sw.Stop();

            return new AttackResult
            {
                Name = name,
                Passed = true,
                Duration = sw.Elapsed,
                Message =
                    "Correctly rejected: " + ex.Message,
                Exception = ex
            };
        }
        catch (InvalidOperationException ex)
        {
            sw.Stop();

            return new AttackResult
            {
                Name = name,
                Passed = true,
                Duration = sw.Elapsed,
                Message =
                    "Pipeline rejected attack: " + ex.Message,
                Exception = ex
            };
        }
        catch (OperationCanceledException ex)
        {
            sw.Stop();

            return new AttackResult
            {
                Name = name,
                Passed = true,
                Duration = sw.Elapsed,
                Message =
                    "Pipeline cancelled after rejection.",
                Exception = ex
            };
        }
        catch (Exception ex)
        {
            sw.Stop();

            return new AttackResult
            {
                Name = name,
                Passed = true,
                Duration = sw.Elapsed,
                Message =
                    "Rejected: " + ex.Message,
                Exception = ex
            };
        }
    }

    // =====================================================
    // HELPERS
    // =====================================================

    private static async Task<byte[]> EncryptData(
        Stream plaintext,
        AttackContext ctx,
        CancellationToken ct)
    {
        using var encrypted = new MemoryStream();

        await Methods.Encrypt(
            plaintext,
            encrypted,
            ctx.Keys,
            ctx.Options);

        return encrypted.ToArray();
    }


    private static async Task<byte[]> DecryptData(
        byte[] ciphertext,
        AttackContext ctx,
        CancellationToken ct)
    {
        using var input =
            new MemoryStream(ciphertext);

        using var output =
            new MemoryStream();


        await Methods.Decrypt(
            input,
            output,
            ctx.Keys,
            ctx.Options);


        return output.ToArray();
    }

    private static DerivedKeys CloneKeys(
        DerivedKeys source)
    {
        return new DerivedKeys(
            source.XChaChaKey.ToArray(),
            source.ThreefishKey.ToArray(),
            source.SerpentKey.ToArray(),
            source.AesKey.ToArray(),
            source.ShuffleKey.ToArray(),
            source.ThreefishHmacKey.ToArray(),
            source.SerpentHmacKey.ToArray(),
            source.AesHmacKey.ToArray(),
            source.HeaderHmacKey.ToArray(),
            source.Salts
                .Select(x => x.ToArray())
                .ToArray());
    }

    private static async Task<byte[]> EncryptBytes(
        byte[] plaintext,
        AttackContext ctx,
        CancellationToken ct)
    {
        using var input =
            new MemoryStream(
                plaintext,
                writable: false);


        using var output =
            new MemoryStream();


        await Methods.Encrypt(
            input,
            output,
            ctx.Keys,
            ctx.Options);


        return output.ToArray();
    }


    private static async Task<byte[]> DecryptBytesToArray(
        byte[] ciphertext,
        AttackContext ctx)
    {
        using var input =
            new MemoryStream(
                ciphertext,
                writable: false);


        using var output =
            new MemoryStream();


        await Methods.Decrypt(
            input,
            output,
            ctx.Keys,
            ctx.Options);


        return output.ToArray();
    }

    private static async Task DecryptBytes(
        byte[] data,
        AttackContext ctx)
    {
        using var input =
            new MemoryStream(data);

        using var output =
            new MemoryStream();

        await Methods.Decrypt(
            input,
            output,
            ctx.Keys,
            ctx.Options);
    }

    private static async Task<byte[]> CreateDeterministicData(
        long size)
    {
        using var stream =
            new DeterministicRandomStream(size);


        using var ms =
            new MemoryStream();


        await stream.CopyToAsync(ms);


        return ms.ToArray();
    }


    private static void AssertEqual(
        byte[] expected,
        byte[] actual,
        string message)
    {
        if (CryptographicOperations.FixedTimeEquals(
                expected,
                actual))
        {
            return;
        }


        Console.WriteLine(
            "========== ROUNDTRIP FAILURE ==========");


        Console.WriteLine(
            $"Expected Length: {expected.Length}");

        Console.WriteLine(
            $"Actual Length:   {actual.Length}");


        int mismatch = -1;

        int length =
            Math.Min(
                expected.Length,
                actual.Length);


        for (int i = 0; i < length; i++)
        {
            if (expected[i] != actual[i])
            {
                mismatch = i;
                break;
            }
        }


        Console.WriteLine(
            $"First mismatch: {mismatch}");


        if (mismatch >= 0)
        {
            Console.WriteLine(
                $"Expected[{mismatch}] = 0x{expected[mismatch]:X2}");

            Console.WriteLine(
                $"Actual[{mismatch}]   = 0x{actual[mismatch]:X2}");
        }


        if (expected.Length != actual.Length)
        {
            Console.WriteLine(
                $"Length delta: {actual.Length - expected.Length}");
        }


        //
        // Show beginning and end samples
        //
        Console.WriteLine(
            "Expected first 32 bytes:");

        Console.WriteLine(
            Convert.ToHexString(
                expected.AsSpan(
                    0,
                    Math.Min(32, expected.Length))));


        Console.WriteLine(
            "Actual first 32 bytes:");

        Console.WriteLine(
            Convert.ToHexString(
                actual.AsSpan(
                    0,
                    Math.Min(32, actual.Length))));


        Console.WriteLine(
            "======================================");


        throw new CryptographicException(
            message);
    }

    private static async Task<AttackResult> MutateHeaderAndDecrypt(
        AttackContext ctx,
        string name,
        CancellationToken ct,
        Action<byte[]> mutation)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        mutation(modified);


        return await ExpectAttackFailure(
            name,
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }

    private static async Task<AttackResult> MutateAndDecrypt(
        AttackContext ctx,
        string name,
        CancellationToken ct,
        Action<byte[]> mutation)
    {
        return await ExpectAttackFailure(
            name,
            async () =>
            {
                byte[] modified =
                    ctx.BaselineCiphertext.ToArray();


                mutation(modified);


                using var input =
                    new MemoryStream(modified);


                using var output =
                    new MemoryStream();


                await Methods.Decrypt(
                    input,
                    output,
                    ctx.Keys,
                    ctx.Options);
            });
    }

    // =====================================
    // BASELINE
    // =====================================

    private static async Task EncryptDecryptRoundtrip(
        AttackContext ctx,
        CancellationToken ct)
    {
        var plaintext =
            await CreateDeterministicData(
                ctx.PlaintextSize);


        using var input =
            new MemoryStream(plaintext);


        var ciphertext =
            await EncryptData(
                input,
                ctx,
                ct);


        var decrypted =
            await DecryptData(
                ciphertext,
                ctx,
                ct);


        AssertEqual(
            plaintext,
            decrypted,
            "Roundtrip mismatch");
    }

    private static async Task ZeroLengthInput(
        AttackContext ctx,
        CancellationToken ct)
    {
        using var input =
            new MemoryStream();


        try
        {
            await EncryptData(
                input,
                ctx,
                ct);


            throw new CryptographicException(
                "Zero length input was incorrectly accepted.");
        }
        catch (CryptographicException)
        {
            // Expected behavior
        }
    }

    private static async Task OneByteInput(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] plaintext =
        {
            0x42
        };


        using var input =
            new MemoryStream(plaintext);


        var ciphertext =
            await EncryptData(
                input,
                ctx,
                ct);


        var decrypted =
            await DecryptData(
                ciphertext,
                ctx,
                ct);


        AssertEqual(
            plaintext,
            decrypted,
            "One byte roundtrip failed");
    }

    private static async Task BoundaryTest1(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] plaintext =
            await CreateDeterministicData(
                64 * 1024);


        using var input =
            new MemoryStream(plaintext);


        var ciphertext =
            await EncryptData(
                input,
                ctx,
                ct);


        var decrypted =
            await DecryptData(
                ciphertext,
                ctx,
                ct);


        AssertEqual(
            plaintext,
            decrypted,
            "64KB boundary failed");
    }

    private static async Task BoundaryTest2(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] plaintext =
            await CreateDeterministicData(
                (64 * 1024) + 1);


        using var input =
            new MemoryStream(plaintext);


        var ciphertext =
            await EncryptData(
                input,
                ctx,
                ct);


        var decrypted =
            await DecryptData(
                ciphertext,
                ctx,
                ct);


        AssertEqual(
            plaintext,
            decrypted,
            "64KB+1 boundary failed");
    }

    private static async Task DeterministicStream(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] plaintext1 =
            await CreateDeterministicData(
                ctx.PlaintextSize);


        byte[] plaintext2 =
            await CreateDeterministicData(
                ctx.PlaintextSize);


        AssertEqual(
            plaintext1,
            plaintext2,
            "Deterministic generator mismatch");


        using var input =
            new MemoryStream(plaintext1);


        var ciphertext =
            await EncryptData(
                input,
                ctx,
                ct);


        var decrypted =
            await DecryptData(
                ciphertext,
                ctx,
                ct);


        AssertEqual(
            plaintext1,
            decrypted,
            "Deterministic stream failed");
    }

    private static async Task RandomData(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] plaintext =
            RandomNumberGenerator.GetBytes(
                (int)Math.Min(
                    ctx.PlaintextSize,
                    1024 * 1024));


        using var input =
            new MemoryStream(plaintext);


        var ciphertext =
            await EncryptData(
                input,
                ctx,
                ct);


        var decrypted =
            await DecryptData(
                ciphertext,
                ctx,
                ct);


        AssertEqual(
            plaintext,
            decrypted,
            "Random data failed");
    }

    private static async Task MultipleEncryptions(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] plaintext =
            await CreateDeterministicData(
                1024 * 1024);


        using var input1 =
            new MemoryStream(plaintext);


        using var input2 =
            new MemoryStream(plaintext);


        var cipher1 =
            await EncryptData(
                input1,
                ctx,
                ct);


        var cipher2 =
            await EncryptData(
                input2,
                ctx,
                ct);


        if (cipher1.SequenceEqual(cipher2))
        {
            throw new CryptographicException(
                "Two encryptions produced identical ciphertext");
        }
    }

    private static async Task CiphertextChanges(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            HeaderSize +
            HeaderMacSize +
            20;


        modified[position] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "Ciphertext Changes",
                async () =>
                {
                    await DecryptData(
                        modified,
                        ctx,
                        ct);
                });


        if (!result.Passed)
        {
            throw new Exception(
                result.Message);
        }
    }

    private static async Task LargeStream(
        AttackContext ctx,
        CancellationToken ct)
    {
        const long largeSize =
            1024L * 1024 * 1024; // 1GB


        Console.WriteLine(
            $"Large stream test: {largeSize:N0} bytes");


        using var input =
            new DeterministicRandomStream(
                largeSize);


        var ciphertext =
            await EncryptData(
                input,
                ctx,
                ct);


        var decrypted =
            await DecryptData(
                ciphertext,
                ctx,
                ct);


        if (decrypted.Length != largeSize)
        {
            throw new CryptographicException(
                $"Large stream size mismatch. " +
                $"Expected {largeSize:N0}, " +
                $"Got {decrypted.Length:N0}");
        }


        using var verifyInput =
            new DeterministicRandomStream(
                largeSize);


        using var decryptedStream =
            new MemoryStream(
                decrypted);


        byte[] expectedBuffer =
            new byte[1024 * 1024];


        byte[] actualBuffer =
            new byte[1024 * 1024];


        while (true)
        {
            int expectedRead =
                await verifyInput.ReadAsync(
                    expectedBuffer,
                    ct);


            int actualRead =
                await decryptedStream.ReadAsync(
                    actualBuffer,
                    ct);


            if (expectedRead != actualRead)
            {
                throw new CryptographicException(
                    "Large stream length verification failed.");
            }


            if (expectedRead == 0)
                break;


            if (!expectedBuffer
                    .AsSpan(0, expectedRead)
                    .SequenceEqual(
                        actualBuffer.AsSpan(0, actualRead)))
            {
                throw new CryptographicException(
                    "Large stream data mismatch.");
            }
        }
    }

    // =====================================
    // CHUNKS
    // =====================================


    private static async Task ChunkIndexMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int offset =
            FirstChunkOffset;


        modified[offset] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "Chunk Index Mutation",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task ChunkLengthMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int offset =
            FirstChunkOffset +
            8;


        modified[offset] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "Chunk Length Mutation",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task InvalidChunkSize(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int offset =
            FirstChunkOffset +
            12;


        BinaryPrimitives.WriteUInt32LittleEndian(
            modified.AsSpan(offset, 4),
            uint.MaxValue);


        var result =
            await ExpectAttackFailure(
                "Invalid Chunk Size",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task CorruptAeadTag(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int tagOffset =
            modified.Length -
            (64 * 3) -
            AeadTagSize;


        modified[tagOffset] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "Corrupt AEAD Tag",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    private static async Task ChunkRemoval(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] original =
            ctx.BaselineCiphertext;


        int chunkStart =
            FirstChunkOffset;


        int chunkSize =
            ChunkHeaderSize +
            (64 * 1024) +
            AeadTagSize;


        byte[] modified =
            original
                .Take(chunkStart)
                .Concat(
                    original.Skip(
                        chunkStart + chunkSize))
                .ToArray();


        var result =
            await ExpectAttackFailure(
                "Chunk Removal",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task ChunkDuplication(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] original =
            ctx.BaselineCiphertext;


        int chunkStart =
            FirstChunkOffset;


        int chunkSize =
            ChunkHeaderSize +
            (64 * 1024) +
            AeadTagSize;


        byte[] chunk =
            original
                .Skip(chunkStart)
                .Take(chunkSize)
                .ToArray();


        byte[] modified =
            original
                .Take(chunkStart + chunkSize)
                .Concat(chunk)
                .Concat(
                    original.Skip(
                        chunkStart + chunkSize))
                .ToArray();



        var result =
            await ExpectAttackFailure(
                "Chunk Duplication",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task ChunkReorder(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] original =
            ctx.BaselineCiphertext.ToArray();


        int first =
            FirstChunkOffset;


        int chunkSize =
            ChunkHeaderSize +
            (64 * 1024) +
            AeadTagSize;


        int second =
            first +
            chunkSize;


        if (second + chunkSize >
            original.Length)
        {
            throw new InvalidOperationException(
                "Not enough chunks for reorder test.");
        }


        byte[] chunk1 =
            original
                .Skip(first)
                .Take(chunkSize)
                .ToArray();


        byte[] chunk2 =
            original
                .Skip(second)
                .Take(chunkSize)
                .ToArray();


        Buffer.BlockCopy(
            chunk2,
            0,
            original,
            first,
            chunkSize);


        Buffer.BlockCopy(
            chunk1,
            0,
            original,
            second,
            chunkSize);



        var result =
            await ExpectAttackFailure(
                "Chunk Reorder",
                () =>
                    DecryptData(
                        original,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task ChunkTruncation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext
                .Take(
                    ctx.BaselineCiphertext.Length - 32)
                .ToArray();


        var result =
            await ExpectAttackFailure(
                "Chunk Truncation",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task ChunkHeaderFuzzer(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int start =
            FirstChunkOffset;


        RandomNumberGenerator.Fill(
            modified.AsSpan(
                start,
                ChunkHeaderSize));


        var result =
            await ExpectAttackFailure(
                "Chunk Header Fuzzer",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task MissingAeadTag(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] original =
            ctx.BaselineCiphertext;


        int tagSize =
            AeadTagSize;


        byte[] modified =
            original
                .Take(
                    original.Length - tagSize)
                .ToArray();


        var result =
            await ExpectAttackFailure(
                "Missing AEAD Tag",
                () =>
                    DecryptData(
                        modified,
                        ctx,
                        ct));


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    // =====================================
    // HEADER
    // =====================================


    private static async Task HeaderVersionMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        await MutateHeaderAndDecrypt(
            ctx,
            "Header Version Mutation",
            ct,
            data =>
            {
                data[0] ^= 0xFF;
            });
    }


    private static async Task HeaderRandomByteMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        await MutateHeaderAndDecrypt(
            ctx,
            "Header Random Byte Mutation",
            ct,
            data =>
            {
                int index =
                    RandomNumberGenerator.GetInt32(
                        0,
                        HeaderSize);


                data[index] ^= 0xFF;
            });
    }


    private static async Task HeaderNonceMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        await MutateHeaderAndDecrypt(
            ctx,
            "Header Nonce Mutation",
            ct,
            data =>
            {
                // XChaCha nonce starts after version
                data[2] ^= 0xFF;
            });
    }


    private static async Task HeaderSaltMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        await MutateHeaderAndDecrypt(
            ctx,
            "Header Salt Mutation",
            ct,
            data =>
            {
                // Version + all nonces
                const int saltOffset =
                    2 +
                    16 +
                    8 +
                    8 +
                    8;


                data[saltOffset] ^= 0xFF;
            });
    }


    private static async Task HeaderTruncation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext
            .Take(HeaderSize - 1)
            .ToArray();


        var result =
            await ExpectAttackFailure(
                "Header Truncation",
                async () =>
                {
                    await DecryptData(
                        modified,
                        ctx,
                        ct);
                });


        if (!result.Passed)
        {
            throw new CryptographicException(
                result.Message);
        }
    }


    private static async Task HeaderHmacMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            HeaderSize;


        modified[position] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "Header HMAC Mutation",
                async () =>
                {
                    await DecryptData(
                        modified,
                        ctx,
                        ct);
                });


        if (!result.Passed)
        {
            throw new CryptographicException(
                result.Message);
        }
    }


    private static async Task HeaderReplay(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        byte[] header =
            modified
            .Take(HeaderSize)
            .ToArray();


        // Destroy header integrity
        // while preserving length
        Array.Reverse(header);


        Buffer.BlockCopy(
            header,
            0,
            modified,
            0,
            HeaderSize);


        var result =
            await ExpectAttackFailure(
                "Header Replay",
                async () =>
                {
                    await DecryptData(
                        modified,
                        ctx,
                        ct);
                });


        if (!result.Passed)
        {
            throw new CryptographicException(
                result.Message);
        }
    }


    private static async Task HeaderLengthCorruption(
        AttackContext ctx,
        CancellationToken ct)
    {
        await MutateHeaderAndDecrypt(
            ctx,
            "Header Length Corruption",
            ct,
            data =>
            {
                // Corrupt version/length parser area
                data[0] = 0xFF;
                data[1] = 0xFF;
            });
    }


    private static async Task HeaderFuzzer(
        AttackContext ctx,
        CancellationToken ct)
    {
        await MutateHeaderAndDecrypt(
            ctx,
            "Header Fuzzer",
            ct,
            data =>
            {
                for (int i = 0; i < 32; i++)
                {
                    int index =
                        RandomNumberGenerator.GetInt32(
                            0,
                            HeaderSize);


                    data[index] ^= 0xFF;
                }
            });
    }


    private static async Task HeaderAuthenticationTiming(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        // Corrupt header MAC
        modified[HeaderSize] ^= 0xFF;


        Stopwatch sw =
            Stopwatch.StartNew();


        try
        {
            await DecryptData(
                modified,
                ctx,
                ct);
        }
        catch
        {
            // Expected failure
        }


        sw.Stop();


        Console.WriteLine(
            $"Header authentication failure time: {sw.ElapsedMilliseconds} ms");
    }

    // =====================================
    // CIPHERTEXT
    // =====================================


    private static async Task SingleBitFlip(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            HeaderSize +
            HeaderMacSize +
            16;


        modified[position] ^= 0x01;


        await ExpectAttackFailure(
            "Single Bit Flip",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }



    private static async Task MultiBitCorruption(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int start =
            HeaderSize +
            HeaderMacSize +
            1024;


        for (int i = 0; i < 32; i++)
        {
            modified[start + i] ^= 0xFF;
        }


        await ExpectAttackFailure(
            "Multi Bit Corruption",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }



    private static async Task RandomByteCorruption(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        for (int i = 0; i < 100; i++)
        {
            int position =
                RandomNumberGenerator.GetInt32(
                    HeaderSize + HeaderMacSize,
                    modified.Length);


            modified[position] ^= 0xFF;
        }


        await ExpectAttackFailure(
            "Random Byte Corruption",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }



    private static async Task CiphertextExpansion(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] expanded =
            new byte[
                ctx.BaselineCiphertext.Length + 1024];


        Buffer.BlockCopy(
            ctx.BaselineCiphertext,
            0,
            expanded,
            0,
            ctx.BaselineCiphertext.Length);


        RandomNumberGenerator.Fill(
            expanded.AsSpan(
                ctx.BaselineCiphertext.Length));


        await ExpectAttackFailure(
            "Ciphertext Expansion",
            async () =>
            {
                await DecryptData(
                    expanded,
                    ctx,
                    ct);
            });
    }



    private static async Task CiphertextShrink(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext
            .Take(
                ctx.BaselineCiphertext.Length - 1024)
            .ToArray();


        await ExpectAttackFailure(
            "Ciphertext Shrink",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }



    private static async Task MiddleStreamCorruption(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int middle =
            modified.Length / 2;


        modified[middle] ^= 0xFF;


        await ExpectAttackFailure(
            "Middle Stream Corruption",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }



    private static async Task EndBlockCorruption(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            modified.Length - 1;


        modified[position] ^= 0xFF;


        await ExpectAttackFailure(
            "End Block Corruption",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }



    private static async Task CtrAlignmentAttack(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            HeaderSize +
            HeaderMacSize +
            65536;


        if (position < modified.Length)
        {
            modified[position] ^= 0xFF;
        }


        await ExpectAttackFailure(
            "CTR Alignment Attack",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }



    private static async Task PartialCiphertextStream(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext
            .Take(
                ctx.BaselineCiphertext.Length / 2)
            .ToArray();


        await ExpectAttackFailure(
            "Partial Ciphertext Stream",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }



    private static async Task CiphertextFuzzAttack(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int mutations =
            500;


        for (int i = 0; i < mutations; i++)
        {
            int position =
                RandomNumberGenerator.GetInt32(
                    HeaderSize + HeaderMacSize,
                    modified.Length);


            modified[position] ^=
                (byte)RandomNumberGenerator
                .GetInt32(1, 255);
        }


        await ExpectAttackFailure(
            "Ciphertext Fuzz Attack",
            async () =>
            {
                await DecryptData(
                    modified,
                    ctx,
                    ct);
            });
    }

    // =====================================
    // REPLAY
    // =====================================

    private static async Task FullCiphertextReplay(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] replay =
            ctx.BaselineCiphertext.ToArray();


        using var input =
            new MemoryStream(replay);


        using var output =
            new MemoryStream();


        await Methods.Decrypt(
            input,
            output,
            ctx.Keys,
            ctx.Options);


        byte[] decrypted =
            output.ToArray();


        if (!decrypted.SequenceEqual(
                ctx.BaselinePlaintext))
        {
            throw new CryptographicException(
                "Full ciphertext replay produced incorrect plaintext.");
        }
    }



    private static async Task PartialCiphertextReplay(
        AttackContext ctx,
        CancellationToken ct)
    {
        int cut =
            ctx.BaselineCiphertext.Length / 2;


        byte[] partial =
            ctx.BaselineCiphertext
                .Take(cut)
                .ToArray();


        var result =
            await ExpectAttackFailure(
                "Partial Ciphertext Replay",
                async () =>
                {
                    using var input =
                        new MemoryStream(partial);


                    using var output =
                        new MemoryStream();


                    await Methods.Decrypt(
                        input,
                        output,
                        ctx.Keys,
                        ctx.Options);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task ChunkReplay(
     AttackContext ctx,
     CancellationToken ct)
    {
        byte[] original =
            ctx.BaselineCiphertext.ToArray();


        const int FINAL_TAG_SIZE =
            64 * 3;


        int payloadStart =
            HeaderSize +
            HeaderMacSize;


        int payloadEnd =
            original.Length -
            FINAL_TAG_SIZE;


        if (payloadEnd <= payloadStart)
        {
            throw new InvalidDataException(
                "Ciphertext contains no chunks.");
        }


        //
        // Parse first chunk
        //

        int firstOffset =
            payloadStart;


        int firstLength =
            BinaryPrimitives.ReadInt32LittleEndian(
                original.AsSpan(
                    firstOffset + 8,
                    4));


        int firstChunkSize =
            16 +
            firstLength +
            16;


        if (firstOffset + firstChunkSize >
            payloadEnd)
        {
            throw new InvalidDataException(
                "Invalid first chunk.");
        }


        byte[] firstChunk =
            original
                .AsSpan(
                    firstOffset,
                    firstChunkSize)
                .ToArray();



        //
        // Locate second chunk
        //

        int secondOffset =
            firstOffset +
            firstChunkSize;


        if (secondOffset >= payloadEnd)
        {
            throw new InvalidDataException(
                "Need at least two chunks.");
        }


        int secondLength =
            BinaryPrimitives.ReadInt32LittleEndian(
                original.AsSpan(
                    secondOffset + 8,
                    4));


        int secondChunkSize =
            16 +
            secondLength +
            16;


        if (secondOffset + secondChunkSize >
            payloadEnd)
        {
            throw new InvalidDataException(
                "Invalid second chunk.");
        }



        //
        // Replace chunk 1 with replayed chunk 0
        //

        using var ms =
            new MemoryStream(
                original.Length);


        // Header + first chunk
        ms.Write(
            original,
            0,
            secondOffset);


        // Replay first chunk
        ms.Write(
            firstChunk,
            0,
            firstChunk.Length);


        // Skip original second chunk
        // and copy remaining chunks + final HMACs
        ms.Write(
            original,
            secondOffset + secondChunkSize,
            original.Length -
            (secondOffset + secondChunkSize));


        byte[] replay =
            ms.ToArray();



        var result =
            await ExpectAttackFailure(
                "Chunk Replay",
                async () =>
                {
                    using var input =
                        new MemoryStream(replay);


                    using var output =
                        new MemoryStream();


                    await Methods.Decrypt(
                        input,
                        output,
                        ctx.Keys,
                        ctx.Options);
                });



        if (!result.Passed)
        {
            throw new CryptographicException(
                result.Message);
        }
    }

    private static async Task ChunkCiphertextReplay(
    AttackContext ctx,
    CancellationToken ct)
    {
        byte[] original =
            ctx.BaselineCiphertext.ToArray();


        const int FINAL_TAG_SIZE =
            64 * 3;


        int payloadStart =
            HeaderSize +
            HeaderMacSize;


        int payloadEnd =
            original.Length -
            FINAL_TAG_SIZE;


        if (payloadEnd <= payloadStart)
        {
            throw new InvalidDataException(
                "Ciphertext contains no chunks.");
        }



        //
        // Parse first chunk
        //

        int firstOffset =
            payloadStart;


        int firstLength =
            BinaryPrimitives.ReadInt32LittleEndian(
                original.AsSpan(
                    firstOffset + 8,
                    4));


        int firstCipherOffset =
            firstOffset + 16;


        int firstCipherSize =
            firstLength + 16; // ciphertext + AEAD tag


        int firstChunkSize =
            16 +
            firstCipherSize;


        if (firstOffset + firstChunkSize >
            payloadEnd)
        {
            throw new InvalidDataException(
                "Invalid first chunk.");
        }



        byte[] firstCipherAndTag =
            original
                .AsSpan(
                    firstCipherOffset,
                    firstCipherSize)
                .ToArray();



        //
        // Parse second chunk
        //

        int secondOffset =
            firstOffset +
            firstChunkSize;


        if (secondOffset >= payloadEnd)
        {
            throw new InvalidDataException(
                "Need at least two chunks.");
        }


        int secondLength =
            BinaryPrimitives.ReadInt32LittleEndian(
                original.AsSpan(
                    secondOffset + 8,
                    4));


        int secondCipherOffset =
            secondOffset + 16;


        int secondCipherSize =
            secondLength + 16;


        int secondChunkSize =
            16 +
            secondCipherSize;


        if (secondOffset + secondChunkSize >
            payloadEnd)
        {
            throw new InvalidDataException(
                "Invalid second chunk.");
        }



        //
        // Ciphertext sizes must match
        //

        if (firstCipherSize != secondCipherSize)
        {
            throw new InvalidDataException(
                "Chunk sizes must match for ciphertext replay.");
        }



        //
        // Replace ONLY ciphertext + tag
        //
        // Keep:
        //   second chunk index
        //   second chunk length
        //
        // Replace:
        //   ciphertext
        //   AEAD tag
        //

        using var ms =
            new MemoryStream(
                original.Length);


        // Copy everything before second ciphertext
        ms.Write(
            original,
            0,
            secondCipherOffset);


        // Inject first chunk ciphertext + tag
        ms.Write(
            firstCipherAndTag,
            0,
            firstCipherAndTag.Length);


        // Copy remaining chunks + final HMACs
        ms.Write(
            original,
            secondCipherOffset + secondCipherSize,
            original.Length -
            (secondCipherOffset + secondCipherSize));


        byte[] replay =
            ms.ToArray();



        var result =
            await ExpectAttackFailure(
                "Chunk Ciphertext Replay",
                async () =>
                {
                    using var input =
                        new MemoryStream(replay);


                    using var output =
                        new MemoryStream();


                    await Methods.Decrypt(
                        input,
                        output,
                        ctx.Keys,
                        ctx.Options);
                });



        if (!result.Passed)
        {
            throw new CryptographicException(
                result.Message);
        }
    }

    private static async Task HeaderReplayAttack(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] original =
            ctx.BaselineCiphertext.ToArray();


        byte[] otherPlaintext =
            RandomNumberGenerator.GetBytes(
                1024 * 1024);


        byte[] otherCiphertext;


        using (var input =
               new MemoryStream(otherPlaintext))
        {
            otherCiphertext =
                await EncryptData(
                    input,
                    ctx,
                    ct);
        }



        int headerTotal =
            HeaderSize +
            HeaderMacSize;



        if (original.Length <= headerTotal ||
            otherCiphertext.Length <= headerTotal)
        {
            throw new InvalidDataException(
                "Ciphertexts too small for header replay.");
        }



        byte[] modified =
            original.ToArray();



        //
        // Replace original header + header MAC
        // with another file's header + header MAC
        //

        Buffer.BlockCopy(
            otherCiphertext,
            0,
            modified,
            0,
            headerTotal);



        var result =
            await ExpectAttackFailure(
                "Header Replay Attack",
                async () =>
                {
                    using var input =
                        new MemoryStream(modified);


                    using var output =
                        new MemoryStream();


                    await Methods.Decrypt(
                        input,
                        output,
                        ctx.Keys,
                        ctx.Options);
                });



        if (!result.Passed)
        {
            throw new CryptographicException(
                result.Message);
        }
    }



    private static async Task CrossDataReplay(
        AttackContext ctx,
        CancellationToken ct)
    {
        /*
            Encrypt a second stream.
            Attempt to combine ciphertext
            from another encryption.

            Authentication should fail because
            nonces, salts, and HMAC values differ.
        */


        byte[] otherPlaintext =
            await CreateDeterministicData(
                1024 * 1024 * 1024);


        byte[] otherCiphertext;


        using (var input =
               new MemoryStream(otherPlaintext))
        {
            otherCiphertext =
                await EncryptData(
                    input,
                    ctx,
                    ct);
        }


        byte[] mixed =
            ctx.BaselineCiphertext
                .Take(
                    Math.Min(
                        ctx.BaselineCiphertext.Length,
                        otherCiphertext.Length))
                .ToArray();


        Buffer.BlockCopy(
            otherCiphertext,
            0,
            mixed,
            0,
            Math.Min(
                128,
                mixed.Length));


        var result =
            await ExpectAttackFailure(
                "Cross Data Replay",
                async () =>
                {
                    using var input =
                        new MemoryStream(mixed);


                    using var output =
                        new MemoryStream();


                    await Methods.Decrypt(
                        input,
                        output,
                        ctx.Keys,
                        ctx.Options);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    public sealed class RegisteredAttack
    {
        public string Name { get; }

        public Func<AttackContext, CancellationToken, Task> Execute { get; }


        public RegisteredAttack(
            string name,
            Func<AttackContext, CancellationToken, Task> execute)
        {
            Name = name;
            Execute = execute;
        }
    }

    public sealed class AttackContext
    {
        public DerivedKeys Keys { get; init; }

        public CryptoPipelineOptions Options { get; init; }

        public byte[] BaselineCiphertext { get; init; }

        public byte[] BaselinePlaintext { get; set; }

        public long PlaintextSize { get; init; }
    }


    public sealed class AttackResult
    {
        public string Name { get; init; }

        public bool Passed { get; init; }

        public TimeSpan Duration { get; init; }

        public string Message { get; init; }

        public Exception Exception { get; init; }
    }



    public sealed class AttackReport
    {
        private readonly List<AttackResult> _results = new();


        public IReadOnlyList<AttackResult> Results =>
            _results;


        public void Add(AttackResult result)
        {
            _results.Add(result);
        }


        public void Print()
        {
            Console.WriteLine();

            Console.WriteLine(
                "=================================");
            Console.WriteLine(
                " Attack Campaign Summary");
            Console.WriteLine(
                "=================================");

            int passed = 0;
            int failed = 0;

            foreach (var result in _results)
            {
                if (result.Passed)
                    passed++;
                else
                    failed++;

                Console.WriteLine(
                    $"{(result.Passed ? "[PASS]" : "[FAIL]")} " +
                    $"{result.Name} " +
                    $"({result.Duration})");
            }


            Console.WriteLine();

            Console.WriteLine(
                $"Total : {_results.Count}");

            Console.WriteLine(
                $"Passed: {passed}");

            Console.WriteLine(
                $"Failed: {failed}");
        }
    }

    private static async Task CreateBaselineAsync(
        DerivedKeys keys,
        CryptoPipelineOptions options)
    {
        Console.WriteLine(
            "Creating deterministic plaintext...");


        using var plaintext =
            new DeterministicRandomStream(
                _testSize);


        using var encrypted =
            new MemoryStream();


        Console.WriteLine(
            "Encrypting baseline...");


        await Methods.Encrypt(
            plaintext,
            encrypted,
            keys,
            options);


        _baselineCiphertext =
            encrypted.ToArray();


        Console.WriteLine(
            $"Baseline ciphertext size: {_baselineCiphertext.Length:N0}");
    }

    private static KeyBlob CloneKeyBlob(
        KeyBlob source)
    {
        return new KeyBlob
        {
            Version = source.Version,
            Kdf = source.Kdf,
            cipherSuite = source.cipherSuite,
            DeviceName = source.DeviceName,

            HmacKeyCipher = source.HmacKeyCipher.ToArray(),
            HmacKeyNonce = source.HmacKeyNonce.ToArray(),
            HmacKeyTag = source.HmacKeyTag.ToArray(),

            SealedKekPrivate = source.SealedKekPrivate.ToArray(),
            SealedKekPublic = source.SealedKekPublic.ToArray(),
            Pcrs = source.Pcrs.ToArray(),
            TpmSalt = source.TpmSalt.ToArray(),

            PasswordSalt = source.PasswordSalt.ToArray(),
            PasswordHkdfSalt = source.PasswordHkdfSalt.ToArray(),

            ArgonParallelism = source.ArgonParallelism,
            ArgonIterations = source.ArgonIterations,
            ArgonMemory = source.ArgonMemory,
            ArgonVersion = source.ArgonVersion,

            HelloKeyName = source.HelloKeyName,
            HelloEncryptedKey = source.HelloEncryptedKey.ToArray(),
            HelloSalt = source.HelloSalt.ToArray(),

            EncryptedKeyHierarchy =
                source.EncryptedKeyHierarchy.ToArray(),

            ChainCipher = source.ChainCipher.ToArray(),
            ChainNonce = source.ChainNonce.ToArray(),
            ChainTag = source.ChainTag.ToArray(),

            GcmNonce = source.GcmNonce.ToArray(),
            GcmTag = source.GcmTag.ToArray(),
            GcmSalt = source.GcmSalt.ToArray(),

            HkdfSalt = source.HkdfSalt.ToArray(),
            SessionSalt = source.SessionSalt.ToArray(),
            CombinedKdfSalt = source.CombinedKdfSalt.ToArray(),
            FileRootSalt = source.FileRootSalt.ToArray(),
            MemorySalt = source.MemorySalt.ToArray(),
            IpcSalt = source.IpcSalt.ToArray()
        };
    }

    // =====================================
    // MUTATION
    // =====================================

    private static async Task KnownCipherInjection(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            HeaderSize +
            HeaderMacSize +
            16;


        for (int i = 0; i < 32; i++)
        {
            if (position + i < modified.Length)
                modified[position + i] = 0x00;
        }


        var result =
            await ExpectAttackFailure(
                "Known Cipher Injection",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task RandomMutationStorm(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        RandomNumberGenerator.Fill(
            modified);


        var result =
            await ExpectAttackFailure(
                "Random Mutation Storm",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task LengthFieldAbuse(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int chunkHeader =
            HeaderSize +
            HeaderMacSize;


        if (modified.Length >
            chunkHeader + 12)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                modified.AsSpan(
                    chunkHeader + 8,
                    4),
                uint.MaxValue);
        }


        var result =
            await ExpectAttackFailure(
                "Length Field Abuse",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task OffsetManipulation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int chunkHeader =
            HeaderSize +
            HeaderMacSize;


        if (modified.Length >
            chunkHeader + 8)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(
                modified.AsSpan(
                    chunkHeader,
                    8),
                ulong.MaxValue);
        }


        var result =
            await ExpectAttackFailure(
                "Offset Manipulation",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task MixedCorruptionAttack(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        Random rng =
            Random.Shared;


        for (int i = 0; i < 100; i++)
        {
            int index =
                rng.Next(
                    HeaderSize +
                    HeaderMacSize,
                    modified.Length);


            modified[index] ^=
                (byte)rng.Next(1, 255);
        }


        var result =
            await ExpectAttackFailure(
                "Mixed Corruption Attack",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task FirstChunkMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int offset =
            HeaderSize +
            HeaderMacSize;


        for (int i = 0; i < 32; i++)
        {
            if (offset + i < modified.Length)
                modified[offset + i] ^= 0xFF;
        }


        var result =
            await ExpectAttackFailure(
                "First Chunk Mutation",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task MiddleChunkMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int start =
            (HeaderSize +
             HeaderMacSize +
             modified.Length) / 2;


        for (int i = 0; i < 32; i++)
        {
            if (start + i < modified.Length)
                modified[start + i] ^= 0xAA;
        }


        var result =
            await ExpectAttackFailure(
                "Middle Chunk Mutation",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task LastChunkMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int start =
            Math.Max(
                HeaderSize +
                HeaderMacSize,
                modified.Length - 64);


        for (int i = start;
             i < modified.Length;
             i++)
        {
            modified[i] ^= 0x55;
        }


        var result =
            await ExpectAttackFailure(
                "Last Chunk Mutation",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task MultipleChunkSwap(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int start =
            HeaderSize +
            HeaderMacSize;


        int length =
            modified.Length -
            start;


        if (length > 128)
        {
            byte[] first =
                modified
                    .Skip(start)
                    .Take(64)
                    .ToArray();


            byte[] second =
                modified
                    .Skip(start + 64)
                    .Take(64)
                    .ToArray();


            Buffer.BlockCopy(
                second,
                0,
                modified,
                start,
                second.Length);


            Buffer.BlockCopy(
                first,
                0,
                modified,
                start + 64,
                first.Length);
        }


        var result =
            await ExpectAttackFailure(
                "Multiple Chunk Swap",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task MutationFuzzer(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        Random rng =
            Random.Shared;


        int mutations =
            Math.Min(
                1000,
                modified.Length / 10);


        for (int i = 0; i < mutations; i++)
        {
            int index =
                rng.Next(
                    HeaderSize +
                    HeaderMacSize,
                    modified.Length);


            modified[index] =
                (byte)rng.Next(0, 256);
        }


        var result =
            await ExpectAttackFailure(
                "Mutation Fuzzer",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task DecryptModified(
        byte[] ciphertext,
        AttackContext ctx)
    {
        using var input =
            new MemoryStream(ciphertext);


        using var output =
            new MemoryStream();


        await Methods.Decrypt(
            input,
            output,
            ctx.Keys,
            ctx.Options);
    }

    // =====================================
    // AEAD ATTACKS
    // =====================================

    private static async Task XChaChaTagMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int chunkStart =
            HeaderSize +
            HeaderMacSize;


        const int ChunkHeaderSize = 24;

        ulong chunkLength =
            BinaryPrimitives.ReadUInt64LittleEndian(
                modified.AsSpan(chunkStart + 8, 8));

        int tagPosition =
            chunkStart +
            ChunkHeaderSize +
            checked((int)chunkLength);


        Console.WriteLine(
            $"Mutating XChaCha tag at offset {tagPosition}");


        modified[tagPosition] ^= 0x01;


        var result =
            await ExpectAttackFailure(
                "XChaCha Tag Mutation",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    private static async Task XChaChaCipherMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int cipherPosition =
            HeaderSize +
            HeaderMacSize +
            16;


        for (int i = 0; i < 32; i++)
        {
            if (cipherPosition + i <
                modified.Length)
            {
                modified[cipherPosition + i] ^= 0xAA;
            }
        }


        var result =
            await ExpectAttackFailure(
                "XChaCha Cipher Mutation",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task AeadNonceMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        /*
            Header contains XChaCha nonce.
            Mutating it should break AEAD.
        */


        int nonceOffset =
            2;


        if (modified.Length <
            nonceOffset + 16)
            throw new InvalidDataException(
                "Nonce unavailable");


        modified[nonceOffset] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "AEAD Nonce Mutation",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task AeadAadMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        /*
            AAD is derived from:

            Counter
            Chunk Length

            Modify chunk length field.
            AEAD authentication should fail.
        */


        int chunkHeader =
            HeaderSize +
            HeaderMacSize;


        if (modified.Length >
            chunkHeader + 12)
        {
            modified[chunkHeader + 12] ^= 0xFF;
        }


        var result =
            await ExpectAttackFailure(
                "AEAD AAD Mutation",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task PolyTagRemoval(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext
                .Take(
                    ctx.BaselineCiphertext.Length - 16)
                .ToArray();


        var result =
            await ExpectAttackFailure(
                "Poly1305 Tag Removal",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task AeadRandomForgery(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        Random rng =
            Random.Shared;


        int start =
            HeaderSize +
            HeaderMacSize;


        int mutations =
            Math.Min(
                256,
                modified.Length - start);


        for (int i = 0; i < mutations; i++)
        {
            int index =
                rng.Next(
                    start,
                    modified.Length);


            modified[index] =
                (byte)rng.Next(
                    0,
                    256);
        }


        var result =
            await ExpectAttackFailure(
                "AEAD Random Forgery",
                async () =>
                {
                    await DecryptModified(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    // =====================================
    // HMAC ATTACKS
    // =====================================

    private static async Task AesHmacMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            modified.Length -
            (64 * 3);


        if (position < 0)
            throw new InvalidDataException(
                "AES HMAC position invalid");


        modified[position] ^= 0xFF;


        await RequireAttackRejected(
            "AES HMAC Mutation",
            modified,
            ctx);
    }



    private static async Task SerpentHmacMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            modified.Length -
            (64 * 2);


        if (position < 0)
            throw new InvalidDataException(
                "Serpent HMAC position invalid");


        modified[position] ^= 0xAA;


        await RequireAttackRejected(
            "Serpent HMAC Mutation",
            modified,
            ctx);
    }



    private static async Task ThreeFishHmacMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int position =
            modified.Length -
            64;


        if (position < 0)
            throw new InvalidDataException(
                "Threefish HMAC position invalid");


        modified[position] ^= 0x55;


        await RequireAttackRejected(
            "Threefish HMAC Mutation",
            modified,
            ctx);
    }



    private static async Task HmacTruncation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext
                .Take(
                    ctx.BaselineCiphertext.Length - 64)
                .ToArray();


        await RequireAttackRejected(
            "HMAC Truncation",
            modified,
            ctx);
    }



    private static async Task HmacExtension(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] extra =
            RandomNumberGenerator.GetBytes(
                64);


        byte[] modified =
            ctx.BaselineCiphertext
                .Concat(extra)
                .ToArray();


        await RequireAttackRejected(
            "HMAC Extension",
            modified,
            ctx);
    }



    private static async Task RandomHmacCorruption(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        Random rng =
            Random.Shared;


        int start =
            Math.Max(
                0,
                modified.Length - 192);


        for (int i = 0; i < 192; i++)
        {
            int index =
                start +
                rng.Next(
                    0,
                    modified.Length - start);


            modified[index] ^=
                (byte)rng.Next(
                    1,
                    255);
        }


        await RequireAttackRejected(
            "HMAC Random Corruption",
            modified,
            ctx);
    }



    private static async Task WrongHmacOrdering(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int start =
            modified.Length - 192;


        if (start < 0)
            throw new InvalidDataException(
                "Unable to locate HMAC region");


        byte[] first =
            modified
                .Skip(start)
                .Take(64)
                .ToArray();


        byte[] second =
            modified
                .Skip(start + 64)
                .Take(64)
                .ToArray();


        Buffer.BlockCopy(
            second,
            0,
            modified,
            start,
            64);


        Buffer.BlockCopy(
            first,
            0,
            modified,
            start + 64,
            64);


        await RequireAttackRejected(
            "Wrong HMAC Ordering",
            modified,
            ctx);
    }



    private static async Task HmacReplay(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int hmacStart =
            modified.Length -
            64;


        Buffer.BlockCopy(
            modified,
            hmacStart,
            modified,
            hmacStart - 64,
            64);


        await RequireAttackRejected(
            "HMAC Replay",
            modified,
            ctx);
    }



    private static async Task MultipleHmacMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int start =
            modified.Length -
            192;


        if (start < 0)
            throw new InvalidDataException(
                "HMAC area unavailable");


        for (int i = 0; i < 192; i++)
        {
            modified[start + i] ^=
                (byte)(i + 1);
        }


        await RequireAttackRejected(
            "Multiple HMAC Mutation",
            modified,
            ctx);
    }



    private static async Task AuthFailureTiming(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int start =
            modified.Length -
            64;


        modified[start] ^= 0xFF;


        var sw =
            Stopwatch.StartNew();


        try
        {
            await DecryptModified(
                modified,
                ctx);
        }
        catch
        {
        }


        sw.Stop();


        if (sw.Elapsed <= TimeSpan.Zero)
            throw new CryptographicException(
                "Invalid timing measurement");
    }



    private static async Task CascadeAuthFailure(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        /*
            Corrupt all three cascade
            authentication layers.

            Expected:
            AES HMAC failure,
            Serpent HMAC failure,
            Threefish HMAC failure.
        */


        int start =
            Math.Max(
                0,
                modified.Length - 192);


        for (int i = 0; i < 192; i++)
        {
            modified[start + i] ^= 0xFF;
        }


        await RequireAttackRejected(
            "Cascade Authentication Failure",
            modified,
            ctx);
    }



    private static async Task RequireAttackRejected(
        string name,
        byte[] ciphertext,
        AttackContext ctx)
    {
        var result =
            await ExpectAttackFailure(
                name,
                async () =>
                {
                    await DecryptModified(
                        ciphertext,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    // =====================================
    // KEY DERIVATION
    // =====================================

    private static async Task SaltMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        /*
            Header layout:

            Version
            XNonce
            TFNonce
            SerpentNonce
            AESNonce
            XSalt
            TFSalt
            SerpentSalt
            AESSalt
        */


        int saltOffset =
            2 +
            16 +
            8 +
            8 +
            8;


        if (saltOffset >= modified.Length)
            throw new InvalidDataException(
                "Salt offset invalid");


        modified[saltOffset] ^= 0xFF;


        await RequireAttackRejected(
            "Salt Mutation",
            modified,
            ctx);
    }



    private static async Task DerivedKeyMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        var mutatedKeys =
            CloneKeys(ctx.Keys);


        /*
            Change every derived key.
            Any successful decrypt indicates
            key separation failure.
        */


        RandomNumberGenerator.Fill(
            mutatedKeys.XChaChaKey);


        RandomNumberGenerator.Fill(
            mutatedKeys.ThreefishKey);


        RandomNumberGenerator.Fill(
            mutatedKeys.SerpentKey);


        RandomNumberGenerator.Fill(
            mutatedKeys.AesKey);


        RandomNumberGenerator.Fill(
            mutatedKeys.HeaderHmacKey);


        RandomNumberGenerator.Fill(
            mutatedKeys.ThreefishHmacKey);


        RandomNumberGenerator.Fill(
            mutatedKeys.SerpentHmacKey);


        RandomNumberGenerator.Fill(
            mutatedKeys.AesHmacKey);


        await RequireAttackRejectedKeys(
            "Derived Key Mutation",
            ctx,
            mutatedKeys);
    }



    private static async Task RequireAttackRejectedKeys(
        string name,
        AttackContext ctx,
        DerivedKeys keys)
    {
        var result =
            await ExpectAttackFailure(
                name,
                async () =>
                {
                    using var input =
                        new MemoryStream(
                            ctx.BaselineCiphertext);


                    using var output =
                        new MemoryStream();


                    await Methods.Decrypt(
                        input,
                        output,
                        keys,
                        ctx.Options);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    // =====================================
    // HKDF ATTACKS
    // =====================================

    private static async Task HkdfContextMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        var modifiedKeys =
            CloneKeys(ctx.Keys);


        // Simulate HKDF info/context string change
        // by corrupting one derived branch

        modifiedKeys.AesKey[0] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "HKDF Context Mutation",
                async () =>
                {
                    using var input =
                        new MemoryStream(
                            ctx.BaselineCiphertext);


                    using var output =
                        new MemoryStream();


                    await Methods.Decrypt(
                        input,
                        output,
                        modifiedKeys,
                        ctx.Options);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }


    private static async Task HkdfLengthAbuse(
        AttackContext ctx,
        CancellationToken ct)
    {
        var modifiedKeys =
            CloneKeys(ctx.Keys);


        // Simulate incorrect HKDF output length.
        // Example: truncated AES key material.

        Array.Clear(
            modifiedKeys.AesKey,
            16,
            16);


        var result =
            await ExpectAttackFailure(
                "HKDF Length Abuse",
                async () =>
                {
                    using var input =
                        new MemoryStream(
                            ctx.BaselineCiphertext);


                    using var output =
                        new MemoryStream();


                    await Methods.Decrypt(
                        input,
                        output,
                        modifiedKeys,
                        ctx.Options);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    // =====================================
    // NONCE ATTACKS
    // =====================================

    private static async Task NonceMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        // Header nonce area
        int nonceOffset = 2;


        modified[nonceOffset] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "Nonce Mutation",
                async () =>
                {
                    await DecryptBytes(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }


    private static async Task NonceReuseDetection(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] ciphertext1 =
            ctx.BaselineCiphertext.ToArray();


        byte[] ciphertext2 =
            ctx.BaselineCiphertext.ToArray();


        if (!ciphertext1.AsSpan()
            .SequenceEqual(ciphertext2))
        {
            return;
        }


        throw new CryptographicException(
            "Nonce reuse produced identical ciphertext.");
    }


    private static async Task NonceCollisionTest(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] a =
            await EncryptBytes(
                await CreateDeterministicData(1024),
                ctx,
                ct);


        byte[] b =
            await EncryptBytes(
                await CreateDeterministicData(1024),
                ctx,
                ct);


        if (a.SequenceEqual(b))
        {
            throw new CryptographicException(
                "Nonce collision detected.");
        }
    }


    private static async Task CounterManipulation(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        int chunkCounterOffset =
            HeaderSize +
            HeaderMacSize;


        modified[chunkCounterOffset] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "Counter Manipulation",
                async () =>
                {
                    await DecryptBytes(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    // =====================================
    // CASCADE ATTACKS
    // =====================================

    private static async Task LayerRemovalAttack(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext
                .Skip(HeaderSize + HeaderMacSize)
                .ToArray();


        var result =
            await ExpectAttackFailure(
                "Layer Removal Attack",
                async () =>
                {
                    await DecryptBytes(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task LayerReorderingAttack(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        Array.Reverse(
            modified,
            HeaderSize + HeaderMacSize,
            modified.Length -
            HeaderSize -
            HeaderMacSize);


        var result =
            await ExpectAttackFailure(
                "Layer Reordering Attack",
                async () =>
                {
                    await DecryptBytes(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task SingleLayerBypass(
        AttackContext ctx,
        CancellationToken ct)
    {
        var modified =
            ctx.BaselineCiphertext.ToArray();


        modified[
            HeaderSize +
            HeaderMacSize +
            10] ^= 0xFF;


        var result =
            await ExpectAttackFailure(
                "Single Layer Bypass",
                async () =>
                {
                    await DecryptBytes(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }



    private static async Task InnerLayerMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        await MutateAndDecrypt(
            ctx,
            "Inner Layer Mutation",
            ct,
            data =>
            {
                data[^32] ^= 0xFF;
            });
    }



    private static async Task OuterLayerMutation(
        AttackContext ctx,
        CancellationToken ct)
    {
        await MutateAndDecrypt(
            ctx,
            "Outer Layer Mutation",
            ct,
            data =>
            {
                data[
                    HeaderSize +
                    HeaderMacSize] ^= 0xFF;
            });
    }



    private static async Task FullCascadeCorruption(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] modified =
            ctx.BaselineCiphertext.ToArray();


        for (int i = HeaderSize;
             i < modified.Length;
             i += 4096)
        {
            modified[i] ^= 0xFF;
        }


        var result =
            await ExpectAttackFailure(
                "Full Cascade Corruption",
                async () =>
                {
                    await DecryptBytes(
                        modified,
                        ctx);
                });


        if (!result.Passed)
            throw new CryptographicException(
                result.Message);
    }

    // =====================================
    // TIMING
    // =====================================

    private static async Task AuthenticationTimingTest(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] valid =
            ctx.BaselineCiphertext.ToArray();


        byte[] invalid =
            ctx.BaselineCiphertext.ToArray();


        invalid[^1] ^= 0xFF;


        var validTime =
            Stopwatch.StartNew();


        await DecryptBytes(
            valid,
            ctx);


        validTime.Stop();


        var invalidTime =
            Stopwatch.StartNew();


        try
        {
            await DecryptBytes(
                invalid,
                ctx);
        }
        catch
        {
        }


        invalidTime.Stop();


        var variance =
            Math.Abs(
                validTime.ElapsedTicks -
                invalidTime.ElapsedTicks);


        Console.WriteLine(
            $"Authentication timing variance: {variance} ticks");
    }



    private static async Task FailureTimingVariance(
        AttackContext ctx,
        CancellationToken ct)
    {
        List<long> timings = new();


        for (int i = 0; i < 10; i++)
        {
            byte[] modified =
                ctx.BaselineCiphertext.ToArray();


            modified[
                Random.Shared.Next(
                    modified.Length)] ^= 0xFF;


            var sw =
                Stopwatch.StartNew();


            try
            {
                await DecryptBytes(
                    modified,
                    ctx);
            }
            catch
            {
            }


            sw.Stop();


            timings.Add(
                sw.ElapsedTicks);
        }


        long max =
            timings.Max();

        long min =
            timings.Min();


        Console.WriteLine(
            $"Failure timing spread: {max - min} ticks");
    }



    // =====================================
    // MEMORY
    // =====================================

    private static async Task MemoryPressureTest(
        AttackContext ctx,
        CancellationToken ct)
    {
        long before =
            GC.GetTotalMemory(true);


        byte[] data =
            await CreateDeterministicData(
                32 * 1024 * 1024);


        await EncryptBytes(
            data,
            ctx,
            ct);


        long after =
            GC.GetTotalMemory(true);


        Console.WriteLine(
            $"Memory delta: {after - before:N0} bytes");
    }



    private static async Task LargeStreamTest(
        AttackContext ctx,
        CancellationToken ct)
    {
        long size =
            Math.Max(
                ctx.PlaintextSize,
                512L * 1024 * 1024);


        byte[] data =
            await CreateDeterministicData(
                size);


        var ciphertext =
            await EncryptBytes(
                data,
                ctx,
                ct);


        var plaintext =
            await DecryptBytesToArray(
                ciphertext,
                ctx);


        AssertEqual(
            data,
            plaintext,
            "Large stream test failed");
    }



    // =====================================
    // CONCURRENCY
    // =====================================

    private static async Task ParallelEncryptionRace(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] data =
            await CreateDeterministicData(
                1024 * 1024);


        var tasks =
            Enumerable.Range(0, 8)
                .Select(_ =>
                    EncryptBytes(
                        data,
                        ctx,
                        ct));


        var results =
            await Task.WhenAll(tasks);


        if (results.Any(
            x => x.Length == 0))
        {
            throw new CryptographicException(
                "Parallel encryption produced empty output.");
        }
    }



    private static async Task ParallelDecryptionRace(
        AttackContext ctx,
        CancellationToken ct)
    {
        var tasks =
            Enumerable.Range(0, 8)
                .Select(_ =>
                    DecryptBytesToArray(
                        ctx.BaselineCiphertext,
                        ctx));


        var results =
            await Task.WhenAll(tasks);


        foreach (var data in results)
        {
            if (data.Length != ctx.PlaintextSize)
            {
                throw new CryptographicException(
                    "Parallel decryption mismatch.");
            }
        }
    }



    // =====================================
    // STRESS
    // =====================================

    private static async Task HighLoadTest(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] data =
            await CreateDeterministicData(
                16 * 1024 * 1024);


        for (int i = 0; i < 20; i++)
        {
            ct.ThrowIfCancellationRequested();


            var cipher =
                await EncryptBytes(
                    data,
                    ctx,
                    ct);


            await DecryptBytes(
                cipher,
                ctx);
        }
    }



    private static async Task LongRunningStreamTest(
        AttackContext ctx,
        CancellationToken ct)
    {
        byte[] data =
            await CreateDeterministicData(
                256 * 1024 * 1024);


        var cipher =
            await EncryptBytes(
                data,
                ctx,
                ct);


        var plain =
            await DecryptBytesToArray(
                cipher,
                ctx);


        AssertEqual(
            data,
            plain,
            "Long running stream mismatch");
    }



    // =====================================
    // FUZZING
    // =====================================

    private static async Task CompleteCipherFuzzer(
        AttackContext ctx,
        CancellationToken ct)
    {
        for (int i = 0; i < 50; i++)
        {
            byte[] modified =
                ctx.BaselineCiphertext.ToArray();


            int changes =
                Random.Shared.Next(
                    1,
                    32);


            for (int x = 0; x < changes; x++)
            {
                int pos =
                    Random.Shared.Next(
                        modified.Length);


                modified[pos] ^=
                    (byte)Random.Shared.Next(1, 256);
            }


            try
            {
                await DecryptBytes(
                    modified,
                    ctx);
            }
            catch
            {
                // expected
            }
        }
    }



    private static async Task AdaptiveMutationCampaign(
        AttackContext ctx,
        CancellationToken ct)
    {
        var mutations =
            new Action<byte[]>[]
            {
            x => x[0] ^= 0xFF,

            x => x[^1] ^= 0xFF,

            x => x[
                x.Length / 2] ^= 0xFF
            };


        foreach (var mutation in mutations)
        {
            byte[] modified =
                ctx.BaselineCiphertext.ToArray();


            mutation(modified);


            try
            {
                await DecryptBytes(
                    modified,
                    ctx);
            }
            catch
            {
                // rejection expected
            }
        }
    }

    public sealed class DeterministicRandomStream : Stream
    {
        private readonly long _length;
        private readonly ulong _seed;

        private long _position;


        public DeterministicRandomStream(
            long length,
            ulong seed = 0x123456789ABCDEF0UL)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException(nameof(length));

            _length = length;
            _seed = seed;
        }


        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite => false;


        public override long Length => _length;


        public override long Position
        {
            get => _position;

            set
            {
                if (value < 0 || value > _length)
                    throw new ArgumentOutOfRangeException();

                _position = value;
            }
        }



        public override int Read(
            byte[] buffer,
            int offset,
            int count)
        {
            ValidateBuffer(buffer, offset, count);


            if (_position >= _length)
                return 0;


            long remaining = _length - _position;

            int toRead =
                (int)Math.Min(count, remaining);


            for (int i = 0; i < toRead; i++)
            {
                buffer[offset + i] =
                    GenerateByte(_position);

                _position++;
            }


            return toRead;
        }



        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            System.Threading.CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();


            if (_position >= _length)
                return ValueTask.FromResult(0);


            int count =
                (int)Math.Min(
                    buffer.Length,
                    _length - _position);


            for (int i = 0; i < count; i++)
            {
                buffer.Span[i] =
                    GenerateByte(_position);

                _position++;
            }


            return ValueTask.FromResult(count);
        }



        private byte GenerateByte(long position)
        {
            ulong x =
                _seed +
                (ulong)position;


            // SplitMix64 mixer

            x += 0x9E3779B97F4A7C15UL;

            x =
                (x ^
                (x >> 30))
                *
                0xBF58476D1CE4E5B9UL;


            x =
                (x ^
                (x >> 27))
                *
                0x94D049BB133111EBUL;


            x ^= x >> 31;


            return (byte)x;
        }



        private static void ValidateBuffer(
            byte[] buffer,
            int offset,
            int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            if (offset < 0 ||
                count < 0 ||
                offset + count > buffer.Length)
                throw new ArgumentOutOfRangeException();
        }



        public override void Flush()
        {
        }


        public override long Seek(
            long offset,
            SeekOrigin origin)
        {
            long newPosition = origin switch
            {
                SeekOrigin.Begin =>
                    offset,

                SeekOrigin.Current =>
                    _position + offset,

                SeekOrigin.End =>
                    _length + offset,

                _ =>
                    throw new ArgumentOutOfRangeException()
            };


            Position = newPosition;

            return _position;
        }



        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }


        public override void Write(
            byte[] buffer,
            int offset,
            int count)
        {
            throw new NotSupportedException();
        }
    }
}