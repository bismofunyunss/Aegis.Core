using Aegis.Core.IPC;
using System.Security;
using System.Security.Cryptography;
using System.Text;

public static class VaultTransport
{
    public static SecureEnvelope EncryptOutgoing(
        byte[] key,
        byte[] plaintext,
        string sessionId,
        ulong counter,
        string command)
    {
        byte[] nonce =
            RandomNumberGenerator.GetBytes(12);

        byte[] ciphertext =
            new byte[plaintext.Length];

        byte[] tag =
            new byte[16];

        byte[] aad =
            Encoding.UTF8.GetBytes(
                $"{sessionId}:{counter}:{command}");

        using var aes =
            new AesGcm(key, 16);

        aes.Encrypt(
            nonce,
            plaintext,
            ciphertext,
            tag,
            aad);

        return new SecureEnvelope
        {
            SessionId = sessionId,
            Counter = counter,
            Command = command,

            Nonce = nonce,
            Ciphertext = ciphertext,
            Tag = tag
        };
    }

    public static byte[] DecryptIncoming(
        byte[] key,
        SecureEnvelope env,
        string sessionId,
        ulong counter,
        string command)
    {
        if (env.Nonce == null ||
            env.Ciphertext == null ||
            env.Tag == null)
        {
            throw new SecurityException(
                "Invalid secure envelope.");
        }

        byte[] plaintext =
            new byte[env.Ciphertext.Length];

        byte[] aad =
            Encoding.UTF8.GetBytes(
                $"{sessionId}:{counter}:{command}");

        using var aes =
            new AesGcm(key, 16);

        aes.Decrypt(
            env.Nonce,
            env.Ciphertext,
            env.Tag,
            plaintext,
            aad);

        return plaintext;
    }
}
