using Aegis.Contracts;
using Aegis.Core.Crypto;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace Aegis.Core.Tpm
{
    public sealed class TpmSealService
    {
        private readonly Tpm2 _tpm;
        private readonly uint[] _pcrs;

        public TpmSealService(Tpm2 tpm, uint[] pcrs = null)
        {
            _tpm = tpm ?? throw new ArgumentNullException(nameof(tpm));
            _pcrs = pcrs ?? new uint[] { 0, 2, 4, 7, 11 };
        }

        public TpmHandle CreateOrLoadSrk(uint handle = 0x81000001)
        {
            var srkHandle = new TpmHandle(handle);

            try
            {
                _tpm.ReadPublic(srkHandle, out _, out _);
                return srkHandle; // already exists
            }
            catch
            {
                var srkPublic = new TpmPublic(
                    TpmAlgId.Rsa,
                    ObjectAttr.Restricted |
                    ObjectAttr.Decrypt |
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.SensitiveDataOrigin |
                    ObjectAttr.UserWithAuth |
                    ObjectAttr.NoDA,
                    new byte[0],
                    new RsaParms(
                        new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                        new NullAsymScheme(),
                        2048,
                        0),
                    new Tpm2bPublicKeyRsa()
                );

                var srk = _tpm.CreatePrimary(
                    TpmRh.Owner,
                    new SensitiveCreate(),
                    srkPublic,
                    Array.Empty<byte>(),
                    Array.Empty<PcrSelection>(),
                    out _,
                    out _,
                    out _,
                    out _
                );

                _tpm.EvictControl(TpmRh.Owner, srk, srkHandle);
                _tpm.FlushContext(srk);

                return srkHandle;
            }
        }

        /// <summary>
        /// Seal a secret to the TPM with PCR policy.
        /// Returns both private + public blobs as a byte[] for storage.
        /// </summary>
        public KeyBlob Seal(byte[] secret, TpmHandle srk)
        {
            if (secret == null || secret.Length == 0)
                throw new ArgumentException(nameof(secret));

            // Start a TPM policy session for PCR auth
            var session = _tpm.StartAuthSession(
                TpmRh.Null,
                TpmRh.Null,
                RandomNumberGenerator.GetBytes(16),
                Array.Empty<byte>(),
                TpmSe.Policy,
                new SymDef(),
                TpmAlgId.Sha256,
                out _
            );

            try
            {
                // Define PCR selection for this blob
                var pcrSel = new[] { new PcrSelection(TpmAlgId.Sha256, _pcrs) };
                _tpm.PolicyPCR(session, null, pcrSel);
                _tpm.PolicyAuthValue(session);

                var sensitive = new SensitiveCreate(Array.Empty<byte>(), secret);
                byte[] policyDigest = _tpm.PolicyGetDigest(session);

                var publicArea = new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.AdminWithPolicy |
                    ObjectAttr.NoDA,
                    policyDigest,
                    new KeyedhashParms(new NullSchemeKeyedhash()),
                    new Tpm2bDigestKeyedhash()
                );

                // Use SRK as parent
                TpmPrivate privateBlob = _tpm.Create(
                    srk,
                    sensitive,
                    publicArea,
                    Array.Empty<byte>(), // outsideInfo
                    Array.Empty<PcrSelection>(),
                    out TpmPublic createdPublic,
                    out _,
                    out _,
                    out _
                );

                // ✅ Return blob with updated counter
                return new KeyBlob()
                {
                    SealedKekPublic = createdPublic.GetTpmRepresentation(),
                    SealedKekPrivate = privateBlob.buffer,
                    Pcrs = _pcrs,
                };
            }
            finally
            {
                _tpm.FlushContext(session);
            }
        }


        public byte[] Unseal(KeyBlob blob, TpmHandle srk)
        {
            if (blob == null)
                throw new ArgumentNullException(nameof(blob));

            var privateBlob = new TpmPrivate(blob.SealedKekPrivate);

            var session = _tpm.StartAuthSession(
                TpmRh.Null,
                TpmRh.Null,
                RandomNumberGenerator.GetBytes(16),
                Array.Empty<byte>(),
                TpmSe.Policy,
                new SymDef(),
                TpmAlgId.Sha256,
                out _
            );

            try
            {
                var auth = new AuthSession(session);

                var pcrSelection = new[] { new PcrSelection(TpmAlgId.Sha256, blob.Pcrs) };
                _tpm.PolicyPCR(session, null, pcrSelection);
                _tpm.PolicyAuthValue(session);

                TpmPublic publicArea = Marshaller.FromTpmRepresentation<TpmPublic>(blob.SealedKekPublic);

                TpmHandle handle = _tpm.Load(srk, privateBlob, publicArea);


                byte[] secret = _tpm[auth].Unseal(handle);
                _tpm.FlushContext(handle);

                return secret;
            }
            finally
            {
                try
                {
                    _tpm.SafeFlushContext(session);
                }
                catch
                {
                    // this will always throw. Ignore exception
                }
            }
        }
    }
}
