using System;
using System.Collections.Generic;
using System.Text;
using Tpm2Lib;

namespace Aegis.Core.Tpm
{
    internal class OpenTpm
    {
        public static Tpm2 CreateTpm()
        {
            // Use TBS device (Windows TPM Base Services) — real TPM
            Tpm2Device tpmDevice = new TbsDevice();

            // Connect to the TPM
            tpmDevice.Connect();

            // Create Tpm2 object
            Tpm2 tpm = new Tpm2(tpmDevice);

            return tpm;
        }
    }
}
