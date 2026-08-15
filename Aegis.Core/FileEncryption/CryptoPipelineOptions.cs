using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.FileEncryption
{
    public sealed class CryptoPipelineOptions
    {
        public CancellationToken CancellationToken { get; init; }

        public int? WorkerCount { get; init; }

        public int CpuBudget =>
            WorkerCount.HasValue
                ? Math.Clamp(
                    WorkerCount.Value,
                    4,
                    Environment.ProcessorCount - 2)
                : Math.Clamp(
                    Environment.ProcessorCount - 4,
                    4,
                    32);


        public int ThreefishWorkers =>
            Math.Clamp(
                (CpuBudget * 2) / 3,
                4,
                10);


        public int SerpentWorkers =>
            Math.Clamp(
                CpuBudget / 4,
                2,
                6);


        public int AesWorkers =>
            Math.Clamp(
                CpuBudget / 4,
                2,
                6);


        public int XChaChaWorkers =>
            Math.Clamp(
                CpuBudget / 5,
                2,
                4);


        public int ChannelCapacity =>
            Math.Clamp(
                CpuBudget * 3,
                32,
                192);
    }
}
