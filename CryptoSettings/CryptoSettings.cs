namespace CryptoConfig
{
    public sealed class CryptoSettings
    {
        public int ArgonParallelism { get; set; }
        public int ArgonIterations { get; set; }
        public int ArgonMemoryKb { get; set; }

        public int Pbkdf2Iterations { get; set; }
    }
}
