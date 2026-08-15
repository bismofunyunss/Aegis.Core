using Aegis.Contracts;

namespace Aegis.Core.IPC
{
    public sealed class IpcRequest
    {
        public string Command { get; set; } = string.Empty;

        public string? SessionId { get; set; }

        public ulong Counter { get; set; }

        public byte[] Payload { get; set; } = Array.Empty<byte>();
    }
}
