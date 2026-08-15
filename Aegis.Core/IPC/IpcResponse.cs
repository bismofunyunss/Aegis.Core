using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace VaultCore.IPC
{
    public sealed class IpcResponse
    {
        public bool Success { get; set; }
        public string Error { get; set; }
        public string? Data { get; set; }
        public string? Message { get; set; }
    }
}
