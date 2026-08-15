using Aegis.Core.IPC;
using VaultCore.IPC;

namespace Aegis.Core;

internal class Program
{
    static async Task Main()
    {
        try
        {
            Console.WriteLine("CORE STARTED");

            var router = new CommandRouter();
            var host = new VaultIpcHost(router);

            await host.RunAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            Console.WriteLine("FATAL ERROR:");
            Console.WriteLine(ex);

            File.WriteAllText("core_crash.txt", ex.ToString());

            Console.ReadLine();
        }
    }
}