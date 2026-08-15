using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Progress
{
    public static class IpcProgressHub
    {
        private static readonly object _lock = new();

        private static readonly Dictionary<string, Action<double>> _subscribers = new();

        public static void Subscribe(string sessionId, Action<double> handler)
        {
            lock (_lock)
            {
                _subscribers[sessionId] = handler;
            }
        }

        public static void Unsubscribe(string sessionId)
        {
            lock (_lock)
            {
                _subscribers.Remove(sessionId);
            }
        }

        public static void Report(string sessionId, double value)
        {
            Action<double>? handler;

            lock (_lock)
            {
                _subscribers.TryGetValue(sessionId, out handler);
            }

            handler?.Invoke(value);
        }
    }
}
