using Aegis.Core.Crypto;
using System.Collections.Concurrent;
using System.Security;

namespace Aegis.Core.Crypto;

internal static class ServerCryptoSessionStore
{
    private static readonly ConcurrentDictionary<string, SessionState>
        _sessions = new();

    public static SessionState Register(
        string username,
        ServerCryptoSession session,
        TimeSpan lifetime)
    {
        var state = new SessionState
        {
            SessionId = session.SessionId,
            Username = username,
            Session = session,
            CreatedUtc = session.CreatedUtc,
            ExpiresUtc = DateTime.UtcNow.Add(lifetime),
            LastCounter = 0
        };

        _sessions[state.SessionId] = state;

        return state;
    }

    public static SessionState Get(
        string sessionId)
    {
        if (!_sessions.TryGetValue(
                sessionId,
                out var state))
        {
            throw new SecurityException(
                "Invalid session.");
        }

        return state;
    }

    public static SessionState Validate(
        string sessionId,
        ulong counter)
    {
        var state = Get(sessionId);

        lock (state.SyncRoot)
        {
            if (DateTime.UtcNow > state.ExpiresUtc)
            {
                Remove(sessionId);

                throw new SecurityException(
                    "Session expired.");
            }

            if (counter <= state.LastCounter)
            {
                throw new SecurityException(
                    "Replay detected.");
            }

            state.LastCounter = counter;
        }

        return state;
    }

    public static bool TryGet(
        string sessionId,
        out SessionState? state)
    {
        return _sessions.TryGetValue(
            sessionId,
            out state);
    }

    public static void Remove(
        string sessionId)
    {
        if (_sessions.TryRemove(
                sessionId,
                out var state))
        {
            state.Session.Dispose();
        }
    }
}
