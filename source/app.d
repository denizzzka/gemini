import vibe.core.log;

///
alias GeminiServerRequestDelegate = GeminiServerResponse delegate(/*GeminiServerRequest req*/) @safe;

///
class GeminiServerResponse
{
}

///
class ServerSettings
{
    /// The interfaces on which the HTTP server is listening.
    ///
    /// By default, the server will listen on all IPv4 and IPv6 interfaces.
    string[] bindAddresses = ["::"];

    ///
    ushort port = 1965;

    /// Determines the server host name.
    ///
    /// If multiple servers are listening on the same port, the host name will determine which one gets a request.
    string hostName;

    ///
    bool reuseAddress;

    ///
    bool reusePort;

    //TODO: set defaults same as in other servers
    /// Time to wait for socket connection & TLS handshake
    uint connectTimeout = 60 * 1000; // 60s

    /// Time until full request is received
    uint requestTimeout = 40 * 1000; // 40s

    /// Maximum number of transferred bytes per request after which the connection is closed with an error
    // Spec: URI MUST NOT exceed 1024 bytes, and a server MUST reject requests where the URI exceeds this limit
    // absolute-URI + CRLF length is 1026
    enum ushort maxRequestSize = 1026;
}

///
class GeminiListener
{
    import vibe.core.net;
    import std.encoding : sanitize;

    //~ static assert(!HaveNoTLS);

    TCPListener[] listeners;

    this(in ServerSettings cfg) @safe
    {
        TCPListenOptions options = TCPListenOptions.defaults;
        if(!cfg.reuseAddress) options &= ~TCPListenOptions.reuseAddress;
        if(!cfg.reusePort) options &= ~TCPListenOptions.reusePort;

        foreach (addr; cfg.bindAddresses)
            listeners ~= createListener(cfg, options, addr);
    }

    static TCPListener createListener(in ServerSettings serverSettings, TCPListenOptions options, string addr) @safe
    {
        return listenTCP(
            serverSettings.port,
            (TCPConnection conn) nothrow @safe => handleConnectionNoThrow(conn, serverSettings),
            addr,
            options
        );
    }

    static handleConnectionNoThrow(TCPConnection conn, in ServerSettings serverSettings) nothrow @safe
    {
        try handleConnection(conn, serverSettings);
        catch (Exception e) {
            logError("Connection handler has thrown at the peer %s: %s", conn.remoteAddress, e.msg);
            debug logDebug("Full error: %s", () @trusted { return e.toString().sanitize(); } ());

            try conn.close();
            catch (Exception e) logError("Failed to close connection: %s", e.msg);
        }
    }

    static handleConnection(in TCPConnection connection, in ServerSettings serverSettings) @safe
    {
    }
}

///
GeminiListener listenGemini(in ServerSettings settings, GeminiServerRequestDelegate requestDg) @safe
{
    auto listener = new GeminiListener(settings);

    return listener;
}

void main()
{
    import std.stdio;

    const cfg = new ServerSettings;
    auto listener = listenGemini(cfg, () @safe => null);
    //~ writeln("Edit source/app.d to start your project.");
}
