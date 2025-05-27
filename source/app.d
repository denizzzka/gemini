import std.datetime;
import std.traits;
import vibe.core.core: runEventLoop;
import vibe.core.log;
import vibe.internal.interfaceproxy;
import vibe.stream.operations;
import vibe.stream.tls;

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
    /// Time to wait for socket connection
    uint preTlsTimeout = 10 * 1000; // 10s

    /// Time to wait for TLS handshake
    uint tlsTimeout = 60 * 1000; // 60s

    /// Time until full request is received
    //~ uint requestTimeout = 40 * 1000; // 40s

    /// Maximum number of transferred bytes per request after which the connection is closed with an error
    // Spec: URI MUST NOT exceed 1024 bytes, and a server MUST reject requests where the URI exceeds this limit
    // absolute-URI + CRLF length
    enum ushort maxRequestSize = 1024 + "\r\n".length;

    TLSContext tlsContext;

    this(TLSContext tlsContext)
    {
		this.tlsContext = tlsContext;
	}
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

    static void handleConnectionNoThrow(TCPConnection conn, in ServerSettings serverSettings) nothrow @safe
    {
        try handleConnection(conn, serverSettings);
        catch (Exception e) {
            logError("Connection handler has thrown at the peer %s: %s", conn.remoteAddress, e.msg);
            debug logDebug("Full error: %s", () @trusted { return e.toString().sanitize(); } ());

            try conn.close();
            catch (Exception e) logError("Failed to close connection: %s", e.msg);
        }
    }

    static void handleConnection(TCPConnection connection, in ServerSettings serverSettings) @safe
    {
        scope(exit) connection.close();

        assert(serverSettings.tlsContext, "No TLS context found");

        connection.tcpNoDelay = true;

        alias TLSStreamType = ReturnType!(createTLSStreamFL!(InterfaceProxy!Stream));
        TLSStreamType tls_stream;

        InterfaceProxy!Stream stream;
        stream = connection;

        if(!connection.waitForData(serverSettings.preTlsTimeout.msecs))
        {
            logDebug("Client didn't send the initial request in a timely manner");
            return;
        }

		logDebug("Accept TLS connection: %s", serverSettings.tlsContext.kind);
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

    enum debugEnabled = true;
    if(debugEnabled)
        setLogLevel = LogLevel.debugV;
    else
        setLogLevel = LogLevel.diagnostic;

    const ss = new ServerSettings(
		tlsContext: createTLSContext(TLSContextKind.server)
	);
    //~ ss.tlsContext.useCertificateChainFile(cfg.pkiCertFile);
    //~ ss.tlsContext.usePrivateKeyFile(cfg.pkiKeyFile);

    auto listener = listenGemini(ss, () @safe => null);
    writeln("Gemini server listening");

    runEventLoop();
}
