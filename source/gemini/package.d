module gemini;

import std.datetime;
import std.exception: enforce;
import std.traits;
import vibe.core.log;
import vibe.core.net;
import vibe.inet.url: URL;
import vibe.internal.interfaceproxy;
import vibe.stream.operations;
import vibe.stream.tls;

///
alias GeminiServerRequestHandler = void delegate(GeminiServerRequest, ref GeminiServerResponse) @safe;

///
enum ReplyCode : ubyte
{
    input = 1,
    success,
    redirect,
    tempfail,
    permfail,
    auth,
}

///
class GeminiServerResponse
{
    ReplyCode replyCode = ReplyCode.permfail;
    ubyte additionalCode;

    union
    {
        string prompt;
        struct
        {
            string mimetype;
            ubyte[] body;

            ///
            void writeBody(string s, string content_type)
            {
                replyCode = ReplyCode.success;
                mimetype = content_type;
                body = cast(ubyte[]) s;
            }
        }
        string redirectUri;
        string errormsg;
    }

    void writeBadRequest() @trusted nothrow
    {
        replyCode = ReplyCode.permfail;
        additionalCode = 9;
        errormsg = "Bad request";
    }

    void writeInternalError() @trusted nothrow
    {
        replyCode = ReplyCode.permfail;
        errormsg = "Internal server error";
    }
}

///
struct ServerSettings
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
    enum ushort maxRequestSize = 1024 + CRLF.length;

    ///
    string pkiCertFile;

    ///
    string pkiPrivateKeyFile;
}

///
class GeminiListener
{
    import std.encoding: sanitize;

    TCPListener[] listeners;

    this(in ServerSettings cfg, GeminiServerRequestHandler geminiRequestHandler) @safe
    {
        TCPListenOptions options = TCPListenOptions.defaults;
        if(!cfg.reuseAddress) options &= ~TCPListenOptions.reuseAddress;
        if(!cfg.reusePort) options &= ~TCPListenOptions.reusePort;

        foreach (addr; cfg.bindAddresses)
            listeners ~= createListener(cfg, options, addr, geminiRequestHandler);
    }

    static TCPListener createListener(in ServerSettings serverSettings, TCPListenOptions options, string addr, GeminiServerRequestHandler dg) @safe
    {
        auto tlsContext = createTLSContext(TLSContextKind.server);
        tlsContext.useCertificateChainFile(serverSettings.pkiCertFile);
        tlsContext.usePrivateKeyFile(serverSettings.pkiPrivateKeyFile);

        return listenTCP(
            serverSettings.port,
            (TCPConnection conn) nothrow @safe => handleConnectionNoThrow(conn, serverSettings, tlsContext, dg),
            addr,
            options
        );
    }

    static void handleConnectionNoThrow(TCPConnection conn, in ServerSettings serverSettings, TLSContext tlsContext, GeminiServerRequestHandler dg) nothrow @safe
    {
        scope(exit) conn.close();

        assert(tlsContext, "No TLS context passed");

        try handleTlsConnection(conn, serverSettings, tlsContext, dg);
        catch(Exception e)
        {
            logError("Connection handler has thrown at the peer %s: %s", conn.remoteAddress, e.msg);
            debug logDebug("Full error: %s", () @trusted { return e.toString().sanitize(); } ());

            try conn.close();
            catch(Exception e) logError("Failed to close connection: %s", e.msg);
        }
    }

    static void handleTlsConnection(TCPConnection conn, in ServerSettings serverSettings, TLSContext tlsContext, GeminiServerRequestHandler dg) @safe
    {
        conn.tcpNoDelay = true;

        logTrace("Accept TLS conn from %s", conn.remoteAddress.toString);

        InterfaceProxy!Stream stream = conn;

        if(!conn.waitForData(serverSettings.preTlsTimeout.msecs))
        {
            logDebug("Client didn't send the initial request in a timely manner");
            return;
        }

        TLSStreamType tls_stream = createTLSStreamFL(stream, tlsContext, TLSStreamState.accepting, null, conn.remoteAddress);

        handleGeminiConnection(conn, tls_stream, serverSettings, dg);
    }
}

alias TLSStreamType = ReturnType!(createTLSStreamFL!(InterfaceProxy!Stream));
immutable ubyte[2] CRLF = cast(immutable ubyte[2]) "\r\n";

private void handleGeminiConnection(TCPConnection conn, TLSStreamType stream, in ServerSettings serverSettings, GeminiServerRequestHandler dg) @safe
{
    string req;
    auto resp = new GeminiServerResponse;

    try () @trusted {
        req = cast(string) stream.readUntil(CRLF, serverSettings.maxRequestSize);
        enforce(!stream.dataAvailableForRead, "Protocol violation: stream contains something after CRLF");
    }();
    catch(Exception e)
    {
        if(conn.empty)
        {
            logTrace("Socket closed by remote peer");
            return;
        }
        else
        {
            // Malformed Gemini request: too huge or CRLF not found
            resp.writeBadRequest;
            () @trusted { logTrace(resp.errormsg); }();

            stream.writeGeminiReply(resp);
            return;
        }
    }

    logTrace("Request: %s", req);

    auto sr = new GeminiServerRequest(serverSettings);
    sr.clientAddress = conn.remoteAddress;
    sr.url = URL(req);

    try
        dg(sr, resp);
    catch(Exception e)
    {
        logError(e.msg);
        resp.writeInternalError;
    }

    stream.writeGeminiReply(resp);
}

private string str(ubyte v) nothrow @safe
{
    import std.conv: to;

    return v.to!string;
}

private void writeGeminiReply(TLSStreamType stream, ref GeminiServerResponse res) @safe
{
    import std.conv: to;
    import vibe.stream.memory;

    stream.write(res.replyCode.str);
    stream.write(res.additionalCode.str);
    stream.write(" ");

    with(ReplyCode)
    final switch(res.replyCode)
    {
        case input:
            () @trusted { stream.write(res.prompt); } ();
        break;

        case success:
            () @trusted { stream.write(res.mimetype); } ();
        break;

        case redirect:
            () @trusted { stream.write(res.redirectUri); } ();
        break;

        case tempfail:
        case permfail:
        case auth:
            () @trusted { stream.write(res.errormsg); } ();
        break;
    }

    stream.write(CRLF);

    if(res.replyCode == ReplyCode.success)
    {
        auto output_stream = createMemoryStream(res.body, false);
        output_stream.pipe(stream);
    }
}

///
class GeminiServerRequest
{
    const ServerSettings* m_settings;
    NetworkAddress clientAddress;
    URL url;

    this(const ref ServerSettings serverSettings) @trusted
    {
        m_settings = &serverSettings;
    }
}

///
GeminiListener listenGemini(in ServerSettings settings, GeminiServerRequestHandler geminiRequestHandler) @safe
{
    auto listener = new GeminiListener(settings, geminiRequestHandler);

    return listener;
}
