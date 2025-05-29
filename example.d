/+ dub.sdl:
	name "example"
    dependency "gemini" version="*"
+/
// How to run: dub run --single example.d

import gemini;
import vibe.core.core: runEventLoop;
import vibe.core.log;

void main()
{
    import std.stdio;

    enum debugEnabled = true;
    if(debugEnabled)
        //~ setLogLevel = LogLevel.debugV;
        setLogLevel = LogLevel.trace;
    else
        setLogLevel = LogLevel.diagnostic;

    const ss = ServerSettings(
        pkiCertFile: "cert.pem",
        pkiPrivateKeyFile: "privkey.pem",
        reuseAddress: true,
        reusePort: true,
    );

    void handler(GeminiServerRequest req, ref GeminiServerResponse res) @trusted
    {
        res.writeBody(`Hello, world!`, "text/gemini");
    }

    auto listener = listenGemini(ss, &handler);
    writeln("Gemini server listening");

    runEventLoop();
}
