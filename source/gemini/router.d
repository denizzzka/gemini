module gemini.router;

import gemini;
import vibe.http.router;

private struct Route {
	string pattern;
	GeminiServerRequestDelegate cb;
}

final class URLRouter : URLRouterBase!Route
{
}

unittest
{
    auto r = new URLRouter;
}
