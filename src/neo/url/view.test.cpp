#include <neo/url/view.hpp>

#include <catch2/catch.hpp>

TEST_CASE("Bad URLs") {
    const std::string_view given = GENERATE(Catch::Generators::values<std::string_view>({
        // Non-alnum in scheme:
        "(http://google.com/mail",
        "\xe8ttp://google.com/mail",
        // Only ASCII alnum in scheme:
        "èttp://google.com/mail",
        "hèttp://google.com/mail",
        // First char MUST be an alpha
        "5ttp://google.com/mail",
        // Not even resembling a URL:
        "ykoc",
        "p://\x85\x85\x85\x85",
        // No double-slash for an authority, required by the scheme being "special"
        // (Soft error in spec, hard error in neo-url)
        "https:example.org",
        // Excess slashes following scheme.
        // (Soft error in spec, hard error in neo-url)
        "https://////example.com///",
        // Using 'c|' for Windows drive letters is invalid.
        // (Soft error in spec, hard error in neo-url)
        "file:///c|/demo",
        // Spaces in path are forbidden. (Soft error in spec, hard error in neo-url)
        "https://example.org/foo bar",
        // Spaces in hostname are never allowed, even per spec
        "https://ex ample.org",
        // // Bracketed hosts should be IPv6 addresses
        // "http://[www.example.com]/",
    }));
    CAPTURE(given);
    auto result = neo::url_view::try_split(given);
    CHECK(std::holds_alternative<neo::url_parse_error>(result));
}

TEST_CASE("Parse a URL") {
    // Parse a simple url:
    using std::nullopt;
    using std::optional;
    using opt_str = optional<std::string>;
    struct case_ {
        std::string_view given;
        std::string      scheme;
        std::string      username       = "";
        std::string      password       = "";
        opt_str          host           = nullopt;
        optional<int>    port           = nullopt;
        std::string      path           = "";
        std::string      query          = "";
        std::string      fragment       = "";
        int              effective_port = 0;
        std::string      to_string_res  = std::string(given);
    };

    const case_ expect = GENERATE(Catch::Generators::values<case_>({
        // Simple URL:
        {
            .given  = "http://google.com/maps",
            .scheme = "http",
            .host   = "google.com",
            .path   = "/maps",
        },
        // // A simple URI without an authority, no implicit `/` in the path:
        {
            .given  = "isbn:something",
            .scheme = "isbn",
            .path   = "something",
        },
        {
            .given  = "some-ns:foo/bar",
            .scheme = "some-ns",
            .path   = "foo/bar",
        },
        // Another simple URL:
        {
            .given  = "http://google.com/mail/inbox",
            .scheme = "http",
            .host   = "google.com",
            .path   = "/mail/inbox",
        },
        // Ending '/' is maintained in round trip:
        {
            .given  = "http://google.com/mail/inbox/",
            .scheme = "http",
            .host   = "google.com",
            .path   = "/mail/inbox/",
        },
        // Another "special" scheme:
        {
            .given  = "https://google.com/mail/inbox",
            .scheme = "https",
            .host   = "google.com",
            .path   = "/mail/inbox",
        },
        // Simple path
        {
            .given  = "https://google.com/",
            .scheme = "https",
            .host   = "google.com",
            .path   = "/",
        },
        // No path on special URL ends up with a single implicit `/`
        {
            .given  = "https://google.com",
            .scheme = "https",
            .host   = "google.com",
            .path   = "",
        },
        // Simple URL again
        {
            .given  = "http://localhost/foo",
            .scheme = "http",
            .host   = "localhost",
            .path   = "/foo",
        },
        // URL with the default port has the default port disappear
        {
            .given  = "http://localhost:80/foo",
            .scheme = "http",
            .host   = "localhost",
            .port   = 80,
            .path   = "/foo",
        },
        // With a non-default port, the port is maintained:
        {
            .given  = "http://localhost:81/foo",
            .scheme = "http",
            .host   = "localhost",
            .port   = 81,
            .path   = "/foo",
        },
        {
            .given  = "http://localhost:66/foo",
            .scheme = "http",
            .host   = "localhost",
            .port   = 66,
            .path   = "/foo",
        },
        // pct-encoded elements remain pct-encoded
        {
            .given  = "http://localhost/foo%20bar",
            .scheme = "http",
            .host   = "localhost",
            .path   = "/foo%20bar",
        },
        // File URLs have an implicit empty string for their host
        // NOTE: This differs from the URL in NodeJS, which has a null hostname
        {
            .given  = "file:///home/user/thing.txt",
            .scheme = "file",
            .host   = "",
            .path   = "/home/user/thing.txt",
        },
        // Because 'git+http' is not "special", it does not receive an implicit '/' in its path:
        {
            .given  = "git+http://example.com",
            .scheme = "git+http",
            .host   = "example.com",
        },
        // Simple with userinfo:
        {
            .given    = "http://user:password@example.com/place",
            .scheme   = "http",
            .username = "user",
            .password = "password",
            .host     = "example.com",
            .path     = "/place",
        },
        // Relative paths are collapsed
        {
            .given  = "file:///usr/../",
            .scheme = "file",
            .host   = "",
            .path   = "/usr/../",
        },
        // Relative paths are collapsed, even without trailing '/'
        {
            .given  = "file:///usr/..",
            .scheme = "file",
            .host   = "",
            .path   = "/usr/..",
        },
        // Simple relative path on non-special scheme:
        {
            .given  = "hello:world",
            .scheme = "hello",
            .path   = "world",
        },
        {
            .given    = "https://user:password@example.org",
            .scheme   = "https",
            .username = "user",
            .password = "password",
            .host     = "example.org",
            .path     = "",
        },
        // Double-slashes in paths are maintained
        {
            .given  = "https://example.org//",
            .scheme = "https",
            .host   = "example.org",
            .path   = "//",
        },
        // `/.` leading path elements with no authority will not accidentally fold back to
        // accidentally create an authority element when we to-string the URL.
        // (NodeJS actually does this wrong.)
        {
            .given  = "web+demo:/.//not-a-host/",
            .scheme = "web+demo",
            // Path has been collapsed, but comes back correctly in to_string()
            .path = "/.//not-a-host/",
        },
        // Similar deal: The '/..' collapses along with the prior element, but
        // does not accidentally form an authority in to_string()
        // (NodeJS gets this wrong as well)
        {
            .given  = "web+demo:/path/..//not-a-host/",
            .scheme = "web+demo",
            // Path has been collapsed, but comes back correctly in to_string()
            .path = "/path/..//not-a-host/",
        },
        // Funky userinfo provided with special characters that must be percent-encoded:
        {
            .given    = "http://user:password:pass@exa:mple@ex.com/",
            .scheme   = "http",
            .username = "user",
            .password = "password:pass@exa:mple",
            .host     = "ex.com",
            .path     = "/",
        },
        {
            .given  = "https://EXAMPLE.com/../x",
            .scheme = "https",
            .host   = "EXAMPLE.com",
            .path   = "/../x",
        },
        // No path, just straight to query:
        {
            .given  = "http://example.com?query",
            .scheme = "http",
            .host   = "example.com",
            .query  = "query",
        },
        // No path, just straight to fragment:
        {
            .given    = "http://example.com#fragment",
            .scheme   = "http",
            .host     = "example.com",
            .fragment = "fragment",
        },
        // Query and fragment:
        {
            .given    = "http://example.com?query#fragment",
            .scheme   = "http",
            .host     = "example.com",
            .query    = "query",
            .fragment = "fragment",
        },
    }));

    INFO("Parsing URL: " << expect.given);
    auto result = neo::url_view::split(expect.given);
    CAPTURE(expect.given);
    CHECK(result.host.value_or("[null]") == expect.host.value_or("[null]"));
    CHECK(result.port.value_or(0) == expect.port.value_or(0));
    CHECK(result.scheme == expect.scheme);
    CHECK(result.username == expect.username);
    CHECK(result.password == expect.password);
    CHECK(result.path == expect.path);
    // if (expect.effective_port) {
    //     CHECK(result.port_or_default_port() == expect.effective_port);
    // }
    CHECK(result.to_string() == expect.to_string_res);
}
