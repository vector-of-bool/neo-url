#include "./url.hpp"

#include <catch2/catch.hpp>

TEST_CASE("Parse a basic host") {
    auto host = neo::url::host_t::parse_opaque("google.com");
    CHECKED_IF(host.has_value()) { CHECK(host->string == "google.com"); }
}

TEST_CASE("Parse an ipv6 host") {
    auto host = neo::url::host_t::parse("[::]");
    CHECKED_IF(host.has_value()) {  //
        CHECK(host->ipv6_addr == neo::url::host_t::ipv6_type{});
    };

    host = host->parse("[::5]");
    CHECKED_IF(host) {  //
        CHECK(host->ipv6_addr[7] == 5);
    }

    host = host->parse("[4f1b:929::989a:3]");
    CHECKED_IF(host) {  //
        CHECK(host->ipv6_addr[0] == 0x4f1b);
        CHECK(host->ipv6_addr[1] == 0x929);
        CHECK(host->ipv6_addr[6] == 0x989a);
        CHECK(host->ipv6_addr[7] == 0x3);
    }
}

TEST_CASE("Bad URLs") {
    const std::string_view given = GENERATE(Catch::Generators::values<std::string_view>({
        // Non-alnum in scheme:
        "(http://google.com/mail",
        "\xe8ttp://google.com/mail",
        // Only ASCII alnum in scheme:
        "èttp://google.com/mail",
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
        // Bracketed hosts should be IPv6 addresses
        "http://[www.example.com]/",
    }));
    CAPTURE(given);
    auto result = neo::url::try_parse(given);
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
            .given         = "https://google.com",
            .scheme        = "https",
            .host          = "google.com",
            .path          = "/",
            .to_string_res = "https://google.com/",
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
            .path   = "/foo",
            // Drops the port because it is the HTTP default:
            .to_string_res = "http://localhost/foo",
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
            .given         = "file:///usr/../",
            .scheme        = "file",
            .host          = "",
            .path          = "/",
            .to_string_res = "file:///",
        },
        // Relative paths are collapsed, even without trailing '/'
        {
            .given         = "file:///usr/..",
            .scheme        = "file",
            .host          = "",
            .path          = "/",
            .to_string_res = "file:///",
        },
        // Files without an empty authority receive one:
        {
            .given         = "file:/home/joe/Documents/stuff.txt",
            .scheme        = "file",
            .host          = "",
            .path          = "/home/joe/Documents/stuff.txt",
            .to_string_res = "file:///home/joe/Documents/stuff.txt",
        },
        // Simple relative path on non-special scheme:
        {
            .given  = "hello:world",
            .scheme = "hello",
            .path   = "world",
        },
        // Again, implicit path '/' for special schemes
        {
            .given         = "https://user:password@example.org",
            .scheme        = "https",
            .username      = "user",
            .password      = "password",
            .host          = "example.org",
            .path          = "/",
            .to_string_res = "https://user:password@example.org/",
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
            .path = "//not-a-host/",
        },
        // Similar deal: The '/..' collapses along with the prior element, but
        // does not accidentally form an authority in to_string()
        // (NodeJS gets this wrong as well)
        {
            .given  = "web+demo:/path/..//not-a-host/",
            .scheme = "web+demo",
            // Path has been collapsed, but comes back correctly in to_string()
            .path          = "//not-a-host/",
            .to_string_res = "web+demo:/.//not-a-host/",
        },
        // Funky userinfo provided with special characters that must be percent-encoded:
        {
            .given         = "http://user:password:pass@exa:mple@ex.com/",
            .scheme        = "http",
            .username      = "user",
            .password      = "password%3Apass%40exa%3Ample",
            .host          = "ex.com",
            .path          = "/",
            .to_string_res = "http://user:password%3Apass%40exa%3Ample@ex.com/",
        },
        {
            .given  = "http://google.com/mail?inbox=12",
            .scheme = "http",
            .host   = "google.com",
            .path   = "/mail",
            .query  = "inbox=12",
        },
        {
            .given    = "http://google.com/mail?inbox=12#subid",
            .scheme   = "http",
            .host     = "google.com",
            .path     = "/mail",
            .query    = "inbox=12",
            .fragment = "subid",
        },
        // Hostnames are lower-cased, and dot-dot at top of URL just disappears
        {
            .given         = "https://EXAMPLE.com/../x",
            .scheme        = "https",
            .host          = "example.com",
            .path          = "/x",
            .to_string_res = "https://example.com/x",
        },
        // No path, just straight to query:
        {
            .given         = "http://example.com?query",
            .scheme        = "http",
            .host          = "example.com",
            .path          = "/",
            .query         = "query",
            .to_string_res = "http://example.com/?query",
        },
        // No path, just straight to fragment:
        {
            .given         = "http://example.com#fragment",
            .scheme        = "http",
            .host          = "example.com",
            .path          = "/",
            .fragment      = "fragment",
            .to_string_res = "http://example.com/#fragment",
        },
        // Query and fragment:
        {
            .given         = "http://example.com?query#fragment",
            .scheme        = "http",
            .host          = "example.com",
            .path          = "/",
            .query         = "query",
            .fragment      = "fragment",
            .to_string_res = "http://example.com/?query#fragment",
        },
    }));

    CAPTURE(expect.given);
    auto result = neo::url::parse(expect.given);
    CHECK(result.host.value_or("[null]") == expect.host.value_or("[null]"));
    CHECK(result.port.value_or(0) == expect.port.value_or(0));
    CHECK(result.scheme == expect.scheme);
    CHECK(result.username == expect.username);
    CHECK(result.password == expect.password);
    CHECK(result.path == expect.path);
    if (expect.effective_port) {
        CHECK(result.port_or_default_port() == expect.effective_port);
    }
    CHECK(result.to_string() == expect.to_string_res);
}

TEST_CASE("Manipulating") {
    auto url = neo::url::parse("http://example.org");
    url.clear_path();
    CHECK(url.path == "/");  // HTTP, so keepts its path
    url.append_path("foo");
    CHECK(url.path == "/foo");
    // Leading slash is ignored
    url.append_path("/bar");
    CHECK(url.path == "/foo/bar");
    // dot-dot erases a path element by normalization
    url.append_path("/../baz");
    CHECK(url.path == "/foo/baz");
    url.append_path("../quux");
    CHECK(url.path == "/foo/quux");
    // /= operator does the same thing:
    url /= "eggs";
    CHECK(url.path == "/foo/quux/eggs");
    // Trailing '/' remains:
    url /= "salad/";
    CHECK(url.path == "/foo/quux/eggs/salad/");

    // Check popping path elements
    url.path = "/foo/quux/baz";
    url.path_pop_back();
    CHECK(url.path == "/foo/quux");
    url.path = "/foo/bar/";  // Trailing '/' doesn't matter
    url.path_pop_back();
    CHECK(url.path == "/foo");
    url.path_pop_back();
    CHECK(url.path == "/");  // HTTP keeps the top-level '/'
    url.path_pop_back();
    CHECK(url.path == "/");  // Nothing more to pop
}
