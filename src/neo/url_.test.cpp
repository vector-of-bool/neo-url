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

TEST_CASE("Parse a URL") {
    // Parse a simple url:
    using std::nullopt;
    using std::optional;
    using opt_str = optional<std::string>;
    struct case_ {
        std::string_view given;
        std::string      scheme;
        opt_str          host;
        optional<int>    port           = nullopt;
        std::string      path           = "";
        std::string      fragment       = "";
        std::string      query          = "";
        int              effective_port = 0;
        std::string      to_string_res  = std::string(given);
    };

    const case_ expect = GENERATE(Catch::Generators::values<case_>({
        {.given  = "http://google.com/maps",
         .scheme = "http",
         .host   = "google.com",
         .path   = "/maps"},
        {.given  = "http://google.com/mail/inbox",
         .scheme = "http",
         .host   = "google.com",
         .path   = "/mail/inbox"},
        {.given  = "http://google.com/mail/inbox/",
         .scheme = "http",
         .host   = "google.com",
         .path   = "/mail/inbox/"},
        {.given  = "https://google.com/mail/inbox",
         .scheme = "https",
         .host   = "google.com",
         .path   = "/mail/inbox"},
        {.given = "https://google.com/", .scheme = "https", .host = "google.com", .path = "/"},
        {.given         = "https://google.com",
         .scheme        = "https",
         .host          = "google.com",
         .path          = "/",
         .to_string_res = "https://google.com/"},
        {.given = "http://localhost/foo", .scheme = "http", .host = "localhost", .path = "/foo"},
        {.given  = "http://localhost:80/foo",
         .scheme = "http",
         .host   = "localhost",
         .path   = "/foo",
         // Drops the port because it is the HTTP default:
         .to_string_res = "http://localhost/foo"},
        {.given  = "http://localhost:81/foo",
         .scheme = "http",
         .host   = "localhost",
         .port   = 81,
         .path   = "/foo"},
        {.given  = "http://localhost:66/foo",
         .scheme = "http",
         .host   = "localhost",
         .port   = 66,
         .path   = "/foo"},
        {.given  = "http://localhost/foo%20bar",
         .scheme = "http",
         .host   = "localhost",
         .path   = "/foo%20bar"},
        {.given  = "file:///home/user/thing.txt",
         .scheme = "file",
         .host   = "",
         .path   = "/home/user/thing.txt"},
        {.given  = "http://example.com",
         .scheme = "http",
         .host   = "example.com",
         // HTTP brings the path back
         .path          = "/",
         .to_string_res = "http://example.com/"},
        {.given = "git+http://example.com", .scheme = "git+http", .host = "example.com"},
    }));

    auto result = neo::url::parse(expect.given);
    CAPTURE(expect.given);
    CHECK(result.host.value_or("[null]") == expect.host.value_or("[null]"));
    CHECK(result.scheme == expect.scheme);
    CHECK(result.path_string() == expect.path);
    if (expect.effective_port) {
        CHECK(result.port_or_default_port() == expect.effective_port);
    }
    CHECK(result.to_string() == expect.to_string_res);
}
