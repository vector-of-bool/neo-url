#include <neo/url/percent.hpp>

#include <catch2/catch.hpp>

TEST_CASE("Percent-encode some strings") {
    struct case_ {
        std::string_view in;
        std::string_view expect;
    };

    auto cur    = GENERATE(Catch::Generators::values<case_>({
        {"foo", "foo"},
        {"foo%20bar", "foo bar"},
    }));
    auto actual = neo::percent_decode(cur.in);
    CAPTURE(cur.in);
    CHECK(actual == cur.expect);
    auto reencoded = neo::percent_encode<neo::fragment_pct_encode_set>(actual);
    CHECK(reencoded == cur.in);
}
