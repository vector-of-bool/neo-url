#include <neo/url/query.hpp>

#include <catch2/catch.hpp>

TEST_CASE("Walk through a query string") {
    std::string                  q = "foo=bar;baz=quux";
    neo::basic_query_string_view qsv{q};

    auto it = qsv.begin();
    CHECK(it->string() == "foo=bar");
    ++it;
    CHECK(it->string() == "baz=quux");
    CHECK(it->key_raw() == "baz");
    CHECK(it->value_raw() == "quux");

    q   = "foo=bar%20baz";
    qsv = neo::basic_query_string_view{q};
    it  = qsv.begin();
    CHECK(it->string() == "foo=bar%20baz");
    CHECK(it->key_raw() == "foo");
    CHECK(it->value_raw() == "bar%20baz");
    CHECK(it->value_decoded() == "bar baz");

    for (auto el [[maybe_unused]] : qsv) {
        // ... Just check that we can iterate ...
    }
}
