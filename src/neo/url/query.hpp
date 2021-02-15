#pragma once

#include <neo/url/percent.hpp>

#include <neo/assert.hpp>
#include <neo/iterator_facade.hpp>
#include <neo/string.hpp>

#include <string_view>

namespace neo {

template <typename Str>
class basic_query_string_view {
    Str _query_string;

    using str_iter = typename Str::const_iterator;

public:
    using view_type   = string_view_type_t<Str>;
    using string_type = string_type_t<Str>;

    constexpr basic_query_string_view() = default;
    constexpr explicit basic_query_string_view(Str s)
        : _query_string(s) {}

    class element_type {
        view_type _str;

    public:
        constexpr explicit element_type(view_type v)
            : _str(v) {}

        constexpr view_type string() const noexcept { return _str; }
        constexpr view_type key_raw() const noexcept {
            auto eq_pos = _str.find('=');
            return eq_pos == _str.npos ? _str : _str.substr(0, eq_pos);
        }
        constexpr view_type value_raw() const noexcept {
            auto eq_pos = _str.find('=');
            return eq_pos == _str.npos ? view_type() : _str.substr(eq_pos + 1);
        }

        constexpr string_type key_decoded() const noexcept { return percent_decode(key_raw()); }

        constexpr string_type value_decoded() const noexcept { return percent_decode(value_raw()); }
    };

    struct iterator : neo::iterator_facade<iterator> {
    private:
        str_iter _s_it;
        str_iter _s_end;

        constexpr static str_iter _adv_until_sep_or_stop(str_iter it, const str_iter end) {
            while (it != end && *it != '&' && *it != ';') {
                ++it;
            }
            return it;
        }

    public:
        iterator() = default;

        struct sentinel_type {};

        constexpr iterator(str_iter first, str_iter last) noexcept
            : _s_it(first)
            , _s_end(last) {}

        constexpr bool equal_to(iterator o) const noexcept { return o._s_it == _s_it; }
        constexpr bool at_end() const noexcept { return _s_it == _s_end; }
        constexpr bool operator==(sentinel_type) const noexcept { return at_end(); }
        constexpr void increment() noexcept {
            neo_assert(expects, !at_end(), "Advance of past-the-end query string view iterator");
            _s_it = _adv_until_sep_or_stop(_s_it, _s_end);
            while (_s_it != _s_end && (*_s_it == ';' || *_s_it == '&')) {
                ++_s_it;
            }
        }

        constexpr element_type dereference() const noexcept {
            neo_assert(expects,
                       !at_end(),
                       "Dereference of past-the-end query string view iterator");
            const auto start = _s_it;
            const auto stop  = _adv_until_sep_or_stop(_s_it, _s_end);
            return element_type{view_type(std::addressof(*start), std::distance(start, stop))};
        }
    };

    constexpr auto begin() const noexcept {
        return iterator{_query_string.begin(), _query_string.end()};
    }

    constexpr auto end() const noexcept { return typename iterator::sentinel_type{}; }
};

template <typename S>
basic_query_string_view(const S&) -> basic_query_string_view<S>;

}  // namespace neo