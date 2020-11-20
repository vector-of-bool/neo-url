#pragma once

#include "./fwd.hpp"
#include "./parse.hpp"

#include <neo/assert.hpp>
#include <neo/memory.hpp>
#include <neo/utf8.hpp>
#include <neo/utility.hpp>

#include <charconv>
#include <cmath>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace neo {

template <typename ViewType>
class basic_url_view {
public:
    using view_type = ViewType;
    using char_type = typename view_type::value_type;

private:
    using opt_view = std::optional<view_type>;

public:
    view_type scheme;
    view_type username;
    view_type password;
    opt_view  host;
    view_type path;
    opt_view  query;
    opt_view  fragment;

    std::optional<std::uint16_t> port;

    constexpr basic_url_view() = default;

    template <typename Allocator>
    constexpr auto to_string(Allocator alloc) const noexcept {
        std::basic_string<char_type,
                          typename view_type::traits_type,
                          rebind_alloc_t<Allocator, char_type>>
            ret(alloc);

        const std::size_t reserve = 0                         //
            + scheme.size() + 1                               //
            + (host ? 2 + host->size() : 0)                   //
            + (port ? 2 + int(std::log10(*port)) : 0)         //
            + (username.empty() ? 0 : (username.size() + 1))  //
            + (password.empty() ? 0 : (password.size() + 1))  //
            + path.size()                                     //
            + (query ? query->size() : 0)                     //
            + (fragment ? fragment->size() : 0);

        ret.reserve(reserve);

        ret.append(scheme);
        ret.push_back(':');
        if (host) {
            ret.push_back('/');
            ret.push_back('/');
            if (!username.empty()) {
                ret.append(username);
                if (!password.empty()) {
                    ret.push_back(':');
                    ret.append(password);
                }
                ret.push_back('@');
            }
            ret.append(*host);
            if (port) {
                ret.push_back(':');
                char_type charbuf[16] = {};
                auto      conv_res    = std::to_chars(charbuf, charbuf + sizeof(charbuf), *port);
                ret.insert(ret.end(), charbuf, conv_res.ptr);
            }
        }
        ret.append(path);
        if (query) {
            ret.push_back('?');
            ret.append(*query);
        }
        if (fragment) {
            ret.push_back('#');
            ret.append(*fragment);
        }

        neo_assert(invariant,
                   reserve == ret.size(),
                   "URL string reserving did not reserve the correct size",
                   reserve,
                   ret.size(),
                   scheme,
                   host.value_or("[nullopt]"),
                   username,
                   password,
                   path,
                   query.value_or("[nullopt]"),
                   fragment.value_or("[nullopt]"));
        return ret;
    }

    constexpr std::basic_string<char_type> to_string() const noexcept {
        return to_string(std::allocator<char_type>{});
    }

    template <typename Allocator, typename Options = default_url_parse_options>
    constexpr auto normalize(Allocator alloc, Options&& opts = {}) const {
        using url_type = basic_url<std::basic_string<char_type,
                                                     typename view_type::traits_type,
                                                     rebind_alloc_t<Allocator, char_type>>>;
        return url_type::normalize(*this, alloc, opts);
    }

    template <typename Allocator, typename Options = default_url_parse_options>
    constexpr auto try_normalize(Allocator alloc, Options&& opts = {}) const {
        using url_type = basic_url<std::basic_string<char_type,
                                                     typename view_type::traits_type,
                                                     rebind_alloc_t<Allocator, char_type>>>;
        return url_type::try_normalize(*this, alloc, opts);
    }

    constexpr auto normalize() const { return normalize(std::allocator<char_type>{}); }
    constexpr auto try_normalize() const noexcept {
        return try_normalize(std::allocator<char_type>{});
    }

    template <typename Options = default_url_parse_options>
    static constexpr basic_url_view split(view_type input, Options opts = {}) {
        auto res = try_split(input, opts);
        auto err = std::get_if<url_parse_error>(&res);
        if (err) {
            throw url_validation_error(std::string(err->error));
        }
        return std::get<basic_url_view>(res);
    }

    template <typename Options = default_url_parse_options>
    static constexpr std::variant<basic_url_view, url_parse_error>
    try_split(view_type input, Options opts = {}) noexcept {
        if (input.empty()) {
            return url_parse_error{"Empty string cannot be a valid URL"};
        }

        basic_url_view url;
        const auto     begin = input.cbegin();
        const auto     end   = input.cend();
        const auto     npos  = input.npos;
        auto           place = begin;
        auto           iter  = place;

        auto pending = [&] { return std::string_view(&*place, iter - place); };

        // Find a scheme
        // First char must be an alpha
        if (iter != end && !url_detail::is_ascii_alpha(*iter)) {
            return url_parse_error{"Invalid URL string: Scheme must start of an ASCII letter"};
        }
        while (iter != end && *iter != ':') {
            // Subsequent must be alpha, +, -, or .
            if (!url_detail::is_ascii_alphanumeric(*iter)
                && *iter == oper::none_of('+', '-', '.')) {
                return url_parse_error{
                    "Invalid URL string: Scheme must consist of ASCII digits, letters, '+', '-', "
                    "or '.'"};
            }
            ++iter;
        }

        // We should have stopped at a colon
        if (iter == end) {
            return url_parse_error{"No colon ':' found in the given URL string"};
        }

        url.scheme = pending();
        ++iter;
        place = iter;

        url.username = pending();
        url.password = pending();

        if (iter == end || ++iter == end) {
            url.path = pending();
            return url;
        }

        ++iter;
        if (pending() == "//") {
            // Split the authority segment
            place = iter;
            if (iter == end) {
                return url_parse_error{
                    "Expected to find authority segment following '//' in URL string"};
            }
            if (*iter == '/' && url.scheme != "file") {
                return url_parse_error{"Invalid URL string: Excessive slashes following shceme"};
            }
            while (iter != end && *iter != '/') {
                if (!is_url_char(*iter) && *iter != '%') {
                    return url_parse_error{"Invalid character in URL string host segment"};
                }
                ++iter;
            }

            const auto authority_str = pending();
            const auto at_pos        = authority_str.rfind('@');
            auto       host          = authority_str;
            if (at_pos != npos) {
                auto userinfo = authority_str.substr(0, at_pos);
                auto colpos   = userinfo.find(':');
                if (colpos != npos) {
                    url.username = userinfo.substr(0, colpos);
                    url.password = userinfo.substr(colpos + 1);
                } else {
                    url.username = userinfo;
                }
                host = authority_str.substr(at_pos + 1);
            }

            auto host_colpos = host.rfind(':');
            if (host_colpos != npos) {
                url.host               = std::make_optional(host.substr(0, host_colpos));
                auto          port_str = host.substr(host_colpos + 1);
                std::uint16_t port     = 0;
                auto          conv_res
                    = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port);
                if (conv_res.ec != std::errc{}) {
                    return url_parse_error{"Invalid port in URL string"};
                }
                url.port = std::make_optional(port);
            } else {
                url.host = std::make_optional(host);
            }
            place = iter;
        } else {
            // Not '//' following scheme
            if (opts.authority_required(url.scheme)) {
                return url_parse_error{"URL string expected an authority element"};
            }
            // No scheme, but that's okay for this URL scheme
        }

        while (iter != end && *iter != '?') {
            if (!is_url_char(*iter) && *iter != '%') {
                return url_parse_error{"Invalid character in URL string path segment"};
            }
            ++iter;
        }

        url.path = pending();
        place    = iter;

        if (iter != end && *iter == '?') {
            ++iter;
            place = iter;
            while (iter != end && *iter != '#') {
                if (!is_url_char(*iter) && *iter != '%') {
                    return url_parse_error{"Invalid character in URL string query segment"};
                }
                ++iter;
            }
            url.query = std::make_optional(pending());
            place     = iter;
        }
        if (iter != end && *iter == '#') {
            ++iter;
            place = iter;
            while (iter != end) {
                if (!is_url_char(*iter) && *iter != '%') {
                    return url_parse_error{"Invalid character in URL string fragment segment"};
                }
                ++iter;
            }
            url.fragment = std::make_optional(pending());
            place        = iter;
        }
        neo_assert(invariant,
                   iter == end,
                   "Did not consume the entire input as we expected",
                   input,
                   pending(),
                   *iter);
        return url;
    }
};

using url_view   = basic_url_view<std::string_view>;
using u8url_view = basic_url_view<std::u8string_view>;

}  // namespace neo