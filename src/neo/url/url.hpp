#pragma once

#include "./fwd.hpp"

#include "./parse.hpp"
#include "./percent.hpp"
#include "./view.hpp"

#include <neo/memory.hpp>
#include <neo/utility.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace neo {

template <typename String>
class basic_url {
public:
    using string_type      = String;
    using char_type        = typename string_type::value_type;
    using string_view_type = std::basic_string_view<char_type>;
    using reference        = typename string_type::reference;
    using const_reference  = typename string_type::const_reference;

    using url_view_type = basic_url_view<string_view_type>;

    using allocator_type = typename string_type::allocator_type;

    using opt_string = std::optional<string_type>;

    struct host_t {
        enum kind { invalid, opaque, ipv6 };

        using ipv6_type = std::array<std::uint16_t, 8>;

        enum kind   kind = invalid;
        string_type string{};
        ipv6_type   ipv6_addr{};

        constexpr static std::optional<host_t> parse(string_view_type str,
                                                     bool is_not_special = false) noexcept {
            auto c_it = str.cbegin();

            // Check for an IPv6 address
            if (c_it != str.cend() && *c_it == '[') {
                if (*str.rbegin() != ']') {
                    return std::nullopt;
                }
                return parse_ipv6(str.substr(1, str.length() - 2));
            }

            // Non-special URLs will use opaque host types.
            if (is_not_special) {
                return parse_opaque(str);
            }

            // TODO: Do domain parsing, as specified:
            // https://url.spec.whatwg.org/#concept-host-parser
            return parse_opaque(str);
        }

        constexpr static std::optional<host_t> parse_ipv6(string_view_type str) noexcept {
            if (str.empty()) {
                return std::nullopt;
            }

            // New address:
            std::array<std::uint16_t, 8> addr = {};

            int  piece_idx = 0;
            int  compress  = -1;
            auto ptr       = str.cbegin();
            auto remaining = str.substr(1);
            auto c         = *ptr;
            if (c == ':') {
                ++ptr;
                if (ptr != str.cend() && *ptr == ':') {
                    // IP begins as '[::'
                    ++ptr;
                    ++piece_idx;
                    compress = piece_idx;
                } else {
                    // A string '[:]' is not a valid ipv6 addr
                    return std::nullopt;
                }
            }
            while (ptr != str.cend()) {
                c         = *ptr;
                remaining = str.substr((ptr - str.cbegin()) + 1);
                if (piece_idx == 8) {
                    // More than eight segments? Not valid
                    return std::nullopt;
                }
                if (c == ':') {
                    if (compress >= 0) {
                        // More than one compression: No
                        return std::nullopt;
                    }
                    ++ptr;
                    ++piece_idx;
                    compress = piece_idx;
                    continue;
                }
                std::uint16_t value  = 0;
                int           length = 0;
                while (length < 4 && url_detail::is_hex_digit(c)) {
                    value = static_cast<std::uint16_t>(value * 0x10);
                    value = static_cast<std::uint16_t>(value + url_detail::hex_decode(c));
                    ++ptr;
                    ++length;
                    c = ptr == str.cend() ? 0 : *ptr;
                }
                if (c == '.') {
                    if (length == 0) {
                        // Dot without digits
                        return std::nullopt;
                    }
                    ptr -= length;
                    if (piece_idx > 6) {
                        return std::nullopt;
                    }
                    int n_num_seen = 0;
                    while (ptr != str.cend()) {
                        int ipv4_piece = -1;
                        c              = *ptr;
                        if (n_num_seen > 0) {
                            if (c == '.' && n_num_seen < 4) {
                                ++ptr;
                            } else {
                                return std::nullopt;
                            }
                        }
                        // We expect a decimal digit following the dot '.'
                        if (!url_detail::is_dec_digit(c)) {
                            return std::nullopt;
                        }
                        // Parse sequence of digits
                        while (ptr != str.cend() && url_detail::is_dec_digit(*ptr)) {
                            c     = *ptr;
                            int n = c - '0';
                            if (ipv4_piece < 0) {
                                ipv4_piece = n;
                            } else if (ipv4_piece == 0) {
                                return std::nullopt;
                            } else {
                                ipv4_piece *= 10;
                                ipv4_piece += n;
                            }
                            if (ipv4_piece > 255) {
                                // ipv4 segments cannot be greater than 255
                                return std::nullopt;
                            }
                            ++ptr;
                        }
                        // Add that piece to the address
                        addr[piece_idx] = static_cast<std::uint16_t>(addr[piece_idx] * 0x100);
                        addr[piece_idx] = static_cast<std::uint16_t>(addr[piece_idx] + ipv4_piece);
                        ++n_num_seen;
                        if (n_num_seen == 2 || n_num_seen == 4) {
                            ++piece_idx;
                        }
                    }
                    if (n_num_seen != 4) {
                        // ipv4 expected to see four numbers
                        return std::nullopt;
                    }
                    break;
                } else if (c == ':') {
                    ++ptr;
                    if (ptr == str.cend()) {
                        return std::nullopt;
                    }
                } else if (ptr != str.cend()) {
                    return std::nullopt;
                }
                addr[piece_idx] = value;
                piece_idx += 1;
            }
            if (compress >= 0) {
                int swaps = piece_idx - compress;
                std::rotate(addr.begin() + compress, addr.begin() + compress + swaps, addr.end());
            }
            if (compress < 0 && piece_idx != 8) {
                // Expected 8 segments
                return std::nullopt;
            }
            return host_t{.kind = kind::ipv6, .ipv6_addr = addr};
        }

        constexpr static std::optional<host_t> parse_opaque(string_view_type str) noexcept {
            if (str.empty()) {
                return std::nullopt;
            }
            // Check that the host string is valid
            for (auto c_it = str.cbegin(); c_it != str.cend(); ++c_it) {
                auto c = *c_it;
                for (auto f : "\x00\t\x0a #/:<>?@[\\]^") {
                    if (char_type(c) == char_type(f)) {
                        // Host string contains a forbidden character
                        return std::nullopt;
                    }
                }
                if (c == '%') {
                    if (std::distance(c_it, str.cend()) < 3) {
                        // Host string contains a '%' without two trailing hex digitis
                        return std::nullopt;
                    }

                    auto c1 = *std::next(c_it);
                    auto c2 = *std::next(c_it, 2);
                    if (url_detail::hex_decode(c1) < 0 || url_detail::hex_decode(c2)) {
                        // Host string contains a '%' without two trailing hex digitis
                        return std::nullopt;
                    }
                }
            }

            return host_t{.kind   = kind::opaque,
                          .string = percent_encode<c0_control_pct_encode_set>(str)};
        }
    };

    template <typename Options>
    static void
    _normalize_path_inplace(string_type& path, string_view_type scheme, Options&& opts) noexcept {
        if (opts.normalize_paths(scheme)) {
            auto ds  = string_view_type("/./");
            auto dds = string_view_type("/../");
            for (auto ds_pos = path.find(ds); ds_pos != path.npos; ds_pos = path.find(ds)) {
                path.erase(ds_pos, 2);
            }
            for (auto pos = path.find(dds); pos != path.npos; pos = path.find(dds)) {
                path.erase(pos, 3);
                if (pos) {  // Don't erase if the dot-dot is at the beginning of the string
                    auto it = path.begin() + pos;
                    --it;
                    while (it != path.begin() && *it != '/') {
                        --it;
                    }
                    path.erase(it, path.begin() + pos);
                }
            }
            if (path.ends_with("/.")) {
                path.erase(path.size() - 2, 2);
            }
            if (path.ends_with("/..")) {
                path.erase(path.size() - 3, 3);
                auto it = path.end();
                if (it != path.begin()) {  // Don't erase if the dot-dot is at the beginning of
                                           // the string
                    --it;
                    while (it != path.begin() && *it != '/') {
                        --it;
                    }
                    path.erase(it, path.end());
                }
            }
        }
        if (path.empty()) {
            // Path _became_ empty via our normalization
            if (opts.force_full_path(scheme)) {
                path.push_back('/');
            }
        }
        percent_encode_inplace<path_pct_encode_set>(path);
    }

public:
    string_type                  scheme;
    string_type                  username{scheme.get_allocator()};
    string_type                  password{scheme.get_allocator()};
    opt_string                   host;
    opt_string                   query;
    opt_string                   fragment;
    std::optional<std::uint16_t> port;
    string_type                  path{scheme.get_allocator()};

    basic_url() = default;
    explicit basic_url(allocator_type alloc)
        : scheme(alloc) {}

    constexpr allocator_type get_allocator() const noexcept { return scheme.get_allocator(); }

    [[nodiscard]] constexpr static std::optional<std::uint16_t>
    default_port_for_scheme(string_view_type s) noexcept {
        if (s == "ftp")
            return 21;
        if (s == "http")
            return 80;
        if (s == "https")
            return 443;
        if (s == "ws")
            return 80;
        if (s == "wss")
            return 443;
        return std::nullopt;
    }
    [[nodiscard]] constexpr auto default_port() const noexcept {
        return default_port_for_scheme(scheme);
    }
    [[nodiscard]] constexpr auto port_or_default_port() const noexcept {
        return port ? port : default_port();
    }
    [[nodiscard]] constexpr auto port_or_default_port_or(std::uint16_t p) const noexcept {
        return port_or_default_port().value_or(p);
    }

    [[nodiscard]] constexpr static basic_url parse(string_view_type input) {
        auto res = try_parse(input);
        auto err = std::get_if<url_parse_error>(&res);
        if (err) {
            throw url_validation_error(std::string(err->error));
        }
        return std::get<basic_url>(std::move(res));
    }

    [[nodiscard]] constexpr basic_url normalized() const {
        return noramlize(*this, get_allocator());
    }

    constexpr void normalize() { *this = normalized(); }

    basic_url& clear_path() noexcept {
        path = make_empty_string_from(path);
        _normalize_path_inplace(path, scheme, default_url_options{});
        return *this;
    }

    basic_url& append_path(string_view_type view) noexcept {
        path.reserve(path.size() + view.size());
        if (path.empty() || path.back() != '/') {
            path.push_back('/');
        }
        while (!view.empty() && view.front() == '/') {
            view.remove_prefix(1);
        }
        path.append(view);
        _normalize_path_inplace(path, scheme, default_url_options{});
        return *this;
    }

    basic_url& operator/=(string_view_type view) noexcept {
        append_path(view);
        return *this;
    }

    basic_url operator/(string_view_type view) const noexcept {
        auto cp = *this;
        cp /= view;
        return cp;
    }

    basic_url& path_pop_back() noexcept {
        auto riter = path.rbegin();
        auto rstop = path.rend();
        while (riter != rstop && *riter == '/') {
            ++riter;
        }
        while (riter != rstop && *riter != '/') {
            ++riter;
        }
        while (riter != rstop && *riter == '/') {
            ++riter;
        }
        path.erase(riter.base(), path.end());
        if (path.empty() && default_url_options::force_full_path(scheme)) {
            path.push_back('/');
        }
        return *this;
    }

    template <typename Options = default_url_options>
    [[nodiscard]] constexpr static basic_url
    normalize(const url_view_type view, allocator_type alloc, Options opts = {}) {
        auto v   = try_normalize(view, alloc, opts);
        auto err = std::get_if<url_parse_error>(&v);
        if (err) {
            throw url_validation_error(std::string(err->error));
        }
        return std::get<basic_url>(std::move(v));
    }

    template <typename Options = default_url_options>
    [[nodiscard]] constexpr static std::variant<basic_url, url_parse_error>
    try_normalize(const url_view_type view, allocator_type alloc, Options opts = {}) noexcept {
        basic_url   ret{alloc};
        string_type empty_string{alloc};
        // Lower-case the scheme string
        ret.scheme.reserve(view.scheme.size());
        for (auto c : view.scheme) {
            ret.scheme.push_back(char_type(std::tolower(c)));
        }

        if (view.host) {
            ret.username
                = percent_encode<userinfo_pct_encode_set>(string_type(view.username, alloc));
            ret.password
                = percent_encode<userinfo_pct_encode_set>(string_type(view.password, alloc));

            if (view.host->empty() && opts.implicit_empty_authority(ret.scheme)) {
                // Host is empty string. This is allowed for file:// URLs
                ret.host.emplace(empty_string);
            } else {
                auto host = host_t::parse(*view.host);
                if (!host) {
                    return url_parse_error{"Invalid host string"};
                }
                ret.host.emplace(empty_string);
                for (auto c : host->string) {
                    ret.host->push_back(char_type(std::tolower(c)));
                }
            }
            if (view.port) {
                if (*view.port != default_port_for_scheme(ret.scheme)) {
                    // Non-default port for this scheme
                    ret.port = view.port;
                } else if (!opts.implicit_default_port(ret.scheme)) {
                    // The port is the same as the default, but we have been asked to keep those
                    // ports in the result
                    ret.port = view.port;
                } else {
                    // The port is the same as the scheme default, and caller wants us to drop it
                    // and allow it to be implicit. Okay.
                }
            }
        }
        if (!view.host) {
            if (opts.implicit_empty_authority(view.scheme)) {
                ret.host.emplace(empty_string);
            }
        }

        if (!view.path.empty()) {
            // Nonempty path, but we may need to "normalize" it
            ret.path = string_type(view.path, alloc);
            _normalize_path_inplace(ret.path, ret.scheme, opts);
        } else if (opts.force_full_path(ret.scheme)) {
            // The path is empty, but the scheme mandates that there be at least a slash
            ret.path = string_type("/", alloc);
        } else {
            // Empty path, but no forcing of the path. This is okay.
        }

        if (view.query) {
            auto q = string_type(*view.query, alloc);
            ret.query.emplace(opts.is_special_scheme(ret.scheme)
                                  ? percent_encode<special_query_pct_encode_set>(q)
                                  : percent_encode<query_pct_encode_set>(q));
        }

        if (view.fragment) {
            ret.fragment.emplace(
                percent_encode<fragment_pct_encode_set>(string_type(*view.fragment, alloc)));
        }

        return ret;
    }

    template <typename Options = default_url_options>
    [[nodiscard]] static constexpr std::variant<basic_url, url_parse_error>
    try_parse(string_view_type input, Options opts = {}) noexcept {
        auto sp = url_view_type::try_split(input, opts);
        if (std::holds_alternative<url_parse_error>(sp)) {
            return std::get<url_parse_error>(sp);
        } else {
            return try_normalize(std::get<url_view_type>(sp), allocator_type(), opts);
        }
    }

    [[nodiscard]] constexpr string_type to_string() const noexcept {
        url_view_type view = *this;
        return view.to_string();
    }

    [[nodiscard]] constexpr friend string_type to_string(const basic_url& self) noexcept {
        return self.to_string();
    }
};

}  // namespace neo
