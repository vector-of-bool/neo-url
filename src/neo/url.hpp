#pragma once

#include "./url/fwd.hpp"
#include "./url/parse.hpp"
#include "./url/percent.hpp"
#include "./url/view.hpp"

#include <neo/assert.hpp>
#include <neo/memory.hpp>
#include <neo/opt_ref.hpp>
#include <neo/utf8.hpp>
#include <neo/utility.hpp>

#include <charconv>
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

    using path_vec_type = std::vector<string_type, rebind_alloc_t<allocator_type, string_type>>;

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
                    value *= 0x10u;
                    value += static_cast<std::uint16_t>(url_detail::hex_decode(c));
                    ++ptr;
                    ++length;
                    c = *ptr;
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
                        addr[piece_idx] *= 0x100;
                        addr[piece_idx] += static_cast<std::uint16_t>(ipv4_piece);
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

    bool _cannot_be_a_base_url = false;

public:
    string_type                  scheme;
    string_type                  username;
    string_type                  password;
    opt_string                   host;
    opt_string                   query;
    opt_string                   fragment;
    std::optional<std::uint16_t> port;
    path_vec_type                path_elems{scheme.get_allocator()};

    basic_url() = default;
    explicit basic_url(allocator_type alloc)
        : scheme(alloc) {}

    constexpr allocator_type get_allocator() const noexcept { return scheme.get_allocator(); }

    constexpr static std::optional<std::uint16_t>
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
    constexpr auto default_port() const noexcept { return default_port_for_scheme(scheme); }
    constexpr auto port_or_default_port() const noexcept { return port ? port : default_port(); }
    constexpr auto port_or_default_port_or(std::uint16_t p) const noexcept {
        return port_or_default_port().value_or(p);
    }

    constexpr static basic_url parse(string_view_type input) {
        auto res = try_parse(input);
        auto err = std::get_if<url_parse_error>(&res);
        if (err) {
            throw url_validation_error(std::string(err->error));
        }
        return std::get<basic_url>(std::move(res));
    }

    template <typename Options = default_url_parse_options>
    constexpr static basic_url
    normalize(const url_view_type view, allocator_type alloc, Options opts = {}) {
        auto v   = try_normalize(view, alloc, opts);
        auto err = std::get_if<url_parse_error>(&v);
        if (err) {
            throw url_validation_error(std::string(err->error));
        }
        return std::get<basic_url>(std::move(v));
    }

    template <typename Options = default_url_parse_options>
    constexpr static std::variant<basic_url, url_parse_error>
    try_normalize(const url_view_type view, allocator_type alloc, Options opts = {}) noexcept {
        basic_url ret{alloc};
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

            if (view.host->empty() && ret.scheme == "file") {
                // Host is empty string. This is allowed for file:// URLs
                ret.host.emplace(alloc);
            } else {
                auto host = host_t::parse(*view.host);
                if (!host) {
                    return url_parse_error{"Invalid host string"};
                }
                ret.host.emplace(host->string);
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

        if (!view.path.empty()) {
            // Nonempty path, but we may need to "normalize" it
            auto path = string_type(view.path, alloc);
            if (opts.normalize_paths(ret.scheme)) {
                auto ds  = string_view_type("/./");
                auto dds = string_view_type("/../");
                for (auto ds_pos = path.find(ds); ds_pos != path.npos; ds_pos = path.find(ds)) {
                    path.erase(ds_pos, 2);
                }
                for (auto pos = path.find(dds); pos != path.npos; pos = path.find(dds)) {
                    path.erase(pos, 3);
                    auto it = path.begin() + pos;
                    --it;
                    while (it != path.begin() && *it != '/') {
                        --it;
                    }
                    path.erase(it, path.begin() + pos);
                }
                if (path.ends_with("/.")) {
                    path.erase(path.size() - 2, 2);
                }
                if (path.ends_with("/..")) {
                    path.erase(path.size() - 3, 3);
                    auto it = path.end();
                    --it;
                    while (it != path.begin() && *it != '/') {
                        --it;
                    }
                    path.erase(it, path.end());
                }
            }
            if (path.empty()) {
                // Path _became_ empty via our normalization
                if (opts.force_full_path(ret.scheme)) {
                    path.push_back('/');
                }
            }
            ret.path_elems.emplace_back(percent_encode<path_pct_encode_set>(path));
        } else if (opts.force_full_path(ret.scheme)) {
            // The path is empty, but the scheme mandates that there be at least a slash
            ret.path_elems.emplace_back("/", alloc);
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

    template <typename Options = default_url_parse_options>
    static constexpr std::variant<basic_url, url_parse_error>
    try_parse(string_view_type input, Options opts = {}) noexcept {
        auto sp = url_view_type::try_split(input, opts);
        if (std::holds_alternative<url_parse_error>(sp)) {
            return std::get<url_parse_error>(sp);
        } else {
            return try_normalize(std::get<url_view_type>(sp), allocator_type(), opts);
        }
    }

    constexpr string_type path_string() const noexcept {
        string_type ret{get_allocator()};
        if (_cannot_be_a_base_url) {
            ret.append(path_elems.front());
        } else {
            for (auto&& el : path_elems) {
                // ret.push_back('/');
                ret.append(el);
            }
        }
        return ret;
    }

    constexpr string_type to_string() const noexcept {
        string_type acc = scheme;
        acc.push_back(':');
        if (host) {
            acc.push_back('/');
            acc.push_back('/');
            if (!username.empty() || !password.empty()) {
                acc.append(username);
                if (!password.empty()) {
                    acc.push_back(':');
                    acc.append(password);
                }
                acc.push_back('@');
            }
            acc.append(*host);
            if (port) {
                acc.push_back(':');
                acc.append(std::to_string(int(*port)));
            }
        } else if (scheme == "file") {
            acc.push_back('/');
            acc.push_back('/');
        }
        if (!host && path_elems[0].starts_with("//")) {
            acc.push_back('/');
            acc.push_back('.');
        }
        acc.append(path_string());
        if (query) {
            acc.push_back('?');
            acc.append(*query);
        }
        if (fragment) {
            acc.push_back('#');
            acc.append(*fragment);
        }
        return acc;
    }

    constexpr friend string_type to_string(const basic_url& self) noexcept {
        return self.to_string();
    }
};

using url = basic_url<std::string>;

}  // namespace neo
