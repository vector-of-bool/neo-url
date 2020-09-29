#pragma once

#include "./url/percent.hpp"

#include <neo/assert.hpp>
#include <neo/opt_ref.hpp>

#include <cctype>
#include <charconv>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace neo {

struct url_validation_error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

namespace url_detail {

constexpr bool is_dec_digit(char32_t c) noexcept { return (c >= '0' && c <= '9'); }

constexpr bool is_hex_digit(char32_t c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

}  // namespace url_detail

constexpr bool is_url_char(char32_t c) {
    for (auto ok : U"!$&'()*+,-./:;=?@_~") {
        if (c == ok) {
            return true;
        }
    }
    if (c >= 0xa0 && c <= 0x10fffd) {
        if (c >= 0xd0'00 && c <= 0xdf'ff) {
            // Exclude surrogates
            return false;
        }
        if (c >= 0xfdd0 && c <= 0xfdef) {
            // Non-char range
            return false;
        }
        auto low  = c & 0xff'ff;
        auto high = (c >> 16) & 0xff;
        if (low == 0xff'ff || low == 0xff'fe) {
            if (high <= 0x10) {
                // A non-char
                return false;
            }
        }
        // Other unicode char:
        return true;
    }
    if (c >= '0' && c <= '9') {
        return true;
    }
    if (c >= 'a' && c <= 'z') {
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        return true;
    }
    return false;
}

template <typename String>
class basic_url {
public:
    using string_type     = String;
    using char_type       = typename string_type::value_type;
    using view_type       = std::basic_string_view<char_type>;
    using reference       = typename string_type::reference;
    using const_reference = typename string_type::const_reference;

    using allocator_type = typename string_type::allocator_type;

    using path_vec_type = std::vector<
        string_type,
        typename std::allocator_traits<allocator_type>::template rebind_alloc<string_type>>;

    using opt_string = std::optional<string_type>;

    struct host_t {
        enum kind { invalid, opaque, ipv6 };

        using ipv6_type = std::array<std::uint16_t, 8>;

        enum kind   kind = invalid;
        string_type string{};
        ipv6_type   ipv6_addr{};

        constexpr static std::optional<host_t> parse(view_type str,
                                                     bool      is_not_special = false) noexcept {
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

        constexpr static std::optional<host_t> parse_ipv6(view_type str) noexcept {
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
                    value *= 0x10;
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

        constexpr static std::optional<host_t> parse_opaque(view_type str) noexcept {
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

public:
    string_type                  scheme;
    opt_string                   host;
    opt_string                   query;
    opt_string                   fragment;
    std::optional<std::uint16_t> port;
    path_vec_type                path_elems{scheme.get_allocator()};

    basic_url() = default;
    explicit basic_url(allocator_type alloc)
        : scheme(alloc) {}

    constexpr static bool is_special_scheme(view_type s) noexcept {
        return s == "ftp" || s == "file" || s == "http" || s == "https" || s == "ws" || s == "wss";
    }
    constexpr bool is_special() const noexcept { return is_special_scheme(scheme); }

    constexpr allocator_type get_allocator() const noexcept { return scheme.get_allocator(); }

    constexpr static std::optional<std::uint16_t> default_port_for_scheme(view_type s) noexcept {
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

    static basic_url parse(view_type input) {
        auto res = try_parse(input);
        auto err = std::get_if<url_validation_error>(&res);
        if (err) {
            throw *err;
        }
        return std::get<basic_url>(std::move(res));
    }

    static std::variant<basic_url, url_validation_error> try_parse(view_type input) noexcept {
        bool at_flag           = false;
        bool square_flag       = false;
        bool password_tok_seen = false;

        enum state_t {
            scheme_start,
            scheme,
            no_scheme,
            file,
            file_slash,
            file_host,
            special_authority_slashes,
            special_authority_ignore_slashes,
            path_or_authority,
            authority,
            path_start,
            path,
            host,
            port,
            query,
            fragment,
        };
        state_t state = scheme_start;

        basic_url url;

        int marker = 0;

        auto              ptr        = input.cbegin();
        bool              is_special = false;
        const string_type empty_string{url.get_allocator()};
        string_type       buffer = empty_string;

        while (true) {
            const bool      at_end     = ptr == input.cend();
            const char_type c          = at_end ? char_type() : *ptr;
            const bool      is_solidus = c == char_type('/');
            const view_type remaining
                = at_end ? view_type() : input.substr((ptr - input.begin()) + 1);

            auto c_is_oneof = [&](view_type arr) { return arr.find_first_of(c) != arr.npos; };

            auto pct_check = [&] {
                if (c == '%') {
                    if (remaining.size() < 2 || url_detail::hex_decode(remaining[0]) < 0
                        || url_detail::hex_decode(remaining[1]) < 0) {
                        return false;
                    }
                }
                return true;
            };

            switch (state) {

            // https://url.spec.whatwg.org/#scheme-start-state
            case scheme_start: {
                if (std::isalpha(c)) {
                    buffer.push_back(char_type(std::tolower(c)));
                    state = scheme;
                    goto next;
                }
                state = no_scheme;
                --ptr;
                goto next;
            }

            // https://url.spec.whatwg.org/#scheme-state
            case scheme: {
                // Characters that should be appended to the scheme:
                if (std::isalnum(c) || c_is_oneof("+-.")) {
                    buffer.push_back(char_type(std::tolower(c)));
                    goto next;
                }
                // The scheme is terminated by the colon
                else if (c == ':') {
                    url.scheme = buffer;
                    is_special = is_special_scheme(url.scheme);
                    buffer     = empty_string;
                    if (url.scheme == "file") {
                        if (remaining.find("//") != 0) {
                            return url_validation_error(
                                "file:// URL must have two slash '/' characters following the "
                                "scheme");
                        }
                        state = file;
                    } else if (is_special) {
                        state = special_authority_slashes;
                    } else if (remaining.find("/") == 0) {
                        state = path_or_authority;
                        ++ptr;
                    } else {
                        return url_validation_error(
                            "URL string is invalid: Expected path-or-authority after 'scheme:' "
                            "prefix");
                    }
                } else {
                    // The character is invalid!
                    return url_validation_error(
                        "URL string is invalid (failed to parse a URL scheme)");
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#no-scheme-state
            case no_scheme: {
                return url_validation_error("URL string does not contain a scheme component");
            }

            case file: {
                if (c == '/' || c == '\\') {
                    state = file_slash;
                    goto next;
                } else {
                    state = path;
                    --ptr;
                }
                goto next;
            }

            case file_slash: {
                if (c == '\\') {
                    return url_validation_error(
                        "URL file path contains a forbidden '\\' character");
                } else if (is_solidus) {
                    state = file_host;
                } else {
                    state = path;
                    --ptr;
                }
                goto next;
            }

            case file_host: {
                if (at_end || c_is_oneof("/\\?#")) {
                    --ptr;
                    if (buffer.empty()) {
                        url.host = empty_string;
                        state    = path_start;
                    } else {
                        auto host = host_t::parse(buffer, !is_special);
                        if (!host) {
                            return url_validation_error(
                                "File URL is invalid: The host segment is not a valid host");
                        }
                        url.host = host->string;
                        if (url.host == "localhost") {
                            url.host = empty_string;
                        }
                        buffer = empty_string;
                        state  = path_start;
                    }
                } else {
                    buffer.push_back(c);
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#special-authority-slashes-state
            case special_authority_slashes: {
                if (is_solidus && remaining.find("/") == 0) {
                    state = special_authority_ignore_slashes;
                    ++ptr;
                } else {
                    return url_validation_error(
                        "URL string is invalid (Expected '//' following 'scheme:')");
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#special-authority-ignore-slashes-state
            case special_authority_ignore_slashes: {
                if (c != '/' && c != '\\') {
                    state = authority;
                    --ptr;
                } else {
                    return url_validation_error(
                        "Unexpected additional slash following 'scheme://' in URL");
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#path-or-authority-state
            case path_or_authority: {
                if (is_solidus) {
                    state = authority;
                } else {
                    state = path;
                    --ptr;
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#authority-state
            case authority: {
                // We don't like '@'
                if (c == char_type('@')) {
                    return url_validation_error(
                        "URL string is invalid: Unexpected '@' character in authority segment.");
                }
                // Check if we're at the end of the authority segment:
                else if (at_end || c_is_oneof("/?#")) {
                    if (at_flag && buffer == "") {
                        return url_validation_error(
                            "URL string is invalid: Unexpected character in authority segment");
                    }
                    std::advance(ptr, -(buffer.size() + 1));
                    buffer = empty_string;
                    state  = host;
                }
                // Just another character:
                else {
                    buffer.push_back(c);
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#host-state
            case host: {
                // Check if we have a port:
                if (c == char_type(':') && !square_flag) {
                    if (buffer.empty()) {
                        return url_validation_error(
                            "URL string is invalid: Expected host before colon in URL string.");
                    }
                    auto host = host_t::parse(buffer, !is_special);
                    if (!host) {
                        return url_validation_error(
                            "URL string is invalid: Host segment is not a valid host");
                    }
                    url.host = host->string;
                    buffer   = empty_string;
                    state    = port;
                } else if (at_end || c_is_oneof("/?#")) {
                    --ptr;
                    auto host = host_t::parse(buffer, !is_special);
                    if (!host) {
                        return url_validation_error(
                            "URL string is invalid: Host segment is not a valid host");
                    }
                    url.host = host->string;
                    buffer   = empty_string;
                    state    = path_start;
                } else {
                    if (c == char_type('[')) {
                        square_flag = true;
                    } else if (c == char_type(']')) {
                        square_flag = false;
                    }
                    buffer.push_back(c);
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#port-state
            case port: {
                if (std::isdigit(c)) {
                    buffer.push_back(c);
                } else if (at_end || c_is_oneof("/?#")) {
                    if (!buffer.empty()) {
                        std::int32_t port_i = 0;
                        auto         conv_res
                            = std::from_chars(buffer.data(), buffer.data() + buffer.size(), port_i);
                        if (conv_res.ec != std::errc{}) {
                            return url_validation_error("URL's host port is invalid. (Too long?)");
                        }
                        if (port >= std::numeric_limits<std::uint16_t>::max()) {
                            return url_validation_error("URL's host port is too large");
                        }
                        if (port_i != default_port_for_scheme(url.scheme)) {
                            url.port = port_i;
                        }
                        buffer = empty_string;
                    }
                    state = path_start;
                    --ptr;
                } else {
                    return url_validation_error("Invalid URL port segment.");
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#path-start-state
            case path_start: {
                if (is_special) {
                    if (c == '\\') {
                        return url_validation_error(
                            "The URL path should not begin with a '\\' character.");
                    }
                    state = path;
                    if (c != '/') {
                        --ptr;
                    }
                } else if (c == char_type('?')) {
                    state     = query;
                    url.query = empty_string;
                } else if (c == char_type('#')) {
                    state        = fragment;
                    url.fragment = empty_string;
                } else if (!at_end) {
                    state = path;
                    if (!is_solidus) {
                        --ptr;
                    }
                } else {
                    // Fires assertion:
                    marker = 533353;
                    break;
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#path-state
            case path: {
                if (at_end || c == '/' || c_is_oneof("?#") || (is_special && c == '\\')) {
                    if (buffer.size() >= 2 && buffer.size() <= 6
                        && percent_decode(buffer) == "..") {
                        if (!url.path_elems.empty()) {
                            url.path_elems.pop_back();
                        }
                        if (c != '/' && !is_special) {
                            url.path_elems.push_back(empty_string);
                        }
                    } else if (buffer == "." && !is_solidus) {
                        // Do nothing
                    } else if (buffer != ".") {
                        if (url.scheme == "file") {
                            // Check for a Windows drive letter. Ew...
                            if (buffer.size() == 2 && std::isalpha(buffer[0])
                                && (buffer[1] == char_type(':') || buffer[1] == char_type('|'))
                                && url.path_elems.empty()) {
                                if (url.host.has_value()) {
                                    return url_validation_error(
                                        "Windows drive letters may not be used with a host in a "
                                        "file:// URL");
                                }
                                buffer[1] = char_type(':');
                            }
                        }
                        url.path_elems.push_back(buffer);
                    }
                    buffer = empty_string;
                    if (url.scheme == "file" && (at_end || c_is_oneof("?#"))) {
                        if (!url.path_elems.empty() && url.path_elems.front().empty()) {
                            return url_validation_error(
                                "file:// URL contains excess empty path elements at the "
                                "beginning");
                        }
                    }
                    if (c == char_type('?')) {
                        url.query = empty_string;
                        state     = query;
                    }
                    if (c == char_type('#')) {
                        url.fragment = empty_string;
                        state        = fragment;
                    }
                } else {
                    if (c != char_type('%') && !is_url_char(c)) {
                        return url_validation_error(
                            "URL string contains an invalid character in its path segment");
                    } else if (!pct_check()) {
                        return url_validation_error("Invalid %-sequence in URL path.");
                    } else {
                        auto enc = percent_encode<path_pct_encode_set>(view_type(&c, 1));
                        buffer.append(enc);
                    }
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#query-state
            case query: {
                if (c == '#') {
                    url.fragment = empty_string;
                    state        = fragment;
                } else if (!at_end) {
                    if (c != '%' && !is_url_char(c)) {
                        return url_validation_error("Invalid character in URL query segment");
                    }
                    if (!pct_check()) {
                        return url_validation_error("Invalid %-sequence in URL query.");
                    }
                    auto enc = is_special
                        ? percent_encode<special_query_pct_encode_set>(view_type(&c, 1))
                        : percent_encode<query_pct_encode_set>(view_type(&c, 1));
                    url.query->append(enc);
                }
                goto next;
            }

            // https://url.spec.whatwg.org/#fragment-state
            case fragment: {
                if (!at_end) {
                    if (!pct_check()) {
                        return url_validation_error("Invalid %-sequence in URL fragment segment.");
                    }
                    auto enc = percent_encode<fragment_pct_encode_set>(view_type(&c, 1));
                    url.fragment->append(enc);
                }
                goto next;
            }
            }
            neo_assert_always(invariant,
                              false,
                              "Failed/unimplemented case in URL parsing code",
                              marker,
                              state,
                              input,
                              c,
                              buffer,
                              url.scheme,
                              url.host.value_or("[nullopt]"),
                              remaining,
                              at_end,
                              ptr - input.begin(),
                              at_flag,
                              password_tok_seen,
                              square_flag);
        next:
            if (ptr == input.cend()) {
                break;
            }
            ++ptr;
        }

        return url;
    }

    constexpr string_type path_string() const noexcept {
        string_type ret{get_allocator()};
        for (auto&& el : path_elems) {
            ret.push_back('/');
            ret.append(el);
        }
        return ret;
    }

    constexpr string_type to_string() const noexcept {
        string_type acc;
        acc = scheme;
        acc.push_back(':');
        if (host) {
            acc.push_back('/');
            acc.push_back('/');
            acc.append(*host);
            if (port) {
                acc.push_back(':');
                acc.append(std::to_string(int(*port)));
            }
        } else if (scheme == "file") {
            acc.push_back('/');
            acc.push_back('/');
        }
        if (!host && path_elems.size() > 1 && path_elems[0].empty()) {
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
