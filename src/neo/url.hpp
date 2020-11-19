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
        if (input.empty()) {
            return url_parse_error{"Empty string given for URL"};
        }

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
            cannot_be_a_base_url_path,
            query,
            fragment,
        };
        state_t state = scheme_start;

        // The URL that we will eventually return
        basic_url url;

        bool              is_special = false;
        const string_type empty_string{url.get_allocator()};
        string_type       buffer = empty_string;

        utf8_range chars{input};
        auto       ptr = chars.begin();

        auto peek = [&](int n) { return *std::next(ptr, n); };

        using std::move;

        while (true) {
            auto cp_res = *ptr;
            if (!!cp_res.error()) {
                switch (cp_res.error()) {
                case utf8_errc::invalid_start_byte:
                    return url_parse_error{"Invalid UTF-8: Invalid start byte"};
                case utf8_errc::invalid_continuation_byte:
                    return url_parse_error{"Invalid UTF-8: Invalid continuation byte"};
                case utf8_errc::need_more:
                    if (cp_res.size != 0) {
                        return url_parse_error{"Invalid UTF-8: Truncated stream"};
                    }
                    break;
                default:
                    return url_parse_error{"Unknown error in UTF-8 decode"};
                }
            }
            const bool     at_end     = ptr.at_end();
            const char32_t c          = cp_res.codepoint;
            const bool     is_solidus = c == U'/';
            auto           char_str   = ptr.tail_string().substr(0, cp_res.size);

            auto pct_check = [&] {
                if (c == '%') {
                    if (url_detail::hex_decode(peek(1).codepoint) < 0
                        || url_detail::hex_decode(peek(2).codepoint) < 0) {
                        return false;
                    }
                }
                return true;
            };

            switch (state) {

            // https://url.spec.whatwg.org/#scheme-start-state
            case scheme_start: {
                if (url_detail::is_ascii_alpha(c)) {
                    buffer.append(char_str);
                    state = scheme;
                    break;
                }
                return url_parse_error{"Invalid URL string"};
            }

            // https://url.spec.whatwg.org/#scheme-state
            case scheme: {
                // Characters that should be appended to the scheme:
                if (url_detail::is_ascii_alphanumeric(c) || c == oper::any_of('+', '-', '.')) {
                    buffer.append(char_str);
                    break;
                }
                // The scheme is terminated by the colon
                else if (c == ':') {
                    url.scheme = move(buffer);
                    is_special = opts.is_special_scheme(url.scheme);
                    buffer     = empty_string;
                    if (url.scheme == "file") {
                        if (peek(1).codepoint != '/' || peek(2).codepoint != '/') {
                            return url_parse_error{
                                "'file:' URL must have two slash '/' characters following the"
                                "scheme"};
                        }
                        state = file;
                    } else if (opts.authority_required(url.scheme)) {
                        state = special_authority_slashes;
                    } else if (peek(1).codepoint == '/') {
                        state = path_or_authority;
                        ++ptr;
                    } else {
                        url.path_elems.push_back(empty_string);
                        state                     = cannot_be_a_base_url_path;
                        url._cannot_be_a_base_url = true;
                    }
                } else {
                    // The character is invalid!
                    return url_parse_error{"URL string is invalid (failed to parse a URL scheme)"};
                }
                break;
            }

            // https://url.spec.whatwg.org/#no-scheme-state
            case no_scheme: {
                return url_parse_error{"URL string does not contain a scheme component"};
            }

            case file: {
                url.host = empty_string;
                if (c == '/' || c == '\\') {
                    state = file_slash;
                    break;
                } else {
                    state = path;
                    --ptr;
                }
                break;
            }

            case file_slash: {
                if (c == '\\') {
                    return url_parse_error{"URL file path contains a forbidden '\\' character"};
                } else if (is_solidus) {
                    state = file_host;
                } else {
                    state = path;
                    --ptr;
                }
                break;
            }

            case file_host: {
                if (at_end || (c == oper::any_of('/', '\\', '?', '#'))) {
                    --ptr;
                    if (buffer.empty()) {
                        url.host = empty_string;
                        state    = path_start;
                    } else {
                        auto host = host_t::parse(buffer, !is_special);
                        if (!host) {
                            return url_parse_error{
                                "File URL is invalid: The host segment is not a valid host"};
                        }
                        url.host = host->string;
                        if (url.host == "localhost") {
                            url.host = empty_string;
                        }
                        buffer = empty_string;
                        state  = path_start;
                    }
                } else {
                    buffer.append(char_str);
                }
                break;
            }

            // https://url.spec.whatwg.org/#special-authority-slashes-state
            case special_authority_slashes: {
                if (is_solidus && peek(1).codepoint == '/') {
                    state = special_authority_ignore_slashes;
                    ++ptr;
                } else {
                    return url_parse_error{
                        "URL string is invalid (Expected '//' following 'scheme:')"};
                }
                break;
            }

            // https://url.spec.whatwg.org/#special-authority-ignore-slashes-state
            case special_authority_ignore_slashes: {
                if (c != '/' && c != '\\') {
                    state = authority;
                    --ptr;
                } else {
                    return url_parse_error{
                        "Unexpected additional slash following 'scheme://' in URL"};
                }
                break;
            }

            // https://url.spec.whatwg.org/#path-or-authority-state
            case path_or_authority: {
                if (is_solidus) {
                    state = authority;
                } else {
                    state = path;
                    --ptr;
                }
                break;
            }

            // https://url.spec.whatwg.org/#authority-state
            case authority: {
                // Userinfo:
                if (c == '@') {
                    if (at_flag) {
                        buffer.insert(0, string_type("%40"));
                    }
                    at_flag = true;
                    utf8_range buf_u8{buffer};
                    for (auto cp_it = buf_u8.begin(); cp_it != buf_u8.end(); ++cp_it) {
                        auto cp = *cp_it;
                        if (cp.codepoint == ':' && !password_tok_seen) {
                            password_tok_seen = true;
                            continue;
                        }
                        auto tail = cp_it.tail_string().substr(0, cp.size);
                        auto enc  = percent_encode<userinfo_pct_encode_set>(tail);
                        if (password_tok_seen) {
                            url.password.append(enc);
                        } else {
                            url.username.append(enc);
                        }
                    }
                    buffer = empty_string;
                }
                // Check if we're at the end of the authority segment:
                else if (at_end || c == oper::any_of('/', '?', '#')) {
                    if (at_flag && buffer == "") {
                        return url_parse_error{
                            "URL string is invalid: Expected a host following '@' in authority"
                            "segment"};
                    }
                    for (auto _ignore [[maybe_unused]] : utf8_range{buffer}) {
                        --ptr;
                    }
                    --ptr;
                    buffer = empty_string;
                    state  = host;
                }
                // Just another character:
                else {
                    buffer.append(char_str);
                }
                break;
            }

            // https://url.spec.whatwg.org/#host-state
            case host: {
                // Check if we have a port:
                if (c == ':' && !square_flag) {
                    if (buffer.empty()) {
                        return url_parse_error{
                            "URL string is invalid: Expected host before colon in URL string."};
                    }
                    auto host = host_t::parse(buffer, !is_special);
                    if (!host) {
                        return url_parse_error{
                            "URL string is invalid: Host segment is not a valid host"};
                    }
                    url.host = host->string;
                    buffer   = empty_string;
                    state    = port;
                } else if (at_end || c == oper::any_of('/', '?', '#')) {
                    --ptr;
                    auto host = host_t::parse(buffer, !is_special);
                    if (!host) {
                        return url_parse_error{
                            "URL string is invalid: Host segment is not a valid host"};
                    }
                    url.host = host->string;
                    buffer   = empty_string;
                    state    = path_start;
                } else {
                    if (c == U'[') {
                        square_flag = true;
                    } else if (c == U']') {
                        square_flag = false;
                    }
                    buffer.append(char_str);
                }
                break;
            }

            // https://url.spec.whatwg.org/#port-state
            case port: {
                if (std::isdigit(c)) {
                    buffer.append(char_str);
                } else if (at_end || c == oper::any_of('/', '?', '#')) {
                    if (!buffer.empty()) {
                        std::int32_t port_i = 0;
                        auto         conv_res
                            = std::from_chars(buffer.data(), buffer.data() + buffer.size(), port_i);
                        if (conv_res.ec != std::errc{}) {
                            return url_parse_error{"URL's host port is invalid. (Too long?)"};
                        }
                        if (port >= std::numeric_limits<std::uint16_t>::max()) {
                            return url_parse_error{"URL's host port is too large"};
                        }
                        if (port_i != default_port_for_scheme(url.scheme)) {
                            url.port = port_i;
                        }
                        buffer = empty_string;
                    }
                    state = path_start;
                    --ptr;
                } else {
                    return url_parse_error{"Invalid URL port segment."};
                }
                break;
            }

            // https://url.spec.whatwg.org/#path-start-state
            case path_start: {
                if (is_special) {
                    if (c == '\\') {
                        return url_parse_error{
                            "The URL path should not begin with a '\\' character."};
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
                    // End of input. We're done!
                }
                break;
            }

            // https://url.spec.whatwg.org/#path-state
            case path: {
                if (at_end || c == '/' || c == oper::any_of('/', '?', '#')
                    || (is_special && c == '\\')) {
                    if (buffer.size() >= 2 && buffer.size() <= 6
                        && percent_decode(buffer) == "..") {
                        if (!url.path_elems.empty()) {
                            url.path_elems.pop_back();
                        }
                        if (c != '/') {
                            url.path_elems.push_back(empty_string);
                        }
                    } else if (buffer == "." && !is_solidus) {
                        // Do nothing
                    } else if (buffer != ".") {
                        if (url.scheme == "file") {
                            // Check for a Windows drive letter. Ew...
                            if (buffer.size() == 2 && url_detail::is_ascii_alpha(buffer[0])
                                && (buffer[1] == char_type(':') || buffer[1] == char_type('|'))
                                && url.path_elems.empty()) {
                                if (url.host.has_value()) {
                                    return url_parse_error{
                                        "Windows drive letters may not be used with a host in a "
                                        "file:// URL"};
                                }
                                buffer[1] = char_type(':');
                            }
                        }
                        url.path_elems.push_back(buffer);
                    }
                    buffer = empty_string;
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
                        return url_parse_error{
                            "URL string contains an invalid character in its path segment"};
                    } else if (!pct_check()) {
                        return url_parse_error{"Invalid %-sequence in URL path."};
                    } else {
                        auto enc = percent_encode<path_pct_encode_set>(char_str);
                        buffer.append(enc);
                    }
                }
                break;
            }

            // https://url.spec.whatwg.org/#cannot-be-a-base-url-path-state
            case cannot_be_a_base_url_path: {
                if (c == '?') {
                    url.query = empty_string;
                    state     = query;
                    break;
                } else if (c == '#') {
                    url.fragment = empty_string;
                    state        = fragment;
                } else {
                    if (!at_end && !is_url_char(c)) {
                        return url_parse_error{"Invalid character in URL path"};
                    } else if (c == '%' && !pct_check()) {
                        return url_parse_error{"Invalid %-sequence in URL path."};
                    } else {
                        auto enc = percent_encode<c0_control_pct_encode_set>(char_str);
                        url.path_elems.back().append(enc);
                    }
                }
                break;
            }

            // https://url.spec.whatwg.org/#query-state
            case query: {
                if (c == '#') {
                    url.fragment = empty_string;
                    state        = fragment;
                } else if (!at_end) {
                    if (c != '%' && !is_url_char(c)) {
                        return url_parse_error{"Invalid character in URL query segment"};
                    }
                    if (!pct_check()) {
                        return url_parse_error{"Invalid %-sequence in URL query."};
                    }
                    auto enc = is_special ? percent_encode<special_query_pct_encode_set>(char_str)
                                          : percent_encode<query_pct_encode_set>(char_str);
                    url.query->append(enc);
                }
                break;
            }

            // https://url.spec.whatwg.org/#fragment-state
            case fragment: {
                if (!at_end) {
                    if (!pct_check()) {
                        return url_parse_error{"Invalid %-sequence in URL fragment segment."};
                    }
                    auto enc = percent_encode<fragment_pct_encode_set>(char_str);
                    url.fragment->append(enc);
                }
                break;
            }
            default:
                neo_assert_always(invariant,
                                  false,
                                  "Failed/unimplemented case in URL parsing code",
                                  state,
                                  input,
                                  char_str,
                                  buffer,
                                  url.scheme,
                                  url.host.value_or("[nullopt]"),
                                  at_end,
                                  at_flag,
                                  password_tok_seen,
                                  square_flag);
            }
            if (ptr.at_end()) {
                break;
            }
            ++ptr;
        }

        return url;
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
