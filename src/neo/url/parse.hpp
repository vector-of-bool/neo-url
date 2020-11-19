#pragma once

#include <neo/utility.hpp>

#include <stdexcept>
#include <string_view>

namespace neo {

struct url_parse_error {
    std::string_view error;
};

struct url_validation_error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

namespace url_detail {

constexpr bool is_dec_digit(char32_t c) noexcept { return neo::between(c, '0', '9'); }

constexpr bool is_hex_digit(char32_t c) noexcept {
    return is_dec_digit(c) || neo::between(c, 'a', 'f') || neo::between(c, 'A', 'F');
}

constexpr bool is_ascii_alpha(char32_t c) noexcept {
    return neo::between(c, 'a', 'z') || neo::between(c, 'A', 'Z');
}

constexpr bool is_ascii_alphanumeric(char32_t c) noexcept {
    return is_ascii_alpha(c) || is_dec_digit(c);
}

}  // namespace url_detail

struct default_url_parse_options {
    constexpr static bool is_special_scheme(std::string_view sv) {
        return sv == oper::any_of("http", "https", "ftp", "file", "ws", "wss");
    }

    constexpr static bool authority_required(std::string_view scheme) {
        return is_special_scheme(scheme);
    }

    constexpr static bool force_full_path(std::string_view scheme) {
        return is_special_scheme(scheme);
    }

    constexpr static bool implicit_default_port(std::string_view scheme) {
        return is_special_scheme(scheme);
    }

    constexpr static bool normalize_paths(std::string_view) { return true; }
};

constexpr bool is_url_char(char32_t c) {
    if (c
        == oper::any_of('!',
                        '$',
                        '&',
                        '\'',
                        '(',
                        ')',
                        '*',
                        '+',
                        ',',
                        '-',
                        '.',
                        '/',
                        ':',
                        ';',
                        '=',
                        '?',
                        '@',
                        '_',
                        '~')) {
        return true;
    }
    using neo::between;
    if (between(c, 0xa0, 0x10fffd)) {
        if (between(c, 0xd0'00, 0xdf'ff)) {
            // Exclude surrogates
            return false;
        }
        if (between(c, 0xfdd0, 0xfdef)) {
            // Non-char range
            return false;
        }
        auto low  = c & 0xff'ff;
        auto high = (c >> 16) & 0xff;
        if (between(c, low, high)) {
            if (high <= 0x10) {
                // A non-char
                return false;
            }
        }
        // Other unicode char:
        return true;
    }
    if (url_detail::is_ascii_alphanumeric(c)) {
        return true;
    }
    return false;
}

}  // namespace neo