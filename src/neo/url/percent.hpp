#pragma once

#include <neo/string.hpp>

#include <cstddef>
#include <iterator>
#include <string_view>

/// Refer: https://url.spec.whatwg.org/#percent-encoded-bytes

namespace neo {

namespace url_detail {

constexpr int hex_decode(char32_t b) {
    bool is_digit       = b >= 0x30 && b <= 0x39;
    bool is_upper_alpha = b >= 0x41 && b <= 0x46;
    bool is_lower_alpha = b >= 0x61 && b <= 0x66;
    if (is_digit) {
        return b - 0x30;
    } else if (is_upper_alpha) {
        return b - 0x41 + 10;
    } else if (is_lower_alpha) {
        return b - 0x61 + 10;
    } else {
        return -1;
    }
}

}  // namespace url_detail

struct c0_control_pct_encode_set {
    template <typename C>
    constexpr static bool is_c0_control(C b) {
        return b >= C(0) && b <= C(0x1f);
    }
    template <typename C>
    constexpr static bool contains(C b) {
        return is_c0_control(b) || (b > C(0x7e));
    }
};

struct fragment_pct_encode_set {
    template <typename C>
    constexpr static bool contains(C c) {
        for (auto bad : " \"<>`") {
            if (C(bad) == c) {
                return true;
            }
        }
        return c0_control_pct_encode_set::contains(c);
    }
};

struct query_pct_encode_set {
    template <typename C>
    constexpr static bool contains(C c) {
        for (auto bad : " \"#<>") {
            if (C(bad) == c) {
                return true;
            }
        }
        return c0_control_pct_encode_set::contains(c);
    }
};

struct special_query_pct_encode_set {
    template <typename C>
    constexpr static bool contains(C c) {
        return query_pct_encode_set::contains(c) || c == C('\'');
    }
};

struct path_pct_encode_set {
    template <typename C>
    constexpr static bool contains(C c) {
        return query_pct_encode_set::contains(c) || c == C('?') || c == C('`') || c == C('{')
            || c == C('}');
    }
};

struct userinfo_pct_encode_set {
    template <typename C>
    constexpr static bool contains(C c) {
        for (auto bad : "/:;=@|") {
            if (C(bad) == c) {
                return true;
            }
        }
        if (c >= C('[') && c <= C('^')) {
            return true;
        }
        return path_pct_encode_set::contains(c);
    }
};

struct component_pct_encode_set {
    template <typename C>
    constexpr static bool contains(C c) {
        if (c >= C('$') && c <= C('&')) {
            return true;
        }
        return userinfo_pct_encode_set::contains(c) || c == C('+') || c == C(',');
    }
};

struct www_form_pct_encode_set {
    template <typename C>
    constexpr static bool contains(C c) {
        return component_pct_encode_set::contains(c) || (c >= C('\'') && c <= C(')'))
            || (c == C('!')) || (c == C('~'));
    }
};

template <typename String>
constexpr string_type_t<String> percent_decode(const String& str) {
    using char_type = typename string_type_t<String>::value_type;
    using std::byte;
    // 1: Empty sequence
    auto ret = make_empty_string_from(str);
    ret.reserve(str.size());
    // 2: For each byte
    for (auto c_it = str.cbegin(); c_it != str.cend(); ++c_it) {
        auto c = *c_it;
        // 2.1 If byte is not 0x25 '%'
        if (byte(c) != byte('%')) {
            // 2.1: Append byte to output
            ret.push_back(c);
            continue;
        }
        // 2.2 Otherwise,
        if (std::distance(c_it, str.cend()) < 2) {
            // 2.2 We need at least two more bytes to hex-decode a byte value
            ret.push_back(c);
            continue;
        }
        // 2.2 Get the high and low nibble pair:
        std::advance(c_it, 1);
        auto c1   = char32_t(*c_it);
        auto high = url_detail::hex_decode(c1);
        std::advance(c_it, 1);
        auto c2  = char32_t(*c_it);
        auto low = url_detail::hex_decode(c2);
        // 2.2 Check if we actually decoded two nibbles
        if (high < 0 || low < 0) {
            // Not a hex pair. Just append those bytes
            ret.push_back(char_type('%'));
            ret.push_back(char_type(c1));
            ret.push_back(char_type(c2));
            continue;
        }
        // 2.3 Interpret as a hex value
        auto val = static_cast<char32_t>(high << 4 | low);
        ret.push_back(char_type(val));
    }
    return ret;
}

template <typename EncodeSet, typename String>
constexpr string_type_t<String> percent_encode(const String& str) {
    using char_type = typename string_type_t<String>::value_type;
    using std::byte;
    auto ret = make_empty_string_from(str);
    if (str.size() >= 3) {
        if (byte(str[0]) == byte('&') && byte(str[1]) == byte('#')
            && byte(str[str.size() - 1]) == byte(';')) {
            // 2.1:
            ret.push_back(char_type('%'));
            ret.push_back(char_type('2'));
            ret.push_back(char_type('6'));
            ret.push_back(char_type('%'));
            ret.push_back(char_type('2'));
            ret.push_back(char_type('3'));
            for (auto it = std::next(str.cbegin(), 2), end = std::prev(str.cend(), 1); it != end;
                 ++it) {
                ret.push_back(char_type(*it));
            }
            ret.push_back(char_type('%'));
            ret.push_back(char_type('3'));
            ret.push_back(char_type('b'));
            return ret;
        }
    }
    for (auto b_ : str) {
        auto b = byte(b_);
        if (EncodeSet::contains(b)) {
            ret.push_back(char_type('%'));
            auto                  high  = int(b) >> 4;
            auto                  low   = int(b) & 0b1111;
            constexpr const char* chars = "0123456789abcdef";
            ret.push_back(char_type(chars[high]));
            ret.push_back(char_type(chars[low]));
        } else {
            ret.push_back(char_type(b));
        }
    }
    return ret;
}

}  // namespace neo
