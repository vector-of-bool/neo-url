#pragma once

#include <string>
#include <string_view>

namespace neo {

template <typename String>
class basic_url;

template <typename ViewType>
class basic_url_view;

using url        = basic_url<std::string>;
using u8url      = basic_url<std::u8string>;
using url_view   = basic_url_view<std::string_view>;
using u8url_view = basic_url_view<std::u8string_view>;

}  // namespace neo
