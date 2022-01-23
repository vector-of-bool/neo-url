#include <neo/url.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace {

enum opt_comma { comma, no_comma };

void print_val(std::string_view val) {
    std::cout.put('"');
    for (auto c : val) {
        if (c == '\\' or c == '"') {
            std::cout.put('\\');
        }
        std::cout.put(c);
    }
    std::cout.put('"');
}

void print_val(int i) { std::cout << i; }

template <typename T>
void print_val(std::optional<T> t) {
    if (t) {
        print_val(*t);
    } else {
        std::cout << "null";
    }
}

template <typename V>
void print_kv(std::string_view key, V val, opt_comma c = comma) {
    std::cout << "    \"" << key << "\": ";
    print_val(val);
    if (c == comma) {
        std::cout << ',';
    }
    std::cout << '\n';
}

void print_result(neo::url_parse_error) {
    std::cout << "{\n";
    print_kv("result", "fail");
    print_kv("error", "Parse failure", no_comma);
    std::cout << "}\n";
}

void print_result(neo::url const& url) {
    std::cout << "{\n";
    print_kv("result", "okay");
    print_kv("scheme", url.scheme);
    print_kv("href", url.to_string());
    print_kv("username", url.username);
    print_kv("password", url.password);
    print_kv("host", url.host);
    print_kv("query", url.query);
    print_kv("fragment", url.fragment);
    print_kv("port", url.port);
    print_kv("pathname", url.path, no_comma);
    std::cout << "}\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " [url-file]\n";
        return 2;
    }
    std::ifstream infile{argv[1], std::ios::binary};
    if (!infile) {
        std::cerr << "Failed to open file [" << argv[1] << "] for reading.\n";
        return 1;
    }
    std::stringstream strm;
    strm << infile.rdbuf();
    infile.close();
    auto str    = strm.str();
    auto result = neo::url::try_parse(str);
    std::visit([](auto&& res) { print_result(res); }, result);
    return 0;
}
