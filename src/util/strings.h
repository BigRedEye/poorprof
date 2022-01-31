#pragma once

#include <string>
#include <type_traits>


namespace util {

template <typename T, typename = std::void_t<decltype(std::to_string(std::declval<T>()))>>
std::string ToString(const T& arg) {
    return std::to_string(arg);
}

template <size_t Count>
std::string ToString(const char (&arr)[Count]) {
    return std::string(arr, arr + Count);
}

template <typename ...Strs>
std::string Join(Strs&& ...strs) {
    std::string result;
    result.reserve((0 + ... + std::string_view{strs}.size()));
    (result += ... += std::forward<Strs>(strs));
    return result;
}

} // namespace util

using namespace std::string_view_literals;
