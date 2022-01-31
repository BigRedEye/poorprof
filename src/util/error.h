#pragma once

#include <fmt/format.h>

#include <stdexcept>


namespace util {

class Error : public std::runtime_error {
public:
    template <typename ...Args>
    Error(std::string_view fmt, Args&& ...args)
        : std::runtime_error{fmt::vformat(fmt, fmt::make_format_args(std::forward<Args>(args)...))}
    {}
};

} // namespace util
