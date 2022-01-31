#pragma once

#include "error.h"
#include "strings.h"
#include "types.h"

#include <fmt/core.h>

#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>


namespace util {

struct SourceLocation {
    std::string_view File;
    u32 Line = 0;
};

inline std::string ToString(const SourceLocation& location) {
    return fmt::format("{}:{}", location.File, location.Line);
}

#define SOURCE_LOCATION \
    ::util::SourceLocation{__FILE__, __LINE__}

class ConditionViolated : public util::Error {
public:
    ConditionViolated(const SourceLocation& loc, std::string_view why, std::string_view msg)
        : util::Error{"{} at {}: {}", why, ToString(loc), msg}
    {
    }
};

#define ENSURE_EXCEPTION(cond, exc) \
    if (!(cond)) { \
        throw (exc); \
    }

#define THIRD_ARG(a, b, c, ...) c
#define ENSURE2(cond, msg) ENSURE_EXCEPTION(cond, (::util::ConditionViolated{SOURCE_LOCATION, "ENSURE failed", msg}))
#define ENSURE1(cond) ENSURE2(cond, "Condition " #cond " violated")
#define ENSURE(...) THIRD_ARG(__VA_ARGS__, ENSURE2, ENSURE1)(__VA_ARGS__)

////////////////////////////////////////////////////////////////////////////////

namespace detail {

inline void Panic(const char* where, const char* what) {
    long pid = 0;
#ifdef __linux__
    pid = ::getpid();
#endif
    fmt::print(stderr, "Thread {} panicked at {}: {}\n", pid, where, what);
    ::abort();
}

} // namespace detail

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)
#define SOURCE_LOCATION_STRING __FILE__ ":" STRINGIFY(__LINE__)

#define VERIFY_IMPL(cond, where, msg) \
    do { \
        if (!(cond)) {\
            ::util::detail::Panic(where, msg); \
        } \
    } while (0)
#define VERIFY2(cond, msg) VERIFY_IMPL(cond, SOURCE_LOCATION_STRING, msg)
#define VERIFY1(cond) VERIFY2(cond, "Condition `" STRINGIFY(cond) "' violated")
#define VERIFY(...) THIRD_ARG(__VA_ARGS__, VERIFY2, VERIFY1)(__VA_ARGS__)

#define FAIL(msg) \
    do { \
        ::util::detail::Panic(SOURCE_LOCATION_STRING, "Forced failure: " msg); \
    } while (0)

} // namespace util
