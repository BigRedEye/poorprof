#pragma once

namespace util {

struct NonCopyable {
    NonCopyable() = default;

    // Non copyable
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(NonCopyable&) = delete;

    // But moveable
    NonCopyable(NonCopyable&&) noexcept = default;
    NonCopyable& operator=(NonCopyable&&) = default;
};

} // namespace util
