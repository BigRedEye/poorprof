#pragma once

#include "types.h"

#include <cassert>


namespace util {

template <typename N>
constexpr bool IsPowerOfTwo(N value) {
    return value > 0 && 0 == (value & (value - 1));
}

template <typename N>
constexpr N AlignDown(N value, N alignment) {
    assert(IsPowerOfTwo(alignment));
    return value - (value & (alignment - 1));
}

template <typename N>
constexpr N AlignUp(N value, N alignment) {
    assert(IsPowerOfTwo(alignment));
    return AlignDown(value + alignment - 1, alignment);
}

template <typename N>
constexpr bool IsAligned(N value, N alignment) {
    assert(IsPowerOfTwo(alignment));
    return (value & ~(alignment - 1)) == value;
}

} // namespace util
