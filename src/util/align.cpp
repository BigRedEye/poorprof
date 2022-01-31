#include "align.h"


namespace util {

static_assert(AlignDown(3, 4) == 0);
static_assert(AlignDown(0, 4) == 0);
static_assert(AlignDown(0, 1) == 0);
static_assert(AlignDown(8, 8) == 8);
static_assert(AlignDown(9, 8) == 8);
static_assert(AlignDown(15, 8) == 8);
static_assert(AlignUp(0, 4) == 0);
static_assert(AlignUp(3, 4) == 4);
static_assert(AlignUp(1, 4) == 4);
static_assert(AlignUp(7, 8) == 8);
static_assert(AlignUp(8, 8) == 8);
static_assert(AlignUp(9, 8) == 16);
static_assert(AlignUp(15, 8) == 16);

} // namespace util
