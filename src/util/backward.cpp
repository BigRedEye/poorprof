#if BACKWARD_HAS_BACKTRACE_SYMBOL
#include <dlfcn.h>
#endif

#include <backward.hpp>

namespace util::backward {

::backward::SignalHandling sh;

} // namespace util::backward
