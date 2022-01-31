#pragma once

#include <utility>


namespace util::detail {

struct Defer {
};

template <typename F>
class DeferredFunctor {
public:
    DeferredFunctor(F func)
        : Func_{std::move(func)}
    {}

    DeferredFunctor(const DeferredFunctor& rhs) = delete;
    DeferredFunctor(DeferredFunctor&& rhs) noexcept = delete;

    DeferredFunctor& operator=(const DeferredFunctor& rhs) = delete;
    DeferredFunctor& operator=(DeferredFunctor&& rhs) noexcept = delete;

    ~DeferredFunctor() {
        Func_();
    }

private:
    F Func_;
};

template <typename F>
inline DeferredFunctor<F> operator<<=(const Defer&, F func) {
    return DeferredFunctor<F>{std::move(func)};
}

} // namespace util::detail

#define CAT2(a, b) a ## b
#define CAT(a, b) CAT2(a, b)

#define DEFER \
    auto CAT(internalDeferDoNotUse, __LINE__) = ::util::detail::Defer{} <<= [&]()
