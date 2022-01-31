#pragma once

#include <algorithm>
#include <cstring>


namespace util {

////////////////////////////////////////////////////////////////////////////////

template <typename T, typename U, typename Func>
T LowerBoundBy(T lhs, T rhs, U value, Func f) {
    return std::lower_bound(lhs, rhs, value, [&f](auto&& lhs, auto&& rhs) {
        return std::invoke(f, lhs) < std::invoke(f, rhs);
    });
}

template <typename C, typename U, typename Func>
auto LowerBoundBy(C&& container, U value, Func f) {
    using std::begin;
    using std::end;
    return std::lower_bound(begin(container), end(container), value,
        [&f](const auto& lhs, const U& rhs) {
            return std::invoke(f, lhs) < rhs;
        });
}

////////////////////////////////////////////////////////////////////////////////

template <typename C>
void Sort(C&& container) {
    using std::begin;
    using std::end;
    return std::sort(begin(container), end(container));
}

template <typename C>
void Unique(C&& container) {
    using std::begin;
    using std::end;
    auto it = std::unique(begin(container), end(container));
    container.erase(it, end(container));
}

template <typename I, typename Func>
void SortBy(I begin, I end, Func f) {
    return std::sort(begin, end, [&f](const auto& lhs, const auto& rhs) {
        return f(lhs) < f(rhs);
    });
}

template <typename C, typename Func>
void SortBy(C&& container, Func f) {
    return SortBy(container.begin(), container.end(), f);
}

////////////////////////////////////////////////////////////////////////////////

namespace detail {

template <typename T>
class RangeIterator {
public:
    using difference_type = T; // NOLINT
    using value_type = T; // NOLINT
    using pointer = const T*; // NOLINT
    using reference = T; // NOLINT
    using iterator_category = std::random_access_iterator_tag; // NOLINT

public:
    RangeIterator(T value, T step)
        : value_{value}
        , step_{step}
    {}

    reference operator*() const {
        return value_;
    }

    pointer operator->() const {
        return &value_;
    }

    reference operator[](T pos) const {
        return value_ + pos * step_;
    }

    RangeIterator& operator++() {
        value_ += step_;
        return *this;
    }

    RangeIterator operator++(int) {
        RangeIterator prev = *this;
        ++*this;
        return prev;
    }

    RangeIterator& operator--() {
        value_ -= step_;
        return *this;
    }

    RangeIterator operator--(int) {
        RangeIterator prev = *this;
        --*this;
        return prev;
    }

    RangeIterator& operator+=(T diff) {
        value_ += step_ * diff;
        return *this;
    }

    RangeIterator& operator-=(T diff) {
        return *this += (-diff);
    }

    friend T operator-(RangeIterator lhs, RangeIterator rhs) {
        return (lhs.value_ - rhs.value_) / lhs.step_;
    }

    friend RangeIterator operator+(RangeIterator lhs, T diff) {
        return lhs += diff;
    }

    bool operator==(const RangeIterator& rhs) const {
        return value_ == rhs.value_;
    }

    bool operator!=(const RangeIterator& rhs) const {
        return !(*this == rhs);
    }

private:
    T value_{0};
    T step_{1};
};

template <typename T>
class RangeAdapter {
public:
    RangeAdapter(T begin, T end) : begin_{std::move(begin)}, end_{std::move(end)} {
    }

    T begin() const { // NOLINT(readability-identifier-naming)
        return begin_;
    }

    T end() const { // NOLINT(readability-identifier-naming)
        return end_;
    }

private:
    T begin_;
    T end_;
};

} // namespace detail

template <typename T>
auto xrange(T min, T max) { // NOLINT(readability-identifier-naming)
    return detail::RangeAdapter{detail::RangeIterator<T>{min, 1}, detail::RangeIterator<T>{max, 1}};
}

template <typename T>
auto xrange(T max) { // NOLINT(readability-identifier-naming)
    return xrange<T>(0, max);
}

} // namespace util
