#pragma once


namespace util {

template <typename It>
class IteratorRange {
public:
    IteratorRange(It begin, It end)
        : Begin_{begin}
        , End_{end}
    {}

    // NOLINTNEXTLINE
    It begin() const {
        return Begin_;
    }

    // NOLINTNEXTLINE
    It end() const {
        return End_;
    }

private:
    It Begin_;
    It End_;
};

template <typename It>
IteratorRange(It, It) -> IteratorRange<It>;

template <typename C>
auto Reversed(C&& cont) {
    return IteratorRange{cont.rbegin(), cont.rend()};
}

} // namespace util
