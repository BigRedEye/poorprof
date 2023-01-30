#include "demangle.h"
#include "util/error.h"

#include <cxxabi.h>

#include <utility>


namespace util {

namespace {

class MallocedBuffer {
public:
    static MallocedBuffer Allocate(size_t size) {
        return MallocedBuffer{SafeMalloc(size), size};
    }

    static MallocedBuffer Acquire(char* ptr, size_t size) {
        return MallocedBuffer{ptr, size};
    }

public:
    MallocedBuffer(MallocedBuffer&& rhs) noexcept {
        *this = std::move(rhs);
    }

    MallocedBuffer& operator=(MallocedBuffer&& rhs) noexcept {
        std::swap(Begin_, rhs.Begin_);
        std::swap(Size_, rhs.Size_);
        return *this;
    }

    ~MallocedBuffer() {
        ::free(Begin_);
    }

    std::pair<char*, size_t> UnsafeRelease() {
        std::pair<char*, size_t> res;
        res.first = std::exchange(Begin_, nullptr);
        res.second = std::exchange(Size_, 0);
        return res;
    }

public:
    const char* Begin() const {
        return Begin_;
    }

    char* Begin() {
        return Begin_;
    }

    size_t Size() const {
        return Size_;
    }

private:
    static char* SafeMalloc(size_t size) {
        char* res = static_cast<char*>(::malloc(size));
        if (res == nullptr) {
            throw std::bad_alloc{};
        }
        return res;
    }

private:
    MallocedBuffer(char* ptr, size_t size)
        : Begin_{ptr}
        , Size_{size}
    {}

private:
    char* Begin_ = nullptr;
    size_t Size_ = 0;
};

bool ShouldDemangle(std::string_view symbol) {
    return symbol.starts_with("_Z");
}

std::string DemangleImpl(std::string_view symbol) {
    // https://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html
    enum EDemangleResult {
        kSuceess = 0,
        kBadAlloc = -1,
        kInvalidMangledName = -2,
        kInvalidArgument = -3,
    };

    static thread_local MallocedBuffer DemangleBuf = MallocedBuffer::Allocate(1024);
    auto [ptr, size] = DemangleBuf.UnsafeRelease();

    int status = 0;
    ptr = __cxxabiv1::__cxa_demangle(symbol.data(), ptr, &size, &status);
    if (ptr) {
        DemangleBuf = MallocedBuffer::Acquire(ptr, size);
    }

    switch (status) {
    case kSuceess:
        break;
    case kBadAlloc:
        throw std::bad_alloc{};
    case kInvalidMangledName:
        return std::string{symbol};
    case kInvalidArgument:
        throw util::Error{"Failed to demangle symbol name"};
    }

    return std::string{ptr};
}

void DemangleInplace(std::string& s) {
    if (ShouldDemangle(s)) {
        s = DemangleImpl(s);
    }
}

} // namespace

std::string Demangle(std::string symbol) {
    DemangleInplace(symbol);
    return symbol;
}

} // namespace util
