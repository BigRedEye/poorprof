#include <cpparg/cpparg.h>

#include <fmt/format.h>
#include <fmt/chrono.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <chrono>
#include <compare>
#include <csignal>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <thread>

#include <absl/container/inlined_vector.h>
#include <absl/container/flat_hash_map.h>
#include <absl/hash/hash.h>

#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwelf.h>
#include <dwarf.h>

#include <sys/types.h>

/// UTIL
namespace util {

class Error : public std::runtime_error {
public:
    template <typename ...Args>
    Error(std::string_view format, Args&& ...args)
        : std::runtime_error{fmt::format(format, std::forward<Args>(args)...)}
    {
    }
};

} // namespace util

// UTIL::ALGO

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

namespace util::ctrlc {

namespace {

std::atomic<bool> Stopped = false;
std::atomic<int> SigIntsLeft = 0;

} // namespace 

void HandleSigInt(int maxtries) {
    SigIntsLeft.store(maxtries);
    ::signal(SIGINT, +[](int) {
        if (SigIntsLeft.fetch_sub(1) <= 1) {
            ::signal(SIGINT, SIG_DFL);
        }
        Stopped.store(true, std::memory_order_release);
    });
}

bool WasInterrupted() {
    return Stopped.load(std::memory_order_acquire);
}

} // namespace util::ctrlc

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

#define DEFER \
    auto internalDeferDoNotUse ## __LINE__ = ::util::detail::Defer{} <<= [&]()

/// ABI
#include <cxxabi.h>

namespace cxx::abi {

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

std::string Demangle(std::string_view symbol) {
    // https://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html
    enum EDemangleResult {
        kSuceess = 0,
        kBadAlloc = -1,
        kInvalidMangledName = -2,
        kInvalidArgument = -3,
    };

    static thread_local MallocedBuffer DemangleBuf = MallocedBuffer::Allocate(64);
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
        s = Demangle(s);
    }
}

} // namespace cxx::abi

class IUnwinder {
public:
    virtual ~IUnwinder() = default;

    virtual void Unwind() = 0;
};

namespace poorprof::dw {

class DwflError : public std::runtime_error {
public:
    DwflError()
        : DwflError{-1}
    {}

    explicit DwflError(int errn)
        : std::runtime_error{fmt::format("dwfl failed: {}", dwfl_errmsg(errn))}
    {
    }
};

#define CHECK_DWFL(...) \
    if (int err = (__VA_ARGS__); err != 0) { \
        if (err < 0) { \
            throw DwflError{}; \
        } \
        throw std::system_error{err, std::system_category()}; \
    }


class Unwinder final : public IUnwinder {
    struct Frame {
        Dwarf_Addr InstructionPointer = 0;
        bool IsActivation = false;

        auto operator<=>(const Frame& rhs) const noexcept = default;

        Dwarf_Addr InstructionPointerAdjusted()  {
            return InstructionPointer - (IsActivation ? 0 : 1);
        }

        template <typename H>
        friend H AbslHashValue(H h, const Frame& frame) {
            return H::combine(std::move(h), frame.InstructionPointer, frame.IsActivation);
        }
    };

    struct SourceLocation {
        std::string File;
        int Line = 0;
        int Column = 0;
    };

    struct Symbol {
        struct Frame Frame;

        std::optional<std::string> Name;
        std::optional<std::string> FileName;
        std::optional<SourceLocation> Location;

        bool Inlined = false;
        bool IsSignal = false;
    };

    using SymbolList = absl::InlinedVector<Symbol, 2>;

public:
    Unwinder(pid_t pid, std::optional<std::filesystem::path> debuginfo = std::nullopt)
        : Pid_{pid}
        , DebugInfo_{std::move(debuginfo)}
        , DebugInfoPath_{DebugInfo_ ? DebugInfo_->data() : nullptr}
        , Callbacks_{
            .find_elf = dwfl_linux_proc_find_elf,
            .find_debuginfo = dwfl_standard_find_debuginfo,
            .debuginfo_path = &DebugInfoPath_,
        }
    {
        InitializeDwfl();
        FillDwflReport();
        AttachToProcess();
        ValidateAttachedPid();
    }

    Unwinder(const Unwinder&) = delete;
    Unwinder(Unwinder&&) noexcept = delete;

    Unwinder& operator=(const Unwinder&) = delete;
    Unwinder& operator=(Unwinder&&) noexcept = delete;

    ~Unwinder() {
        if (Dwfl_) {
            dwfl_end(Dwfl_);
        }
    }

    void Unwind() override {
        dwfl_getthreads(Dwfl_, +[](Dwfl_Thread* thread, void* arg) -> int {
            static_cast<Unwinder*>(arg)->HandleThread(thread);
            return DWARF_CB_OK;
        }, this);
    }

    void DumpTraces() {
        size_t numHits = 0;
        for (auto&& [_, trace] : Traces_) {
            fmt::print("{} {}\n", trace.ResolvedTrace, trace.HitCount);
            numHits += trace.HitCount;
        }
        spdlog::info("Dumped {} different stacktraces with {} samples", Traces_.size(), numHits);
    }

private:
    using FrameList = absl::InlinedVector<Frame, 128>;

    struct TraceInfo {
        size_t HitCount = 0;
        std::string ResolvedTrace;
    };

    void HandleThread(Dwfl_Thread* thread) {
        FrameList frames;

        pid_t tid = dwfl_thread_tid(thread);

        int err = dwfl_thread_getframes(thread, +[](Dwfl_Frame* raw, void* arg) -> int {
            FrameList* frames = static_cast<FrameList*>(arg);
            Frame& frame = frames->emplace_back();
            dwfl_frame_pc(raw, &frame.InstructionPointer, &frame.IsActivation);
            return DWARF_CB_OK;
        }, &frames);

        if (err == -1) {
            int errn = dwfl_errno();
            if (strcmp(dwfl_errmsg(errn), "No such process") == 0) {
                return;
            }
            spdlog::error("Failed to get thread frames: {}", dwfl_errmsg(errn));
            return;
        }

        spdlog::debug("Thread {} of process {}", tid, Pid_);
        spdlog::debug("Found {} frames", frames.size());

        TraceInfo& trace = Traces_[absl::Hash<FrameList>{}(frames)];
        if (trace.HitCount++ > 0) {
            return;
        }

        fmt::memory_buffer traceBuf;
        fmt::format_to(traceBuf, "{}", ThreadName(tid));

        unsigned frameNumber = 0;
        for (Frame frame : util::Reversed(frames)) {
            const SymbolList& symbols = ResolveFrame(frame);
            for (const Symbol& sym : util::Reversed(symbols)) {
                // fmt::print("#{:<#4}", frameNumber++);
                if (!sym.Name) {
                    // fmt::print("{:#018x}\n", sym.Frame.InstructionPointer);
                    fmt::format_to(traceBuf, ";{:#018x}", sym.Frame.InstructionPointer);
                    continue;
                }

                std::stringstream location;
                if (auto& loc = sym.Location) {
                    location << " at " << loc->File;
                    if (loc->Line > 0) {
                        location << ':' << loc->Line;
                        if (loc->Column > 0) {
                            location << ':' << loc->Column;
                        }
                    }
                }
                // fmt::print("{}{}{}\n", sym.Name.value_or("<unknown>"), sym.Inlined ? " (inlined)" : "", location.str());
                fmt::format_to(traceBuf, ";{}{}{}", sym.Name.value_or("<unknown>"), sym.Inlined ? " (inlined)" : "", location.str());
            }
        }
        trace.ResolvedTrace = std::string{traceBuf.data(), traceBuf.size()};
    }

    std::string ThreadName(pid_t tid) {
#ifdef __linux__
        if (auto it = ThreadNameCache_.find(tid); it != ThreadNameCache_.end()) {
            return it->second;
        }

        std::ifstream input{fmt::format("/proc/{}/comm", tid)};
        std::string name;
        std::getline(input, name);

        return ThreadNameCache_[tid] = name;
#else
        return "<unknown thread>";
#endif
    }

    const SymbolList& ResolveFrame(Frame frame) {
        if (auto it = SymbolCache_.find(frame); it != SymbolCache_.end()) {
            return it->second;
        }
        return SymbolCache_[frame] = ResolveFrameImpl(frame);
    }

    SymbolList ResolveFrameImpl(Frame frame) {
        spdlog::debug("Start resolve frame at rip {}", frame.InstructionPointer);

        Dwfl_Module* module = dwfl_addrmodule(Dwfl_, frame.InstructionPointerAdjusted());
        if (!module) {
            return {{
                .Name = "<unknown>",
            }};
        }

        // DIE stands for Debug Info Element
        std::optional<Dwarf_Die> debugInfoElement;

        Dwarf_Addr offset = 0;
        Dwarf_Die* comilationUnitDebugInfoElement = dwfl_module_addrdie(module, frame.InstructionPointerAdjusted(), &offset);

        Dwarf_Die* scopes = nullptr;
        int numScopes = dwarf_getscopes(comilationUnitDebugInfoElement, frame.InstructionPointerAdjusted() - offset, &scopes);
        DEFER {
            ::free(scopes);
        };

        const char* firstSymbolName = nullptr;
        if (numScopes > 0) {
            spdlog::debug("Found {} scopes", numScopes);

            for (Dwarf_Die* scope = scopes; scope < scopes + numScopes; ++scope) {
                if (IsInlinedScope(scope)) {
                    firstSymbolName = TryGetDebugInfoElementLinkageName(scope);
                }

                if (firstSymbolName) {
                    debugInfoElement = *scope;
                    break;
                }
            }
        }

        if (firstSymbolName == nullptr) {
            firstSymbolName = dwfl_module_addrname(module, frame.InstructionPointerAdjusted());
        }

        SymbolList symbols;
        symbols.push_back(FillSymbol(frame, module, firstSymbolName, nullptr, nullptr, false));
        if (debugInfoElement) {
            Dwarf_Die* scopes = nullptr;
            int numInlinedSymbols = dwarf_getscopes_die(&*debugInfoElement, &scopes);
            DEFER {
                ::free(scopes);
            };

            Dwarf_Die* prevScope = scopes;
            for (Dwarf_Die* scope = scopes + 1; scope < scopes + numInlinedSymbols; ++scope) {
                int tag = dwarf_tag(scope);
                if (IsInlinedScope(tag)) {
                    const char* inlinedSymbolName = TryGetDebugInfoElementLinkageName(scope);
                    symbols.push_back(FillSymbol(frame, module, inlinedSymbolName, comilationUnitDebugInfoElement, prevScope, true));
                    prevScope = scope;
                }

                if (tag == DW_TAG_subprogram) {
                    break;
                }
            }
        }

        return symbols;
    }

    Symbol FillSymbol(Frame frame, Dwfl_Module* module, const char* name, Dwarf_Die* cudie, Dwarf_Die* lastScope, bool inlined) {
        Symbol sym{
            .Frame = frame,
            .Inlined = inlined,
            .IsSignal = frame.IsActivation,
        };

        if (name) {
            sym.Name = cxx::abi::Demangle(name);
        }

        {
            const char* fileName = dwfl_module_info(module, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            if (fileName) {
                sym.FileName = fileName;
            }
        }

        SourceLocation location;
        if (lastScope) {
            Dwarf_Files* files = nullptr;
            if (dwarf_getsrcfiles(cudie, &files, NULL) == 0) {
                Dwarf_Attribute attr;
                Dwarf_Word val = 0;
                if (dwarf_formudata(dwarf_attr(lastScope, DW_AT_call_file, &attr), &val) == 0) {
                    location.File = dwarf_filesrc(files, val, NULL, NULL);
                    if (dwarf_formudata(dwarf_attr(lastScope, DW_AT_call_line, &attr), &val) == 0) {
                        location.Line = val;
                        if (dwarf_formudata(dwarf_attr(lastScope, DW_AT_call_column, &attr), &val) == 0) {
                            location.Column = val;
                        }
                    }
                }
            }
        } else {
            Dwfl_Line* line = dwfl_module_getsrc(module, frame.InstructionPointerAdjusted());
            if (line) {
                const char* name = dwfl_lineinfo(line, nullptr, &location.Line, &location.Column, nullptr, nullptr);
                if (name) {
                    location.File = name;
                }
            }
        }

        if (!location.File.empty()) {
            sym.Location = std::move(location);
        }

        return sym;
    }

    static const char* TryGetDebugInfoElementLinkageName(Dwarf_Die *die) {
        Dwarf_Attribute dummy;

        Dwarf_Attribute* attr = dwarf_attr_integrate(die, DW_AT_MIPS_linkage_name, &dummy);
        if (!attr) {
            attr = dwarf_attr_integrate(die, DW_AT_linkage_name, &dummy);
        }

        const char* name = nullptr;
        if (attr) {
            name = dwarf_formstring(attr);
        }

        if (!name) {
            name = dwarf_diename(die);
        }
        return name;
    }

    static bool IsInlinedScope(Dwarf_Die* scope) {
        return IsInlinedScope(dwarf_tag(scope));
    }

    static bool IsInlinedScope(int dwarfTag) {
        static constexpr int kAllowedTags[] = {DW_TAG_inlined_subroutine, DW_TAG_subprogram, DW_TAG_entry_point};
        return std::find(std::begin(kAllowedTags), std::end(kAllowedTags), dwarfTag) != std::end(kAllowedTags);
    }

private:
    void InitializeDwfl() {
        Dwfl_ = dwfl_begin(&Callbacks_);
        if (Dwfl_ == nullptr) {
            throw DwflError{};
        }
    }

    void FillDwflReport() {
        CHECK_DWFL(dwfl_linux_proc_report(Dwfl_, Pid_));
        CHECK_DWFL(dwfl_report_end(Dwfl_, nullptr, nullptr));
    }

    void AttachToProcess() {
        CHECK_DWFL(dwfl_linux_proc_attach(Dwfl_, Pid_, /*assume_ptrace_stopped=*/false));
    }

    void ValidateAttachedPid() {
        if (dwfl_pid(Dwfl_) < 0) {
            throw util::Error{"Invalid pid"};
        }
    }

private:
    pid_t Pid_ = 0;
    std::optional<std::string> DebugInfo_;
    char* DebugInfoPath_ = nullptr;

    Dwfl_Callbacks Callbacks_;
    Dwfl* Dwfl_ = nullptr;

    absl::flat_hash_map<Frame, absl::InlinedVector<Symbol, 2>> SymbolCache_;
    absl::flat_hash_map<pid_t, std::string> ThreadNameCache_;
    absl::flat_hash_map<size_t, TraceInfo> Traces_;
};

#undef CHECK_DWFL

} // namespace poorprof::dw

namespace poorprof {

struct Options {
    pid_t Pid = 0;
    std::optional<std::filesystem::path> DebugInfo;

    bool ThreadNames = false;
    double Frequency = 0.0;
};

Options ParseOptions(int argc, const char* argv[]) {
    Options options;

    cpparg::parser parser("poorprof");

    parser
        .title("Fast poor man's profiler");

    parser
        .add('p', "pid")
        .description("Process to trace")
        .required()
        .store(options.Pid);

    parser
        .add('T', "thread-names")
        .description("Show thread names")
        .flag(options.ThreadNames);

    parser
        .add('F', "freq")
        .description("Collect samples at this frequency")
        .default_value(0)
        .store(options.Frequency);

    parser
        .add('d', "debug-info")
        .description("Use separate debug info")
        .optional()
        .handle<std::string>([&options](std::string arg) {
            options.DebugInfo = std::filesystem::path{std::move(arg)};
        });

    parser
        .add_help('h', "help");

    parser
        .parse(argc, argv);

    return options;
}

int Main(int argc, const char* argv[]) {
    spdlog::set_level(spdlog::level::info);
    spdlog::set_default_logger(spdlog::stderr_color_mt("stderr"));
    util::ctrlc::HandleSigInt(3);

    Options options = ParseOptions(argc, argv);
    spdlog::info("Going to trace process {}", options.Pid);

    poorprof::dw::Unwinder unwinder{options.Pid};

    size_t count = 0;
    auto begin = std::chrono::high_resolution_clock::now();

    auto sleep_delta = options.Frequency ? std::chrono::seconds{1} / options.Frequency : std::chrono::seconds{0};
    while (!util::ctrlc::WasInterrupted()) {
        auto start = std::chrono::steady_clock::now();
        unwinder.Unwind();

        ++count;

        if (count % 10000 == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            spdlog::info("Collected {} traces in {:.3f}s", count, std::chrono::duration_cast<std::chrono::duration<double>>(now - begin).count());
        }

        std::this_thread::sleep_until(start + sleep_delta);
    }
    spdlog::info("Stopped by SIGINT");

    unwinder.DumpTraces();

    return 0;
}

} // namespace poorprof

int main(int argc, const char* argv[]) {
    return poorprof::Main(argc, argv);
}
