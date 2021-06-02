#include <cpparg/cpparg.h>

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <optional>
#include <stdexcept>

#include <elfutils/libdwfl.h>
#include <sys/types.h>

class IUnwinder {
public:
    virtual ~IUnwinder() = default;

    virtual void Unwind() = 0;
};

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

namespace poorprof::dw {

class DwflError : public std::runtime_error {
public:
    DwflError()
        : std::runtime_error{fmt::format("dwfl failed: {}", dwfl_errmsg(-1))}
    {}
};

#define CHECK_DWFL(...) \
    if (int err = (__VA_ARGS__); err != 0) { \
        throw DwflError{}; \
    }

class Unwinder final : public IUnwinder {
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

private:
    void HandleThread(Dwfl_Thread* thread) {
        spdlog::info("Found thread {} of process {}", dwfl_thread_tid(thread), Pid_);
    }

private:
    void InitializeDwfl() {
        Dwfl_ = dwfl_begin(&Callbacks_);
        if (Dwfl_ == nullptr) {
            throw DwflError{};
        }
    }

    void FillDwflReport() {
        if (int err = dwfl_linux_proc_report(Dwfl_, Pid_); err != 0) {
            spdlog::error("DWFL failed: {}", dwfl_errmsg(err));
            throw DwflError{};
        }

        CHECK_DWFL(dwfl_linux_proc_report(Dwfl_, Pid_));
        CHECK_DWFL(dwfl_report_end(Dwfl_, nullptr, nullptr));
    }

    void AttachToProcess() {
        CHECK_DWFL(dwfl_linux_proc_attach(Dwfl_, Pid_, /*assume_ptrace_stopped=*/false));
    }

    void ValidateAttachedPid() {
        if (dwfl_pid(Dwfl_) < 0) {
            throw util::Error{"Invalid "};
        }
    }

private:
    pid_t Pid_ = 0;
    std::optional<std::string> DebugInfo_;
    char* DebugInfoPath_ = nullptr;

    Dwfl_Callbacks Callbacks_;
    Dwfl* Dwfl_ = nullptr;
};

#undef CHECK_DWFL

} // namespace poorprof::dw

namespace poorprof {

struct Options {
    pid_t Pid = 0;
    std::optional<std::filesystem::path> DebugInfo;
};

Options ParseOptions(int argc, const char* argv[]) {
    Options options;

    cpparg::parser parser("poorprof");

    parser
        .title("Fast poor man's profiler");

    parser
        .add('p', "pid")
        .required()
        .store(options.Pid);
    parser
        .add("debug-info")
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
    Options options = ParseOptions(argc, argv);
    spdlog::info("Going to trace process {}", options.Pid);

    poorprof::dw::Unwinder unwinder{options.Pid};
    unwinder.Unwind();
    return 0;
}

} // namespace poorprof

int main(int argc, const char* argv[]) {
    return poorprof::Main(argc, argv);
}
