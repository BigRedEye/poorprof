#include "dw/gdb_index.h"
#include "util/ctrlc.h"
#include "util/defer.h"
#include "util/demangle.h"
#include "util/iterator.h"

#include <cpparg/cpparg.h>

#include <fmt/chrono.h>
#include <fmt/format.h>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <absl/container/flat_hash_map.h>
#include <absl/container/inlined_vector.h>
#include <absl/hash/hash.h>

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>
#include <gelf.h>
#include <libelf.h>

#include <chrono>
#include <compare>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

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
    {}
};

#define CHECK_DWFL(...) \
    if (int err = (__VA_ARGS__); err != 0) { \
        if (err < 0) { \
            throw DwflError{}; \
        } \
        throw std::system_error{err, std::system_category()}; \
    }

class Unwinder : public IUnwinder {
    struct Frame {
        Dwarf_Addr InstructionPointer = 0;
        bool IsActivation = false;

        auto operator<=>(const Frame& rhs) const noexcept = default;

        Dwarf_Addr InstructionPointerAdjusted() const {
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

    struct ObjectFile {
        const char* Name = nullptr;
        const char* File = nullptr;
        Dwarf_Addr Begin = 0;
        Dwarf_Addr End = 0;
        std::optional<dw::GdbIndex> GdbIndex;
    };

    struct Symbol {
        struct Frame Frame;

        std::optional<ObjectFile*> Object;
        std::optional<std::string> Function;
        std::optional<SourceLocation> Location;
        bool Inlined = false;
    };

    using SymbolList = absl::InlinedVector<Symbol, 2>;

public:
    Unwinder(pid_t pid, std::optional<std::filesystem::path> debuginfo = std::nullopt, std::optional<std::filesystem::path> maps = std::nullopt)
        : Pid_{pid}
        , CustomMaps_{std::move(maps)}
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
        dwfl_getthreads(Dwfl_, +[](Dwfl_Thread* thread, void* that) -> int {
            static_cast<Unwinder*>(that)->HandleThread(thread);
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
        pid_t tid = dwfl_thread_tid(thread);

        FrameList frames;
        int err = dwfl_thread_getframes(thread, +[](Dwfl_Frame* raw, void* arg) -> int {
            FrameList* frames = static_cast<FrameList*>(arg);
            Frame& frame = frames->emplace_back();
            if (!dwfl_frame_pc(raw, &frame.InstructionPointer, &frame.IsActivation)) {
                return -1;
            }
            return DWARF_CB_OK;
        }, &frames);

        if (err == -1) {
            int errn = dwfl_errno();
            if (strcmp(dwfl_errmsg(errn), "No such process") == 0) {
                return;
            }
            if (frames.empty()) {
                spdlog::error("TID {}: Failed to get thread frames: {}", tid, dwfl_errmsg(errn));
                return;
            }
        }

        spdlog::debug("Thread {} of process {}", tid, Pid_);
        spdlog::debug("Found {} frames", frames.size());

        TraceInfo& trace = Traces_[absl::Hash<FrameList>{}(frames)];
        if (trace.HitCount++ > 0) {
            return;
        }

        trace.ResolvedTrace = ResolveTrace(tid, frames);
    }

    std::string ResolveTrace(pid_t tid, std::span<Frame> frames) {
        fmt::memory_buffer traceBuf;
        auto buf = std::back_inserter(traceBuf);
        fmt::format_to(buf, "{}", ThreadName(tid));

        unsigned frameNumber = 0;
        for (Frame frame : util::Reversed(frames)) {
            if (frameNumber == 0 && frame.InstructionPointerAdjusted() == 0x0) {
                continue;
            }
            ++frameNumber;

            const SymbolList& symbols = ResolveFrame(frame);
            for (const Symbol& sym : util::Reversed(symbols)) {
                if (!sym.Function) {
                    if (sym.Object) {
                        ObjectFile* file = *sym.Object;
                        fmt::format_to(buf, ";{}+{:#x}", file->File, sym.Frame.InstructionPointerAdjusted() - file->Begin);
                    } else {
                        fmt::format_to(buf, ";{:#018x}", sym.Frame.InstructionPointerAdjusted());
                    }
                    continue;
                }
                fmt::format_to(buf, ";{}{}", *sym.Function, sym.Inlined ? " (inlined)" : "");

                if (auto& loc = sym.Location) {
                    fmt::format_to(buf, " at {}", loc->File);
                    if (loc->Line > 0) {
                        fmt::format_to(buf, ":{}", loc->Line);
                        if (loc->Column > 0) {
                            fmt::format_to(buf, ":{}", loc->Column);
                        }
                    }
                }
            }
        }
        return std::string{traceBuf.data(), traceBuf.size()};
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

    static bool DieHasPc(Dwarf_Die *die, Dwarf_Addr pc) {
        Dwarf_Addr low, high;

        // continuous range
        if (dwarf_hasattr(die, DW_AT_low_pc) && dwarf_hasattr(die, DW_AT_high_pc)) {
            if (dwarf_lowpc(die, &low) != 0) {
                return false;
            }
            if (dwarf_highpc(die, &high) != 0) {
                Dwarf_Attribute attr_mem;
                Dwarf_Attribute *attr = dwarf_attr(die, DW_AT_high_pc, &attr_mem);
                Dwarf_Word value;
                if (dwarf_formudata(attr, &value) != 0) {
                    return false;
                }
                high = low + value;
            }
            return pc >= low && pc < high;
        }

        // non-continuous range.
        Dwarf_Addr base;
        ptrdiff_t offset = 0;
        while ((offset = dwarf_ranges(die, offset, &base, &low, &high)) > 0) {
            if (pc >= low && pc < high) {
                return true;
            }
        }
        return false;
    }

    static Dwarf_Die* FindFunDieByPc(Dwarf_Die* parent_die, Dwarf_Addr pc, Dwarf_Die* result) {
        if (dwarf_child(parent_die, result) != 0) {
            return 0;
        }

        Dwarf_Die *die = result;
        do {
            switch (dwarf_tag(die)) {
                case DW_TAG_subprogram:
                case DW_TAG_inlined_subroutine:
                    if (DieHasPc(die, pc)) {
                        return result;
                    }
            };
            bool declaration = false;
            Dwarf_Attribute attr_mem;
            dwarf_formflag(dwarf_attr(die, DW_AT_declaration, &attr_mem), &declaration);
            if (!declaration) {
                // let's be curious and look deeper in the tree,
                // function are not necessarily at the first level, but
                // might be nested inside a namespace, structure etc.
                Dwarf_Die die_mem;
                Dwarf_Die *indie = FindFunDieByPc(die, pc, &die_mem);
                if (indie) {
                    *result = die_mem;
                    return result;
                }
            }
        } while (dwarf_siblingof(die, result) == 0);
        return 0;
    }

    void VisitDwarf(Dwarf_Die* die) {
        Dwarf_Die child;
        if (dwarf_child(die, &child) != 0) {
            return;
        }

        do {
            VisitDwarf(&child);
            switch (dwarf_tag(&child)) {
                case DW_TAG_call_site:
                case DW_TAG_GNU_call_site: {
                    Dwarf_Attribute attr;
                    if (dwarf_attr_integrate(&child, DW_AT_abstract_origin, &attr) == 0) {
                        break;
                    }
                    Dwarf_Die mem;
                    if (dwarf_formref_die(&attr, &mem) == 0) {
                        break;
                    }
                    const char* name = dwarf_diename(&mem) ?: "(null)";

                    Dwarf_Word ptr = 0xbebebebe;
                    dwarf_lowpc(&child, &ptr);
                    spdlog::info("Found call site to {} die at {:x} (DW_AT_low_pc=0x{:x})", name, (uintptr_t)child.addr, (uintptr_t)ptr);
                }
                break;

                default:
                    break;
            };
        } while (dwarf_siblingof(&child, &child) == 0);
    }

    SymbolList ResolveFrameImpl(Frame frame) {
        if (frame.IsActivation) {
            spdlog::info("Activation frame at {:x}", frame.InstructionPointer);
        }
        spdlog::debug("Start resolve frame at ip {:x}", frame.InstructionPointer);

        Dwarf_Addr ip = frame.InstructionPointerAdjusted();
        Dwfl_Module* module = dwfl_addrmodule(Dwfl_, ip);
        if (!module) {
            spdlog::debug("No module found for ip {:x}", ip);
            return {{
                .Frame = frame,
            }};
        }

        if (!Modules_.contains(module)) {
            ObjectFile obj;
            obj.Name = dwfl_module_info(module, nullptr, &obj.Begin, &obj.End, nullptr, nullptr, &obj.File, nullptr);
            spdlog::info("Found module {} (@{})", obj.Name, obj.File);
            obj.GdbIndex = GdbIndex::Open(module, obj.File);
            Modules_[module] = std::make_unique<ObjectFile>(obj);
        }
        ObjectFile* obj = Modules_[module].get();

        Dwarf_Addr offset = 0;
        Dwarf_Die cudieStorage;
        Dwarf_Die* cudie = nullptr;
        if (getenv("POORPORF_ADDRDIE")) {
            cudie = dwfl_module_addrdie(module, ip, &offset);
        }
        if (!cudie && obj->GdbIndex) {
            // Clang does not generate .debug_aranges, so dwfl_module_addrdie can fail.
            // Try to find CU DIE using gdb_index.
            cudie = obj->GdbIndex->Lookup(ip, &cudieStorage);
        }
        if (!cudie) {
            // We failed to find CU DIE using .debug_aranges (dwfl_module_addrdie) and .gdb_index.
            // Let's scan all CUs in the current module.
            while ((cudie = dwfl_module_nextcu(module, cudie, &offset))) {
                Dwarf_Die die_mem;
                Dwarf_Die *fundie = FindFunDieByPc(cudie, ip - offset, &die_mem);
                if (fundie) {
                    break;
                }
            }
        }
        if (false && !cudie) {
            // If it's still not enough, lets dive deeper in the shit, and try
            // to save the world again: for every compilation unit, we will
            // load the corresponding .debug_line section, and see if we can
            // find our address in it.

            Dwarf_Addr cfi_bias;
            Dwarf_CFI *cfi_cache = dwfl_module_eh_cfi(module, &cfi_bias);

            Dwarf_Addr bias;
            while ((cudie = dwfl_module_nextcu(module, cudie, &bias))) {
                if (dwarf_getsrc_die(cudie, ip - bias)) {
                    // ...but if we get a match, it might be a false positive
                    // because our (address - bias) might as well be valid in a
                    // different compilation unit. So we throw our last card on
                    // the table and lookup for the address into the .eh_frame
                    // section.

                    Dwarf_Frame* frame = nullptr;
                    dwarf_cfi_addrframe(cfi_cache, ip - cfi_bias, &frame);
                    if (frame) {
                        break;
                    }
                }
            }
        }
        if (!cudie) {
            // Give up.
            spdlog::error("No CU DIE found for ip {:x}", ip);
            return {{
                .Frame = frame,
            }};
        }

        spdlog::info("Found CU DIE {:x} for ip {:x} with bias {:x} (addr: {:x})", (uintptr_t)cudie, ip, offset, (uintptr_t)(cudie ? cudie->addr : nullptr));

        Dwarf_Die* scopes = nullptr;
        int numScopes = dwarf_getscopes(cudie, ip - offset, &scopes);

        DEFER {
            ::free(scopes);
        };

        Dwarf_Die* die = nullptr;
        const char* firstSymbolName = nullptr;
        if (numScopes > 0) {
            for (Dwarf_Die* scope = scopes; scope < scopes + numScopes; ++scope) {
                if (IsInlinedScope(scope)) {
                    firstSymbolName = TryGetDebugInfoElementLinkageName(scope);
                } else {
                    spdlog::info("Non-inlined scope {}", (int)dwarf_tag(scope));
                    VisitDwarf(scope);
                }

                if (firstSymbolName) {
                    spdlog::debug("Found by iteration");
                    die = scope;
                    break;
                }
            }
        }

        if (firstSymbolName == nullptr) {
            firstSymbolName = dwfl_module_addrname(module, ip);
            if (firstSymbolName) {
                spdlog::debug("Found by dwfl_module_addrname");
            }
        }

        if (firstSymbolName) {
            spdlog::debug("Found {} scopes for symbol {}", numScopes, util::Demangle(firstSymbolName));
        }

        SymbolList symbols;
        symbols.push_back(FillSymbol(frame, module, obj, firstSymbolName, cudie, nullptr, offset));
        if (die) {
            Dwarf_Die* scopes = nullptr;
            int numInlinedSymbols = dwarf_getscopes_die(die, &scopes);
            if (numInlinedSymbols == -1) {
                spdlog::warn("dwarf_getscopes_die failed: {}", dwfl_errmsg(-1));
            }

            DEFER {
                ::free(scopes);
            };

            Dwarf_Die* prevScope = scopes;
            for (Dwarf_Die* scope = scopes + 1; scope < scopes + numInlinedSymbols; ++scope) {
                int tag = dwarf_tag(scope);
                if (IsInlinedScope(tag)) {
                    const char* inlinedSymbolName = TryGetDebugInfoElementLinkageName(scope);
                    symbols.push_back(FillSymbol(frame, module, obj, inlinedSymbolName, cudie, prevScope, offset));
                    prevScope = scope;
                }

                if (tag == DW_TAG_subprogram) {
                    break;
                }
            }
        }
        symbols.back().Inlined = false;
        for (size_t i = 0; i + 1 < symbols.size(); ++i) {
            symbols[i].Inlined = true;
        }

        return symbols;
    }

    Symbol FillSymbol(Frame frame, Dwfl_Module* module, ObjectFile* obj, const char* name, Dwarf_Die* cudie, Dwarf_Die* lastScope, Dwarf_Word mod_offset) {
        bool inlined = lastScope != nullptr;
        Symbol sym{
            .Frame = frame,
            .Object = obj,
        };

        if (name) {
            sym.Function = util::Demangle(name);
            spdlog::debug("Start resolve frame {}, inlined: {}", *sym.Function, inlined);
        }

        SourceLocation location;
        if (inlined) {
            Dwarf_Attribute attr;
            Dwarf_Word val = 0;
            Dwarf_Files* files = nullptr;
            if (dwarf_getsrcfiles(cudie, &files, NULL) == 0) {
                if (dwarf_formudata(dwarf_attr(lastScope, DW_AT_call_file, &attr), &val) == 0) {
                    location.File = dwarf_filesrc(files, val, NULL, NULL);
                }
            } else {
                location.File = "<<dwarf_getsrcfiles>>";
            }
            if (dwarf_formudata(dwarf_attr(lastScope, DW_AT_call_line, &attr), &val) == 0) {
                location.Line = val;
            }
            if (dwarf_formudata(dwarf_attr(lastScope, DW_AT_call_column, &attr), &val) == 0) {
                location.Column = val;
            }
        } else {
            Dwarf_Word ip = frame.InstructionPointerAdjusted() - mod_offset; 
            Dwarf_Line* line = dwarf_getsrc_die(cudie, ip);
            if (line) {
                Dwarf_Word length = 0;
                Dwarf_Word mtime = 0;
                const char* name = dwarf_linesrc(line, &mtime, &length);
                if (length == 0 && name != 0) {
                    length = std::strlen(name);
                }
                if (name) {
                    location.File.assign(name, length);
                } else {
                    spdlog::info("dwarf_linesrc failed");
                }
                if (dwarf_lineno(line, &location.Line) < 0) {
                    spdlog::info("dwarf_lineno failed");
                }
                if (dwarf_linecol(line, &location.Column) < 0) {
                    spdlog::info("dwarf_linecol failed");
                }
            } else if (Dwfl_Line* line = dwfl_module_getsrc(module, ip)) {
                const char* name = dwfl_lineinfo(line, nullptr, &location.Line, &location.Column, nullptr, nullptr);
                if (name) {
                    location.File = name;
                }
            } else {
                // Failed to find source location for the given pc.
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
            spdlog::error("Failed to initialize dwfl");
            throw DwflError{};
        }
    }

    void FillDwflReport() {
        dwfl_report_begin(Dwfl_);
        if (CustomMaps_) {
            FILE* maps = fopen(CustomMaps_->data(), "r");
            DEFER {
                fclose(maps);
            };
            int code = dwfl_linux_proc_maps_report(Dwfl_, maps);
            CHECK_DWFL(code);
        } else {
            int code = dwfl_linux_proc_report(Dwfl_, Pid_);
            CHECK_DWFL(code);
        }
        CHECK_DWFL(dwfl_report_end(Dwfl_, nullptr, nullptr));
    }

    void AttachToProcess() {
        CHECK_DWFL(dwfl_linux_proc_attach(Dwfl_, Pid_, /*assume_ptrace_stopped=*/false));
    }

    void ValidateAttachedPid() {
        if (pid_t pid = dwfl_pid(Dwfl_); pid != Pid_) {
            throw util::Error{"Invalid pid {}", pid};
        }
    }

private:
    pid_t Pid_ = 0;
    std::optional<std::string> CustomMaps_;
    std::optional<std::string> DebugInfo_;
    char* DebugInfoPath_ = nullptr;

    Dwfl_Callbacks Callbacks_;
    Dwfl* Dwfl_ = nullptr;

    absl::flat_hash_map<Frame, SymbolList> SymbolCache_;
    absl::flat_hash_map<pid_t, std::string> ThreadNameCache_;
    absl::flat_hash_map<size_t, TraceInfo> Traces_;
    absl::flat_hash_map<Dwfl_Module*, std::unique_ptr<ObjectFile>> Modules_;
};

#undef CHECK_DWFL

} // namespace poorprof::dw

namespace poorprof {

struct Options {
    pid_t Pid = 0;
    std::optional<std::filesystem::path> DebugInfo;
    std::optional<std::filesystem::path> CustomMaps;

    bool ThreadNames = false;
    double Frequency = 0.0;
    std::optional<size_t> MaxSamples;
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
        .add('L', "limit")
        .description("Limit number of samples")
        .store<size_t>(options.MaxSamples);

    parser
        .add('d', "debug-info")
        .description("Use separate debug info")
        .optional()
        .handle<std::string>([&options](std::string arg) {
            options.DebugInfo = std::filesystem::path{std::move(arg)};
        });

    parser
        .add('M', "maps")
        .description("Use custom maps file")
        .optional()
        .handle<std::string>([&options](std::string arg) {
            options.CustomMaps = std::filesystem::path{std::move(arg)};
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
    spdlog::set_pattern("%Y-%m-%dT%H:%M:%S.%f [%^%l%$] %v");

    util::HandleSigInt(3);

    Options options = ParseOptions(argc, argv);
    spdlog::info("Going to trace process {}", options.Pid);

    poorprof::dw::Unwinder unwinder{options.Pid, options.DebugInfo, options.CustomMaps};

    auto begin = std::chrono::high_resolution_clock::now();
    auto sleep_delta = options.Frequency ? std::chrono::seconds{1} / options.Frequency : std::chrono::seconds{0};
    size_t max = options.MaxSamples.value_or(std::numeric_limits<size_t>::max());
    for (size_t iter = 1; iter <= max; ++iter) {
        if (util::WasInterrupted()) {
            spdlog::info("Stopped by SIGINT");
            break;
        }

        auto start = std::chrono::steady_clock::now();
        unwinder.Unwind();

        if (iter % 10000 == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            auto delta = std::chrono::duration_cast<std::chrono::duration<double>>(now - begin).count();
            spdlog::info("Collected {} traces in {:.3f}s ({:.3f} traces/s)", iter, delta, iter / delta);
        }

        std::this_thread::sleep_until(begin + sleep_delta * iter);
    }

    unwinder.DumpTraces();

    return 0;
}

} // namespace poorprof

int main(int argc, const char* argv[]) {
    return poorprof::Main(argc, argv);
}
