#pragma once

#include <util/align.h>
#include <util/assert.h>
#include <util/error.h>
#include <util/range.h>
#include <util/types.h>

#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <gelf.h>
#include <libelf.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <bit>
#include <compare>
#include <cstddef>
#include <cstring>
#include <exception>
#include <optional>
#include <string_view>
#include <type_traits>


namespace poorprof::dw {

template <typename T>
requires (std::is_trivially_copyable_v<T>)
T UnalignedLoad(const char* ptr) {
    T result;
    std::memcpy(&result, ptr, sizeof(T));
    return result;
}

template <typename T>
struct TriviallyCopyableSerializer {
    static constexpr size_t Size() {
        return sizeof(T);
    }

    static T Deserialize(const char* buf) {
        return UnalignedLoad<T>(buf);
    }
};

template <typename T, typename Serializer = TriviallyCopyableSerializer<T>>
class ExternalSpan {
public:
    ExternalSpan() = default;

    ExternalSpan(const char* begin, const char* end)
        : ExternalSpan(begin, end - begin)
    {}

    ExternalSpan(const char* begin, size_t size)
        : Begin_{begin}
        , Size_{size}
    {
        ENSURE(Size_ % Serializer::Size() == 0);
    }

    // NOLINTNEXTLINE(readability-identifier-naming)
    size_t size() const {
        return Size_ / Serializer::Size();
    }

    T operator[](size_t idx) const {
        ENSURE(idx < Size_);
        return Serializer::Deserialize(Begin_ + idx * Serializer::Size());
    }

private:
    const char* Begin_ = nullptr;
    size_t Size_ = 0;
};

// The index format is described here:
// https://sourceware.org/gdb/onlinedocs/gdb/Index-Section-Format.html#Index-Section-Format
class GdbIndex {
    // gdb index format encodes integers in the little endian.
    static_assert(std::endian::native == std::endian::little, "TODO");

    using offset_type = u32;

    struct CULocation {
        u64 Offset = 0; // Offset from the beginning of the .debug_info section
        u64 Length = 0; // Length of the CU DIE
    };

    struct AddressRange {
        u64 LowAddress = 0;
        u64 HighAddress = 0;
        offset_type CUIndex = 0; 

        u64 LastAddressInclusive() const {
            return HighAddress - 1;
        }
    };

    struct AddressRangeSerializer {
        static constexpr size_t Size() {
            return sizeof(AddressRange::LowAddress)
                + sizeof(AddressRange::HighAddress)
                + sizeof(AddressRange::CUIndex);
        }

        static AddressRange Deserialize(const char* ptr) {
            return AddressRange{
                .LowAddress = UnalignedLoad<u64>(ptr),
                .HighAddress = UnalignedLoad<u64>(ptr + sizeof(u64)),
                .CUIndex = UnalignedLoad<u32>(ptr + sizeof(u64) * 2),
            };
        }
    };

    class TriviallyCopyableLoader {
    public:
        explicit TriviallyCopyableLoader(const char* cursor, const char* end) {
            Reset(cursor, end);
        }

        void Reset(const char* cursor, const char* end) {
            Cursor_ = cursor;
            End_ = end;
        };

        template <typename T>
        requires std::is_trivially_copyable_v<T>
        T Read() {
            static constexpr size_t kSize = sizeof(T);
            ENSURE(Cursor_ + kSize <= End_);
            T value;
            std::memcpy(&value, Cursor_, kSize);
            Cursor_ += kSize;
            return value;
        }

        offset_type ReadOffset() {
            return Read<offset_type>();
        }

        const char* Cursor() const {
            return Cursor_;
        }

    private:
        const char* Cursor_ = nullptr;
        const char* End_ = nullptr;
    };

public:
    explicit GdbIndex(Dwfl_Module* mod, Elf_Scn* scn)
        : Module_{mod}
        , Section_{scn}
        , Dwarf_{dwfl_module_getdwarf(mod, &DwarfBias_)}
    {
        dwfl_module_info(Module_, nullptr, &ModuleMappingBegin_, &ModuleMappingEnd_, nullptr, nullptr, nullptr, nullptr);

        Elf_Data* data = elf_getdata(scn, nullptr);
        const char* begin = static_cast<const char*>(data->d_buf);
        ParseGdbIndex(begin - data->d_off, begin, data->d_size);
    }

    static std::optional<GdbIndex> Open(Dwfl_Module* mod, const char* path) {
        try {
            Elf_Scn* gdbIndexSection = nullptr;
            IterateSections(mod, [&gdbIndexSection](const char* name, Elf_Scn* section) {
                if (std::string_view{".gdb_index"} == name) {
                    gdbIndexSection = section;
                    return true;
                }
                return false;
            });

            if (!gdbIndexSection) {
                spdlog::debug("Object {} does not contain gdb_index", path);
                return std::nullopt;
            }
            spdlog::info("Found gdb_index for {}", path ? path : "<nil>");

            return std::make_optional<GdbIndex>(mod, gdbIndexSection);
        } catch (const std::exception& e) {
            spdlog::error("Failed to load gdb_index for {}: {}", path, e.what());
            return std::nullopt;
        }
    }

    Dwarf_Die* Lookup(Dwarf_Addr address, Dwarf_Die* result) const {
        ENSURE(address >= ModuleMappingBegin_ && address < ModuleMappingEnd_);
        address -= DwarfBias_;

        auto range = util::xrange<u64>(Addresses_.size());
        auto it = util::LowerBoundBy(range, static_cast<u64>(address), [this](size_t idx) {
            return Addresses_[idx].LastAddressInclusive();
        });
        if (it == range.end()) {
            return nullptr;
        }

        offset_type cuIdx = Addresses_[*it].CUIndex;
        CULocation cu = CULocations_[cuIdx];

        // Locate this CU via libdw 
        Dwarf_Off nextOffset;
        size_t headerSize = 0;
        int res = dwarf_nextcu(Dwarf_, 0, &nextOffset, &headerSize, nullptr, nullptr, nullptr);
        if (res != 0) {
            spdlog::error("Malformed .gdb_index: {}", dwarf_errmsg(res));
            return nullptr;
        }

        Dwarf_Die* cudie = dwarf_offdie(Dwarf_, cu.Offset + headerSize, result);
        spdlog::debug("Found CU using gdb index, offset: {}, header: {}, total: {}", cu.Offset, headerSize, dwarf_dieoffset(cudie));
        return cudie;
    }

    Dwarf_Addr DwarfBias() const {
        return DwarfBias_;
    }

private:
    template <typename F>
    static void IterateSections(Dwfl_Module* mod, F&& cb) {
        GElf_Addr bias;
        Elf* elf = dwfl_module_getelf(mod, &bias);

        GElf_Ehdr ehdr;
        if (gelf_getehdr(elf, &ehdr) == nullptr) {
            throw util::Error{"Failed to find ELF header"};
        }
        size_t shstrndx = 0;
        if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
            throw util::Error{"Failed to find ELF section header string table"};
        }
        Elf_Scn* scn = nullptr;
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            gelf_getshdr(scn, &shdr);
            const char* name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
            if (cb(name, scn)) {
                break;
            }
        }
    }

    void ParseGdbIndex(const char* begin, const char* ptr, size_t size) {
        using offset_type = u32;

        TriviallyCopyableLoader loader{ptr, ptr + size};

        offset_type version = loader.ReadOffset();
        spdlog::debug("Found gdb index version {}", version);
        ENSURE(version >= 7, "Unsupported gdb index version");

        offset_type cuListOffset = loader.ReadOffset();
        offset_type typesCuListOffset = loader.ReadOffset();
        offset_type addresAreaOffset = loader.ReadOffset();
        offset_type symbolTableOffset = loader.ReadOffset();
        offset_type constantPoolOffset = loader.ReadOffset();

        CULocations_ = {begin + cuListOffset, typesCuListOffset - cuListOffset};
        Addresses_ = {begin + addresAreaOffset, symbolTableOffset - addresAreaOffset};
        spdlog::debug("Found {} CUs, {} address ranges", CULocations_.size(), Addresses_.size());
    }

private:
    Dwfl_Module* Module_ = nullptr;
    Elf_Scn* Section_ = nullptr;
    Dwarf_Addr DwarfBias_ = 42;
    Dwarf* Dwarf_ = nullptr;
    Dwarf_Addr ModuleMappingBegin_ = 0;
    Dwarf_Addr ModuleMappingEnd_ = 0;

    ExternalSpan<CULocation> CULocations_;
    ExternalSpan<AddressRange, AddressRangeSerializer> Addresses_;
};

} // namespace poorprof::dw
