#include "debuginfod.h"

#include "util/assert.h"
#include "util/defer.h"

#include <spdlog/spdlog.h>

#include <elfutils/debuginfod.h>

#ifdef __linux__
#include <dlfcn.h>
#endif


namespace poorprof::dw {

RemoteDebugInfo::RemoteDebugInfo()
{
    Client_ = debuginfod_begin();
    if (Client_) {
        debuginfod_set_progressfn(Client_, +[](debuginfod_client*, long a, long b) {
            spdlog::info("Loading {}/{}", a, b);
            return 0;
        });
        spdlog::info("Successfully initialized debuginfod client");
    } else {
        spdlog::info("Failed to initialize debuginfod client");
    }
}

RemoteDebugInfo::~RemoteDebugInfo() {
    if (Client_) {
        debuginfod_end(std::exchange(Client_, nullptr));
    }
}

std::optional<FileDescriptor> RemoteDebugInfo::FindDebugInfo(std::string buildId) {
    if (!Client_) {
        return std::nullopt;
    }

    char* path = nullptr;
    DEFER {
        ::free(path);
    };

    spdlog::info("Loading remote debug info");
    const unsigned char* ptr = reinterpret_cast<const unsigned char*>(buildId.data());
    int fd = debuginfod_find_debuginfo(Client_, ptr, buildId.size(), &path);
    if (fd <= 0) {
        spdlog::warn("Failed to find remote debug info: {}", strerror(-fd));
        return std::nullopt;
    }

    spdlog::info("Successfully fetched remote debug info");
    return fd;
}

} // namespace poorprof::dw
