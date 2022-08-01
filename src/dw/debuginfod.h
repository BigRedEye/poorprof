#pragma once

#include "util/fs.h"
#include "util/noncopyable.h"

#include <absl/container/flat_hash_map.h>

#include <optional>


struct debuginfod_client;

namespace poorprof::dw {

using FileDescriptor = int;

class RemoteDebugInfo : util::NonCopyable {
    struct DebugInfoLib;

public:
    RemoteDebugInfo();
    ~RemoteDebugInfo();

    std::optional<FileDescriptor> FindDebugInfo(std::string buildId);

private:
    debuginfod_client* Client_ = nullptr;
};

} // namespace poorprof::dw
