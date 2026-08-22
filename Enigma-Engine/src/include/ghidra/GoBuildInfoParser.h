#pragma once

#include <ghidra/Address.h>
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class Memory;
class Program;

/**
 * Parses the Go build info section (go.buildinfo / go_buildinfo).
 * Extracts Go version, module path, build flags, and dependencies.
 */
class GoBuildInfoParser {
public:
    struct BuildInfo {
        std::string goVersion;
        std::string modulePath;
        std::vector<std::string> dependencies;
        std::vector<std::string> buildFlags;
        std::string compiler;
        bool valid = false;
    };

    /**
     * Parse Go build info from a memory block.
     * Looks for the "\xff Go buildinf:" magic header.
     */
    static BuildInfo parse(Memory* memory, const Address& start, int64_t size);

    /**
     * Search all memory blocks for Go build info.
     */
    static BuildInfo findAndParse(Memory* memory);

private:
};

} // namespace ghidra
