#include <ghidra/EnigmaPipeline.h>
#include <iostream>
#include <string>
#include <cstring>
#include <exception>

static void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options] <binary>\n"
              << "Options:\n"
              << "  -a <arch>    Architecture (x86, arm, mips, ppc) [default: x86]\n"
              << "  -b <bits>    Bitness (32 or 64) [default: 64]\n"
              << "  -base <addr> Base address (hex) [default: 0x1000]\n"
              << "  -h           Print this help\n";
}

int main(int argc, char** argv) {
    std::string binary;
    std::string arch = "x86";
    int bitness = 64;
    uint64_t baseAddr = 0x1000;

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "-h") == 0) {
            printUsage(argv[0]);
            return 0;
        } else if (std::strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            arch = argv[++i];
        } else if (std::strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bitness = std::stoi(argv[++i]);
        } else if (std::strcmp(argv[i], "-base") == 0 && i + 1 < argc) {
            baseAddr = std::stoull(argv[++i], nullptr, 16);
        } else {
            binary = argv[i];
        }
    }

    if (binary.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    ghidra::EnigmaPipeline pipeline;
    pipeline.setArchitecture(arch, bitness);
    pipeline.setBaseAddress(baseAddr);

    try {
        if (!pipeline.loadBinary(binary)) {
            std::cerr << "Error: Failed to load binary: " << binary << "\n";
            return 1;
        }

        if (!pipeline.decompile()) {
            std::cerr << "Error: Failed to decompile\n";
            return 1;
        }

        std::cout << pipeline.getOutput() << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception\n";
        return 1;
    }
}
