/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DecompilerAdapter.cpp
/// \brief Decompiler adapter implementation - bridges Enigma Engine to Ghidra C++ decompiler

#include "ghidra/DecompilerAdapter.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/Function.h"
#include "ghidra/Memory.h"
#include "ghidra/Msg.h"

#include <libdecomp.hh>
#include <sleigh_arch.hh>
#include <raw_arch.hh>
#include <loadimage.hh>
#include <printc.hh>
#include <printjava.hh>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <fstream>
#include <iostream>

// Decompiler types in their own namespace
using namespace ghidra_decompiler;

namespace ghidra {

namespace {

#ifndef ENIGMA_SLEIGH_DIR
#define ENIGMA_SLEIGH_DIR ""
#endif

bool hasLanguageDefinition(const std::filesystem::path& dir) {
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) {
        return false;
    }

    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!ec && entry.is_regular_file(ec) && entry.path().extension() == ".ldefs") {
            return true;
        }
    }
    return false;
}

std::vector<std::filesystem::path> getSleighCandidates() {
    std::vector<std::filesystem::path> candidates;

    if (const char* envPath = std::getenv("ENIGMA_SLEIGH_DIR")) {
        if (*envPath != '\0') {
            candidates.emplace_back(envPath);
        }
    }

    if (std::string compilePath = ENIGMA_SLEIGH_DIR; !compilePath.empty()) {
        candidates.emplace_back(compilePath);
    }

    std::error_code ec;
    auto cwdSleigh = std::filesystem::current_path(ec) / "sleigh";
    if (!ec) {
        candidates.emplace_back(cwdSleigh);
    }

    return candidates;
}

std::string registerSleighSpecs() {
    for (const auto& root : getSleighCandidates()) {
        std::error_code ec;
        if (!std::filesystem::is_directory(root, ec)) {
            continue;
        }

        if (hasLanguageDefinition(root)) {
            ghidra_decompiler::SleighArchitecture::scanForSleighDirectories(root.string());
        }

        bool registeredAny = hasLanguageDefinition(root);
        for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
            if (ec) {
                break;
            }
            if (entry.is_directory(ec) && hasLanguageDefinition(entry.path())) {
                ghidra_decompiler::SleighArchitecture::scanForSleighDirectories(entry.path().string());
                registeredAny = true;
            }
        }

        if (registeredAny) {
            return root.string();
        }
    }

    return {};
}

std::string resolveLanguageId(ProgramDB* program) {
    if (program) {
        std::string languageId = program->getLanguageID().getIdAsString();
        if (!languageId.empty() && languageId != "unknown") {
            return languageId;
        }
    }

    return "x86:LE:64:default";
}

} // namespace

class LoadImageEnigma : public ghidra_decompiler::RawLoadImage {
private:
    ProgramDB* program_;
    AddressSpace* ramSpace_;

public:
    LoadImageEnigma(ProgramDB* program, const std::string& path)
        : ghidra_decompiler::RawLoadImage(path), program_(program), ramSpace_(nullptr) {
        if (program_) {
            auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(program_->getAddressFactory());
            if (addrFactory) {
                for (const auto* space : addrFactory->getAddressSpaces()) {
                    if (space->isMemorySpace()) {
                        ramSpace_ = const_cast<AddressSpace*>(space);
                        break;
                    }
                }
            }
        }
    }

    void loadFill(ghidra_decompiler::uint1* ptr, ghidra_decompiler::int4 size, const ghidra_decompiler::Address &addr) override {
        if (!program_ || !ramSpace_) {
            std::memset(ptr, 0, size);
            return;
        }
        auto* memory = program_->getMemory();
        if (!memory) {
            std::memset(ptr, 0, size);
            return;
        }
        ghidra_decompiler::uintb currentOffset = addr.getOffset();
        ghidra_decompiler::int4 remaining = size;
        while (remaining > 0) {
            Address readAddr(ramSpace_, static_cast<int64_t>(currentOffset));
            ghidra_decompiler::int4 chunk = std::min(remaining, 4096);
            int got = memory->getBytes(readAddr, ptr, chunk);
            if (got < 0) got = 0;
            if (got < chunk) {
                std::memset(ptr + got, 0, chunk - got);
            }
            ptr += chunk;
            currentOffset += chunk;
            remaining -= chunk;
        }
    }

    std::string getArchType(void) const override { return "enigma"; }
    void adjustVma(long adjust) override { (void)adjust; }
};

class EnigmaArchitecture : public ghidra_decompiler::RawBinaryArchitecture {
private:
    ghidra_decompiler::LoadImage* customLoader_;
public:
    EnigmaArchitecture(const std::string& fname, const std::string& targ, std::ostream* estream, ghidra_decompiler::LoadImage* customLoader)
        : ghidra_decompiler::RawBinaryArchitecture(fname, targ, estream), customLoader_(customLoader) {}

    void buildLoader(ghidra_decompiler::DocumentStorage &store) override {
        collectSpecFiles(*errorstream);
        loader = customLoader_;
    }
};

class DecompilerAdapterImpl : public DecompilerAdapter {
private:
    std::unique_ptr<LoadImageEnigma> loader_;
    std::unique_ptr<ghidra_decompiler::Architecture> arch_;
    ghidra_decompiler::DocumentStorage store_;
    std::string sleighHome_;
    bool initialized_ = false;

public:
    ~DecompilerAdapterImpl() override {
        if (arch_) {
            arch_->loader = nullptr;
        }
    }

    bool initialize(ProgramDB* program) override {
        program_ = program;
        if (!program_) return false;

        // Force linker to retain printc.cc and printjava.cc objects
        // We write their addresses to an std::stringstream to prevent the compiler from optimizing these references away.
        std::stringstream ss;
        ss << "PrintC: " << (uintptr_t)&ghidra_decompiler::PrintCCapability::printCCapability << "\n";
        ss << "PrintJava: " << (uintptr_t)&ghidra_decompiler::PrintJavaCapability::printJavaCapability << "\n";
        (void)ss.str();

        // Initialize the decompiler library
        ghidra_decompiler::AttributeId::initialize();
        ghidra_decompiler::ElementId::initialize();
        ghidra_decompiler::CapabilityPoint::initializeAll();
        ghidra_decompiler::ArchitectureCapability::sortCapabilities();

        sleighHome_ = registerSleighSpecs();

        // Create loader
        loader_ = std::make_unique<LoadImageEnigma>(program, "enigma_program");

        // Try to build architecture using EnigmaArchitecture
        try {
            std::string langId = resolveLanguageId(program);
            std::string filename = loader_->getFileName();

            arch_.reset(new EnigmaArchitecture(filename, langId, &std::cerr, loader_.get()));
            if (arch_) {
                arch_->init(store_);
                initialized_ = true;
                Msg::info("DecompilerAdapter", "Initialized with language: " + langId);
                return true;
            }
        } catch (const ghidra_decompiler::LowlevelError& le) {
            Msg::info("DecompilerAdapter", "Failed to initialize due to LowlevelError: " + le.explain);
        } catch (const std::exception& e) {
            Msg::info("DecompilerAdapter", "Failed to initialize: " + std::string(e.what()));
        } catch (...) {
            Msg::info("DecompilerAdapter", "Failed to initialize due to unknown exception");
        }

        initialized_ = false;
        return false;
    }

    DecompiledFunction decompileFunction(Function* func, int maxSeconds) override {
        (void)maxSeconds;

        DecompiledFunction result;
        result.success = false;

        if (!func) {
            result.warnings.push_back("Null function");
            return result;
        }

        if (!initialized_ || !arch_) {
            result.cCode = "/* Decompiler not initialized */\n";
            result.cCode += "/* Requires SLEIGH spec files for target architecture */\n";
            result.cCode += "void " + func->getName() + "() {\n";
            result.cCode += "    // Function at " + func->getEntryPoint().toString() + "\n";
            result.cCode += "}\n";
            result.warnings.push_back("Decompiler not initialized - SLEIGH specs not found");
            result.warnings.push_back("Searched: " + sleighHome_);
            return result;
        }

        try {
            // Get function entry point
            ghidra_decompiler::uintb entryOffset = func->getEntryPoint().getOffset();

            // Create decompiler address
            ghidra_decompiler::AddrSpace* codeSpace = arch_->getDefaultCodeSpace();
            if (!codeSpace) {
                result.warnings.push_back("No default code space");
                return result;
            }

            ghidra_decompiler::Address decompAddr(codeSpace, entryOffset);

            // Query or create function in decompiler database
            ghidra_decompiler::Funcdata* fd = arch_->symboltab->getGlobalScope()->queryFunction(decompAddr);
            if (!fd) {
                ghidra_decompiler::FunctionSymbol* fsym = arch_->symboltab->getGlobalScope()->addFunction(decompAddr, func->getName());
                fd = fsym ? fsym->getFunction() : nullptr;
            }

            if (!fd) {
                result.warnings.push_back("Could not create function data");
                return result;
            }

            // Decompile
            if (fd->isProcStarted()) {
                arch_->clearAnalysis(fd);
            }

            if (arch_->allacts.getCurrent() != nullptr) {
                arch_->allacts.getCurrent()->reset(*fd);
                arch_->allacts.getCurrent()->perform(*fd);
            } else {
                fd->startProcessing();
            }

            // Generate C code
            std::ostringstream cStream;
            arch_->print->setOutputStream(&cStream);
            arch_->print->docFunction(fd);

            result.cCode = cStream.str();

            // Post-process: normalize undefinedN types and strip WARNING comments
            {
                std::string& s = result.cCode;

                // Strip /* WARNING: ... */ blocks
                for (size_t pos = 0; (pos = s.find("/* WARNING:", pos)) != std::string::npos; ) {
                    size_t end = s.find("*/", pos + 11);
                    if (end == std::string::npos) break;
                    end += 2;
                    size_t lineEnd = s.find('\n', end);
                    if (lineEnd != std::string::npos && lineEnd == end - 1) {
                        size_t lineStart = (pos > 0) ? s.rfind('\n', pos - 1) : std::string::npos;
                        if (lineStart == std::string::npos || lineStart < pos)
                            lineStart = pos;
                        s.erase(lineStart + 1, lineEnd - lineStart);
                        pos = lineStart + 1;
                    } else {
                        s.erase(pos, end - pos);
                    }
                }

                // Normalize undefined8/4/2/1 -> uint64_t/uint32_t/uint16_t/uint8_t
                static const char* undefs[] = {"undefined8", "undefined4", "undefined2", "undefined1"};
                static const char* fixed[]  = {"uint64_t",   "uint32_t",    "uint16_t",   "uint8_t"};
                for (int i = 0; i < 4; ++i) {
                    size_t flen = std::strlen(undefs[i]);
                    size_t tlen = std::strlen(fixed[i]);
                    for (size_t pos = 0; (pos = s.find(undefs[i], pos)) != std::string::npos; ) {
                        s.replace(pos, flen, fixed[i]);
                        pos += tlen;
                    }
                }
            }

            result.success = true;

        } catch (const ghidra_decompiler::LowlevelError& le) {
            result.warnings.push_back("Decompilation error (LowlevelError): " + le.explain);
        } catch (const std::exception& e) {
            result.warnings.push_back("Decompilation error: " + std::string(e.what()));
        } catch (...) {
            result.warnings.push_back("Decompilation error: unknown exception");
        }

        return result;
    }

    void generatePcode(Function* func, std::vector<PcodeOutput>& result) override {
        if (!func || !initialized_ || !arch_) {
            return;
        }

        try {
            ghidra_decompiler::uintb entryOffset = func->getEntryPoint().getOffset();
            ghidra_decompiler::AddrSpace* codeSpace = arch_->getDefaultCodeSpace();
            if (!codeSpace) return;

            ghidra_decompiler::Address decompAddr(codeSpace, entryOffset);

            ghidra_decompiler::Funcdata* fd = arch_->symboltab->getGlobalScope()->queryFunction(decompAddr);
            if (!fd) {
                ghidra_decompiler::FunctionSymbol* fsym = arch_->symboltab->getGlobalScope()->addFunction(decompAddr, func->getName());
                fd = fsym ? fsym->getFunction() : nullptr;
            }
            if (!fd) return;

            if (fd->isProcStarted()) {
                arch_->clearAnalysis(fd);
            }
            fd->startProcessing();

            // Extract p-code from basic blocks
            const ghidra_decompiler::BlockGraph& blockGraph = fd->getBasicBlocks();
            for (ghidra_decompiler::int4 i = 0; i < blockGraph.getSize(); i++) {
                ghidra_decompiler::FlowBlock* fb = blockGraph.getBlock(i);
                ghidra_decompiler::BlockBasic* block = dynamic_cast<ghidra_decompiler::BlockBasic*>(fb);
                if (!block) continue;

                for (auto iter = block->beginOp(); iter != block->endOp(); ++iter) {
                    ghidra_decompiler::PcodeOp* op = *iter;
                    PcodeOutput output;
                    output.address = Address(nullptr, op->getSeqNum().getAddr().getOffset());
                    output.mnemonic = op->getOpName();

                    for (ghidra_decompiler::int4 j = 0; j < op->numInput(); j++) {
                        ghidra_decompiler::Varnode* vn = op->getIn(j);
                        std::ostringstream ss;
                        if (vn) {
                            vn->printRaw(ss);
                            output.inputs.push_back(ss.str());
                        } else {
                            output.inputs.push_back("NULL_VARNODE");
                        }
                    }

                    if (op->getOut()) {
                        std::ostringstream ss;
                        op->getOut()->printRaw(ss);
                        output.outputs.push_back(ss.str());
                    }

                    result.push_back(output);
                }
            }

        } catch (const std::exception& e) {
            Msg::info("DecompilerAdapter", "P-code generation error: " + std::string(e.what()));
        } catch (...) {
            Msg::info("DecompilerAdapter", "P-code generation error: unknown exception");
        }
    }

    std::string getDecompilerVersion() const override {
        ghidra_decompiler::uint4 major = ghidra_decompiler::ArchitectureCapability::getMajorVersion();
        ghidra_decompiler::uint4 minor = ghidra_decompiler::ArchitectureCapability::getMinorVersion();
        return "Ghidra Decompiler " + std::to_string(major) + "." + std::to_string(minor);
    }

    void setOption(const std::string& name, const std::string& value) override {
        (void)name;
        (void)value;

        if (arch_) {
            // Options are set via Architecture's option system
        }
    }

    void setSleighHome(const std::string& path) {
        sleighHome_ = path;
    }
};

std::unique_ptr<DecompilerAdapter> createDecompilerAdapter() {
    return std::make_unique<DecompilerAdapterImpl>();
}

} // namespace ghidra
