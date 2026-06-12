#pragma once

#include <ghidra/Funcdata.h>
#include <ghidra/LoadImage.h>
#include <ghidra/Sleigh.h>
#include <ghidra/PrintC.h>
#include <string>
#include <memory>

namespace ghidra {

class EnigmaPipeline {
public:
    EnigmaPipeline();
    ~EnigmaPipeline();

    bool loadBinary(const std::string& path);
    bool decompile();
    std::string getOutput() const;

    void setArchitecture(const std::string& arch, int bitness);
    void setBaseAddress(uint64_t base);

    const Funcdata& getFuncdata() const { return *fd_; }
    const Sleigh& getSleigh() const { return *sleigh_; }
    bool isLoaded() const { return loaded_; }
    int4 getLoaderSize() const { return loader_ ? loader_->getSize() : 0; }

private:
    std::unique_ptr<LoadImageRawFile> loader_;
    std::unique_ptr<Sleigh> sleigh_;
    std::unique_ptr<Funcdata> fd_;
    std::unique_ptr<PrintC> printer_;
    std::string arch_;
    int bitness_ = 64;
    uint64_t baseAddr_ = 0x1000;
    bool loaded_ = false;
    std::string output_;
};

} // namespace ghidra
