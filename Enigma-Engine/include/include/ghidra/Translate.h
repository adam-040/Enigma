#pragma once

#include <ghidra/Address.h>
#include <ghidra/FloatFormat.h>
#include <ghidra/LoadImage.h>
#include <ghidra/Types.h>
#include <string>
#include <vector>
#include <map>

namespace ghidra {

class PcodeOpAST;
class VarnodeAST;
class Funcdata;

class Translate {
public:
    enum InstructionFallthrough {
        FALLTHROUGH_UNKNOWN = 0,
        FALLTHROUGH_YES,
        FALLTHROUGH_NO,
        FALLTHROUGH_OVERRIDE
    };

    struct TranslateStats {
        int4 numInstructions = 0;
        int4 numPcodeOps = 0;
        int4 decodeTime = 0;
        int4 pcodeTime = 0;
    };

protected:
    LoadImage* loader;
    TranslateStats stats;
    std::string targetArch;
    int4 pointerSize;
    int4 codeAlign;
    bool bigEndian;
    std::vector<FloatFormat> floatformats;

public:
    Translate(LoadImage* ld, int4 ptrSize, bool endian);
    virtual ~Translate() = default;

    virtual int4 instructionLength(const Address& addr) const = 0;
    virtual int4 printAssembly(const Address& addr, std::string& output) const = 0;
    virtual int4 oneInstruction(Funcdata& fd, const Address& addr) = 0;

    virtual void setContextDefault(const std::string& name, uintb value) = 0;
    virtual void allowContextSet(bool val) = 0;

    LoadImage* getLoader() const { return loader; }
    int4 getPointerSize() const { return pointerSize; }
    int4 getCodeAlign() const { return codeAlign; }
    bool isBigEndian() const { return bigEndian; }
    const std::string& getTargetArch() const { return targetArch; }
    const TranslateStats& getStats() const { return stats; }

    virtual bool hasFallthrough(const Address& addr) const = 0;
    virtual Address getFallthrough(const Address& addr) const = 0;
    virtual bool isBranchFallthrough(const Address& addr) const = 0;
    virtual bool isCallInstruction(const Address& addr) const = 0;
    virtual bool isReturnInstruction(const Address& addr) const = 0;

    void setDefaultFloatFormats();
    const FloatFormat* getFloatFormat(int4 size) const;
};

} // namespace ghidra
