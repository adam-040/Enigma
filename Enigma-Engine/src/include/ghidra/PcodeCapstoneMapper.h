#pragma once

#include <ghidra/Disassembler.h>
#include <ghidra/Funcdata.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Types.h>
#include <string>
#include <unordered_map>
#include <functional>
#include <vector>
#include <memory>

namespace ghidra {

class PcodeCapstoneMapper {
public:
    PcodeCapstoneMapper();
    ~PcodeCapstoneMapper() = default;

    bool initialize(const std::string& architecture);
    bool isInitialized() const { return initialized_; }

    void mapInstruction(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    bool isMemoryOperand(const std::string& op) const;
    int getUniqueCounter() const { return uniqueCounter_; }

private:
    bool initialized_ = false;
    std::string architecture_;
    bool isAARCH64_ = false;
    bool isARM_ = false;
    bool isMIPS_ = false;
    bool isPPC_ = false;

    // address spaces
    std::unique_ptr<GenericAddressSpace> constSpace_;
    std::unique_ptr<GenericAddressSpace> uniqueSpace_;
    std::unique_ptr<GenericAddressSpace> regSpace_;

    // varnode/register cache across instructions within a function
    std::unordered_map<std::string, VarnodeAST*> regCache_;
    int uniqueCounter_ = 0;

    // helpers
    VarnodeAST* makeConst(Funcdata& fd, uintb val, int4 size);
    VarnodeAST* makeUnique(Funcdata& fd, int4 size);
    VarnodeAST* makeReg(Funcdata& fd, const std::string& name, int4 size, uintb offset);
    VarnodeAST* getOrCreateReg(Funcdata& fd, const std::string& name, int4 size, uintb offset);
    VarnodeAST* parseOperand(const std::string& op, Funcdata& fd, const Address& addr, int ptrSize);

    // dispatch
    void mapDefault(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapCopyMov(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapAddSub(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode);
    void mapCall(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapCallInd(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapReturn(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapBranch(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapBranchInd(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapCBranch(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapLoad(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapStore(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapPtrAdd(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapSubpiece(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapPopcount(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapInt2Float(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapFloat2Int(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapBoolOp(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode);

    // single-op helpers
    void emitOp(Funcdata& fd, const Address& addr, int seq, int opcode,
                const std::vector<VarnodeAST*>& inputs, VarnodeAST* output);

    // extended instruction handlers
    void mapIncDec(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, bool isInc);
    void mapNegNot(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, bool isNeg);
    void mapCmpTest(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, bool isTest);
    void mapMulDiv(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode);
    void mapSyscall(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);
    void mapXchg(const DisassembledInstruction& di, Funcdata& fd, const Address& addr);

    // float helpers
    void mapFloatArith(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode);
    void mapFloatCmp(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode);
    void mapFloatUnary(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode);

    // per-architecture dispatch tables
    using Handler = std::function<void(const DisassembledInstruction&, Funcdata&, const Address&)>;
    std::unordered_map<std::string, Handler> x86Handlers_;
    std::unordered_map<std::string, Handler> armHandlers_;
    std::unordered_map<std::string, Handler> aarch64Handlers_;
    std::unordered_map<std::string, Handler> mipsHandlers_;
    std::unordered_map<std::string, Handler> ppcHandlers_;

    void buildX86Handlers();
    void buildARMHandlers();
    void buildAARCH64Handlers();
    void buildMIPSHandlers();
    void buildPPCHandlers();
};

} // namespace ghidra
