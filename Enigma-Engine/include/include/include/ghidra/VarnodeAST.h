#pragma once

#include <ghidra/Varnode.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/HighVariable.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class VarnodeAST : public Varnode {
private:
    bool bInput;
    bool bAddrTied;
    bool bPersistent;
    bool bUnaffected;
    bool bFree;
    bool bVolatile;
    int32_t uniqId;
    int16_t mergegroup;
    int16_t version;
    HighVariable* high;
    PcodeOp* def;
    DataType* dataType;
    std::vector<PcodeOp*> descend;

public:
    VarnodeAST(const Address& a, uint32_t sz, int32_t id);
    ~VarnodeAST() = default;

    bool isFree() const;
    bool isInput() const;
    bool isPersistent() const;
    bool isAddrTied() const;
    bool isUnaffected() const;
    bool isVolatile() const;
    DataType* getDataType() const;

    PcodeOp* getDef() const;
    const std::vector<PcodeOp*>& getDescendants() const;
    PcodeOp* getLoneDescend() const;
    bool hasNoDescend() const;
    Address getPCAddress() const;
    HighVariable* getHigh() const;
    int32_t getUniqueId() const;
    int16_t getMergeGroup() const;
    int16_t getVersion() const;

    void setAddrtied(bool val);
    void setInput(bool val);
    void setPersistent(bool val);
    void setUnaffected(bool val);
    void setFree(bool val);
    void setDef(PcodeOp* op);
    void setMergeGroup(int16_t val);
    void setVersion(int16_t val);
    void setHigh(HighVariable* hi);
    void setVolatile(bool val);
    void setDataType(DataType* type);

    void addDescendant(PcodeOp* op);
    void removeDescendant(PcodeOp* op);
    void descendReplace(VarnodeAST* vn);

    bool operator==(const VarnodeAST& vn) const;
    bool operator!=(const VarnodeAST& vn) const { return !(*this == vn); }
};

} // namespace ghidra