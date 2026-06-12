#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class Varnode;
class VarnodeAST;
class HighFunction;
class HighSymbol;
class DataType;
class Decoder;

typedef uint32_t uint4;

class HighVariable {
protected:
    std::string name;
    DataType* type;                                     // لا يملكه
    VarnodeAST* represent;                              // الـ Varnode الممثل لهذا المتغير (لا يملكه)
    std::vector<VarnodeAST*> instances;                 // حالات المتغير المختلفة (لا يملكها)
    int32_t offset;
    HighFunction* function;                             // الدالة المرتبطة (لا يملكها)

    void setHighOnInstances();
    void decodeInstances(Decoder* decoder);             // TODO: Implement when Decoder is ready

public:
    HighVariable(HighFunction* func);
    HighVariable(const std::string& nm, DataType* tp, VarnodeAST* rep, 
                 const std::vector<VarnodeAST*>& inst, HighFunction* func);
    virtual ~HighVariable() = default;

    HighFunction* getHighFunction() const;
    const std::string& getName() const;
    uint4 getSize() const;
    DataType* getDataType() const;
    void setDataType(DataType* tp);
    VarnodeAST* getRepresentative() const;
    const std::vector<VarnodeAST*>& getInstances() const;

    virtual HighSymbol* getSymbol() const = 0;          // Pure virtual (Abstract)
    int32_t getOffset() const;

    void attachInstances(const std::vector<VarnodeAST*>& inst, VarnodeAST* rep);

    bool requiresDynamicStorage() const;

    virtual void decode(Decoder* decoder) = 0;          // Pure virtual (Abstract)
};

} // namespace ghidra