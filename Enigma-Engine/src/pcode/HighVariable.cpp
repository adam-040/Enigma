#include <ghidra/HighVariable.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/Decoder.h>
#include <ghidra/AttributeId.h>
#include <ghidra/DecoderException.h>

namespace ghidra {

HighVariable::HighVariable(HighFunction* func)
    : type(nullptr), represent(nullptr), offset(-1), function(func) {
}

HighVariable::HighVariable(const std::string& nm, DataType* tp, VarnodeAST* rep,
                           const std::vector<VarnodeAST*>& inst, HighFunction* func)
    : name(nm), type(tp), represent(nullptr), offset(-1), function(func) {
    attachInstances(inst, rep);
}

void HighVariable::setHighOnInstances() {
    for (VarnodeAST* instance : instances) {
        if (instance != nullptr) {
            // في الجافا كان يستخدم instanceof، في C++ نستخدم dynamic_cast
            // لكن بما أننا خزّناهم كـ VarnodeAST* بالفعل في الـ vector، لا نحتاج dynamic_cast هنا
            instance->setHigh(this);
        }
    }
}

HighFunction* HighVariable::getHighFunction() const { return function; }
const std::string& HighVariable::getName() const { return name; }

uint4 HighVariable::getSize() const {
    return represent != nullptr ? represent->getSize() : 0;
}

DataType* HighVariable::getDataType() const { return type; }
void HighVariable::setDataType(DataType* tp) { type = tp; }
VarnodeAST* HighVariable::getRepresentative() const { return represent; }
const std::vector<VarnodeAST*>& HighVariable::getInstances() const { return instances; }

int32_t HighVariable::getOffset() const { return offset; }

void HighVariable::attachInstances(const std::vector<VarnodeAST*>& inst, VarnodeAST* rep) {
    represent = rep;
    if (inst.empty()) {
        instances.clear();
        if (rep != nullptr) {
            instances.push_back(rep);
        }
    } else {
        instances = inst;
    }
}

void HighVariable::decodeInstances(Decoder* decoder) {
    /*
    int repref = (int)decoder->readUnsignedInteger(ATTRIB_REPREF);
    // VarnodeAST* rep = function->getRef(repref); // Requires full HighFunction
    // if (rep == nullptr) {
    //     throw DecoderException("Undefined varnode reference");
    // }

    // type = nullptr;
    // std::vector<VarnodeAST*> vnlist;
    // type = function->getDataTypeManager()->decodeDataType(decoder);

    // while (decoder->peekElement() != 0) {
    //     VarnodeAST* vn = VarnodeAST::decode(decoder, function);
    //     vnlist.push_back(vn);
    // }

    // attachInstances(vnlist, rep);
    // setHighOnInstances();
    */
}

bool HighVariable::requiresDynamicStorage() const {
    if (represent != nullptr && represent->isUnique()) {
        return true;
    }
    if (represent != nullptr && represent->getAddress().isStackAddress() && !represent->isAddrTied()) {
        return true;
    }
    return false;
}

} // namespace ghidra