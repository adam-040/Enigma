#include <ghidra/VarnodeAST.h>
#include <algorithm>

namespace ghidra {

VarnodeAST::VarnodeAST(const Address& a, uint4 sz, int32_t id)
    : Varnode(a, sz),
      bInput(false),
      bAddrTied(false),
      bPersistent(false),
      bUnaffected(false),
      bFree(true),
      bVolatile(false),
      uniqId(id),
      mergegroup(0),
      version(0),
      high(nullptr),
      def(nullptr),
      dataType(nullptr) {
}

bool VarnodeAST::isFree() const { return bFree; }
bool VarnodeAST::isInput() const { return bInput; }
bool VarnodeAST::isPersistent() const { return bPersistent; }
bool VarnodeAST::isAddrTied() const { return bAddrTied; }
bool VarnodeAST::isUnaffected() const { return bUnaffected; }
bool VarnodeAST::isVolatile() const { return bVolatile; }
DataType* VarnodeAST::getDataType() const { return dataType; }

PcodeOp* VarnodeAST::getDef() const { return def; }

const std::vector<PcodeOp*>& VarnodeAST::getDescendants() const {
    return descend;
}

PcodeOp* VarnodeAST::getLoneDescend() const {
    if (descend.size() != 1) {
        return nullptr;
    }
    return descend.front();
}

bool VarnodeAST::hasNoDescend() const {
    return descend.empty();
}

Address VarnodeAST::getPCAddress() const {
    if (bInput) {
        return Address::NO_ADDRESS;
    }
    if (def != nullptr) {
        return def->getSeqnum().getTarget();
    }
    if (descend.size() == 1) {
        return descend[0]->getSeqnum().getTarget();
    }
    return Address::NO_ADDRESS;
}

HighVariable* VarnodeAST::getHigh() const { return high; }
int32_t VarnodeAST::getUniqueId() const { return uniqId; }
int16_t VarnodeAST::getMergeGroup() const { return mergegroup; }
int16_t VarnodeAST::getVersion() const { return version; }

void VarnodeAST::setAddrtied(bool val) { bAddrTied = val; }

void VarnodeAST::setInput(bool val) {
    bInput = val;
    bFree = false;
    def = nullptr;
}

void VarnodeAST::setPersistent(bool val) { bPersistent = val; }
void VarnodeAST::setUnaffected(bool val) { bUnaffected = val; }
void VarnodeAST::setFree(bool val) { bFree = val; }

void VarnodeAST::setDef(PcodeOp* op) {
    def = op;
    if (op != nullptr) {
        bFree = false;
        bInput = false;
    }
}

void VarnodeAST::setMergeGroup(int16_t val) { mergegroup = val; }
void VarnodeAST::setVersion(int16_t val) { version = val; }
void VarnodeAST::setHigh(HighVariable* hi) { high = hi; }
void VarnodeAST::setVolatile(bool val) { bVolatile = val; }
void VarnodeAST::setDataType(DataType* type) { dataType = type; }

void VarnodeAST::addDescendant(PcodeOp* op) {
    descend.push_back(op);
}

void VarnodeAST::removeDescendant(PcodeOp* op) {
    auto it = std::find(descend.begin(), descend.end(), op);
    if (it != descend.end()) {
        descend.erase(it);
    }
}

void VarnodeAST::descendReplace(VarnodeAST* vn) {
    std::vector<PcodeOp*> opsToProcess = vn->descend; // نسخ لتجنب تعديل الـ list أثناء التكرار
    
    for (PcodeOp* op : opsToProcess) {
        if (op->getOutput() == this) {
            continue;
        }
        int num = op->getNumInputs();
        for (int i = 0; i < num; ++i) {
            if (op->getInput(i) == vn) {
                vn->removeDescendant(op);
                op->setInput(nullptr, i);
                addDescendant(op);
                op->setInput(this, i);
                break;
            }
        }
    }
}

bool VarnodeAST::operator==(const VarnodeAST& vn) const {
    if (this == &vn) {
        return true;
    }

    if (getOffset() != vn.getOffset() || getSize() != vn.getSize() ||
        getSpace() != vn.getSpace()) {
        return false;
    }

    if (isFree()) {
        if (vn.isFree()) {
            return (uniqId == vn.uniqId);
        }
        return false;
    } else if (vn.isFree()) {
        return false;
    }

    if (isInput() != vn.isInput()) {
        return false;
    }

    if (def != nullptr) {
        PcodeOp* vnDef = vn.getDef();
        if (vnDef == nullptr) {
            return false;
        }
        return (def->getSeqnum() == vnDef->getSeqnum());
    }
    return true;
}

} // namespace ghidra