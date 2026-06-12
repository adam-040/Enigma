#include <ghidra/CompositeInternal.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/DataType.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <ghidra/DataOrganization.h>
#include <sstream>

namespace ghidra {

const std::string CompositeInternal::ALIGN_NAME = "aligned";
const std::string CompositeInternal::PACKING_NAME = "pack";
const std::string CompositeInternal::DISABLED_PACKING_NAME = "disabled";
const std::string CompositeInternal::DEFAULT_PACKING_NAME = "";

const CompositeInternal::ComponentComparator CompositeInternal::ComponentComparator::INSTANCE;
const CompositeInternal::OffsetComparator CompositeInternal::OffsetComparator::INSTANCE;
const CompositeInternal::OrdinalComparator CompositeInternal::OrdinalComparator::INSTANCE;

int CompositeInternal::ComponentComparator::compare(const DataTypeComponent& dtc1, const DataTypeComponent& dtc2) const {
    return dtc1.getOrdinal() - dtc2.getOrdinal();
}

int CompositeInternal::OffsetComparator::compare(const DataTypeComponent* dtc, int offset) const {
    if (offset < dtc->getOffset()) return 1;
    if (offset > dtc->getEndOffset()) return -1;
    return 0;
}

int CompositeInternal::OrdinalComparator::compare(const DataTypeComponent* dtc, int ordinal) const {
    return dtc->getOrdinal() - ordinal;
}

std::string CompositeInternal::toString(const Composite* composite) {
    std::ostringstream buf;
    buf << composite->getPathName() << std::endl;
    buf << getAlignmentAndPackingString(composite) << std::endl;
    buf << (dynamic_cast<const Structure*>(composite) ? "Structure" : "Union")
        << " " << composite->getDisplayName() << " {" << std::endl;

    auto components = composite->getDefinedComponents();
    for (auto* dtc : components) {
        auto* dataType = dtc->getDataType();
        buf << "   " << dtc->getOffset();
        buf << "   " << dataType->getName();
        if (auto* bfDt = dynamic_cast<BitFieldDataType*>(dataType)) {
            buf << "(" << bfDt->getBitOffset() << ")";
        }
        buf << "   " << dtc->getLength();
        std::string name = dtc->getFieldName();
        buf << "   " << (name.empty() ? "" : name);
        std::string comment = dtc->getComment();
        buf << "   \"" << (comment.empty() ? "" : comment) << "\"" << std::endl;
    }
    buf << "}" << std::endl;
    int length = composite->isZeroLength() ? 0 : composite->getLength();
    buf << "Length: " << length << " Alignment: " << composite->getAlignment() << std::endl;
    return buf.str();
}

std::string CompositeInternal::getMinAlignmentString(const Composite* composite) {
    if (composite->isDefaultAligned()) return "";
    std::ostringstream buf;
    buf << ALIGN_NAME << "(";
    if (composite->isMachineAligned()) {
        buf << "machine:" << composite->getDataOrganization()->getMachineAlignment();
    } else {
        buf << composite->getExplicitMinimumAlignment();
    }
    buf << ")";
    return buf.str();
}

std::string CompositeInternal::getPackingString(const Composite* composite) {
    std::ostringstream buf;
    buf << PACKING_NAME << "(";
    if (composite->isPackingEnabled()) {
        if (composite->hasExplicitPackingValue()) {
            buf << composite->getExplicitPackingValue();
        } else {
            buf << DEFAULT_PACKING_NAME;
        }
    } else {
        buf << DISABLED_PACKING_NAME;
    }
    buf << ")";
    return buf.str();
}

std::string CompositeInternal::getAlignmentAndPackingString(const Composite* composite) {
    std::string minAlign = getMinAlignmentString(composite);
    std::string packing = getPackingString(composite);
    if (!minAlign.empty()) {
        return minAlign + " " + packing;
    }
    return packing;
}

} // namespace ghidra
