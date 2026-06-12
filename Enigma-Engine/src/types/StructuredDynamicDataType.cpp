#include <ghidra/StructuredDynamicDataType.h>
#include <ghidra/DataTypeInstance.h>
#include <ghidra/ReadOnlyDataTypeComponent.h>
#include <ghidra/MemoryBufferImpl.h>
#include <ghidra/Settings.h>
#include <ghidra/ByteDataType.h>
#include <iostream>

namespace ghidra {

StructuredDynamicDataType::StructuredDynamicDataType(const std::string& name, const std::string& description, DataTypeManager* dtm)
    : DynamicDataType(name, dtm), description_(description) {
}

DataType* StructuredDynamicDataType::clone(DataTypeManager* dtm) const {
    return new StructuredDynamicDataType(getName(), description_, dtm);
}

std::string StructuredDynamicDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return getName();
}

int StructuredDynamicDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    return getLength();
}

DataType* StructuredDynamicDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

void StructuredDynamicDataType::add(DataType* data, const std::string& componentName, const std::string& componentDescription) {
    components_.push_back(data);
    componentNames_.push_back(componentName);
    componentDescs_.push_back(componentDescription);
}

void StructuredDynamicDataType::setComponents(const std::vector<DataType*>& components, 
                                              const std::vector<std::string>& componentNames,
                                              const std::vector<std::string>& componentDescs) {
    components_ = components;
    componentNames_ = componentNames;
    componentDescs_ = componentDescs;
}

std::vector<DataTypeComponent*> StructuredDynamicDataType::getAllComponents(MemBuffer* buf) {
    Memory* memory = buf->getMemory();

    std::vector<DataTypeComponent*> comps;
    comps.resize(components_.size(), nullptr);
    int offset = 0;
    
    MemoryBufferImpl newBuf(memory, buf->getAddress());
    try {
        for (size_t i = 0; i < components_.size(); i++) {
            DataTypeInstance* dti = DataTypeInstance::getDataTypeInstance(components_[i], &newBuf, false);
            if (!dti) {
                std::cerr << "StructuredDynamicDataType: Invalid data at " << newBuf.getAddress().toString() << "\n";
                // Cleanup allocated components if needed (but ownership is tricky. 
                // We'll return an empty list if it fails).
                return {};
            }
            int len = dti->getLength();
            std::string compName = componentNames_[i] + "_" + newBuf.getAddress().toString();
            comps[i] = new ReadOnlyDataTypeComponent(dti->getDataType(), this, len, static_cast<int>(i), offset,
                                                     compName, componentDescs_[i]);
            offset += len;
            newBuf.advance(len);
            delete dti; // DataTypeInstance is a factory-created wrapper
        }
    } catch (const std::exception& e) {
        std::cerr << "StructuredDynamicDataType: Invalid data at " << newBuf.getAddress().toString() << "\n";
        return {};
    }
    return comps;
}

} // namespace ghidra
