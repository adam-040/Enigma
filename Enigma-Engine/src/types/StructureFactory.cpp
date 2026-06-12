#include <ghidra/StructureFactory.h>
#include <stdexcept>

namespace ghidra {

const std::string StructureFactory::DEFAULT_STRUCTURE_NAME = "struct";

Structure* StructureFactory::createStructureDataType(Program* program, const Address& address, int dataLength) {
    return createStructureDataType(program, address, dataLength, DEFAULT_STRUCTURE_NAME, true);
}

Structure* StructureFactory::createStructureDataType(Program* program, const Address& address, int dataLength,
                                                     const std::string& structureName, bool makeUniqueName) {
    if (structureName.empty()) {
        throw std::invalid_argument("Structure name cannot be empty.");
    }
    if (dataLength <= 0) {
        throw std::invalid_argument("Structure length must be positive.");
    }

    // In Enigma Engine, we don't have the GUI DataProviderContexts, so this method is stubbed.
    // If it's ever needed natively, we would instantiate a headless DataTypeProviderContext.
    throw std::runtime_error("Not implemented: StructureFactory depends on GUI contexts in original Ghidra.");
}

Structure* StructureFactory::createStructureDataTypeInStrucuture(Program* program, const Address& address,
                                                                 const std::vector<int>& fromPath,
                                                                 const std::vector<int>& toPath) {
    return createStructureDataTypeInStrucuture(program, address, fromPath, toPath, DEFAULT_STRUCTURE_NAME, true);
}

Structure* StructureFactory::createStructureDataTypeInStrucuture(Program* program, const Address& address,
                                                                 const std::vector<int>& fromPath,
                                                                 const std::vector<int>& toPath,
                                                                 const std::string& structureName,
                                                                 bool makeUniqueName) {
    if (structureName.empty()) {
        throw std::invalid_argument("Structure name cannot be empty.");
    }
    throw std::runtime_error("Not implemented: StructureFactory depends on GUI contexts in original Ghidra.");
}

} // namespace ghidra
