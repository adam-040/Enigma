#pragma once

#include <ghidra/Structure.h>
#include <ghidra/Program.h>
#include <ghidra/Address.h>
#include <vector>

namespace ghidra {

/**
 * Creates and initializes Structure objects.
 */
class StructureFactory {
public:
    StructureFactory() = delete;

    static const std::string DEFAULT_STRUCTURE_NAME;

    /**
     * Creates a StructureDataType instance based upon the information provided.
     * Note: In Enigma Engine, this will throw as it depends on GUI provider context.
     */
    static Structure* createStructureDataType(Program* program, const Address& address, int dataLength);

    static Structure* createStructureDataType(Program* program, const Address& address, int dataLength,
                                              const std::string& structureName, bool makeUniqueName);

    static Structure* createStructureDataTypeInStrucuture(Program* program, const Address& address,
                                                          const std::vector<int>& fromPath,
                                                          const std::vector<int>& toPath);

    static Structure* createStructureDataTypeInStrucuture(Program* program, const Address& address,
                                                          const std::vector<int>& fromPath,
                                                          const std::vector<int>& toPath,
                                                          const std::string& structureName,
                                                          bool makeUniqueName);
};

} // namespace ghidra
