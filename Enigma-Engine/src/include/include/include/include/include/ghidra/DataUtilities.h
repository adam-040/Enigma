#pragma once

#include <ghidra/Address.h>
#include <ghidra/Program.h>
#include <string>

namespace ghidra {

class DataUtilities {
public:
    DataUtilities() = delete;

    /**
     * Determine if the specified name is a valid data-type name
     * @param name candidate data-type name
     * @return true if name is valid, else false
     */
    static bool isValidDataTypeName(const std::string& name);

    /**
     * Finds the first conflicting address in the given address range.
     * @param program The program.
     * @param addr The starting address of the range.
     * @param length The length of the range.
     * @param ignoreUndefinedData True to ignore Undefined data.
     * @return The address of the first conflict, or Address::NO_ADDRESS if none.
     */
    static Address findFirstConflictingAddress(Program* program, const Address& addr, int length, bool ignoreUndefinedData);

    /**
     * Determine if there is only undefined data from startAddress to endAddress.
     */
    static bool isUndefinedRange(Program* program, const Address& startAddress, const Address& endAddress);
};

} // namespace ghidra
