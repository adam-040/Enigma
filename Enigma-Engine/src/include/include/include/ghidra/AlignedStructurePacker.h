/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AlignedStructurePacker.h
/// \brief Provides aligned packing of Structure components.
/// Translated from: ghidra.program.model.data.AlignedStructurePacker
#pragma once

#include <vector>

namespace ghidra {

class StructureInternal;
class InternalDataTypeComponent;

class AlignedStructurePacker {
public:
    struct StructurePackResult {
        int numComponents;
        int structureLength;
        int alignment;
        bool componentsChanged;

        StructurePackResult(int numComponents, int structureLength, int alignment,
                            bool componentsChanged)
            : numComponents(numComponents),
              structureLength(structureLength),
              alignment(alignment),
              componentsChanged(componentsChanged) {}
    };

protected:
    AlignedStructurePacker(StructureInternal* structure,
                           std::vector<InternalDataTypeComponent*> components);

    StructurePackResult pack();

public:
    static StructurePackResult packComponents(StructureInternal* structure,
                                              std::vector<InternalDataTypeComponent*> components);

private:
    StructureInternal* structure_;
    std::vector<InternalDataTypeComponent*> components_;
};

} // namespace ghidra
