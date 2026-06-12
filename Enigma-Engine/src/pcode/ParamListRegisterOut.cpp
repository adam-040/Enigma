/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ParamListRegisterOut.h>
#include <ghidra/VoidDataType.h>

namespace ghidra {

void ParamListRegisterOut::assignMap(const PrototypePieces& proto, DataTypeManager* dtManager,
                                      std::vector<ParameterPieces>& res, bool addAutoParams) {
    std::vector<int> status(getNumGroup(), 0);

    ParameterPieces store;
    res.push_back(store);
    if (VoidDataType::isVoidDataType(proto.outtype)) {
        res.back().type = proto.outtype;
        return;
    }
    assignAddress(proto.outtype, proto, -1, dtManager, status.data(), res.back());
}

} // namespace ghidra
