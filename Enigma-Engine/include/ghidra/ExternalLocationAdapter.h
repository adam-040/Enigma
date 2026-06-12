/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalLocationAdapter.h
/// \brief Adapter wrapping an ExternalLocation iterator
/// Translated from: ghidra.program.model.symbol.ExternalLocationAdapter
#pragma once

#include <ghidra/ExternalLocationIterator.h>
#include <vector>

namespace ghidra {

class ExternalLocationAdapter : public ExternalLocationIterator {
public:
    explicit ExternalLocationAdapter(std::vector<ExternalLocation*> locations);
    explicit ExternalLocationAdapter(std::vector<ExternalLocation*>::iterator begin,
                                      std::vector<ExternalLocation*>::iterator end);

    bool hasNext() override;
    ExternalLocation* next() override;

private:
    std::vector<ExternalLocation*> locations_;
    size_t index_ = 0;
};

} // namespace ghidra
