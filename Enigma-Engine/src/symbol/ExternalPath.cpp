/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/ExternalPath.h"
#include <sstream>
#include <stdexcept>

namespace ghidra {

ExternalPath::ExternalPath(std::string library, std::string label) {
    if (library.empty() || label.empty()) {
        throw std::invalid_argument("Library and label must be non-empty");
    }
    elements_.push_back(std::move(library));
    elements_.push_back(std::move(label));
}

ExternalPath::ExternalPath(std::vector<std::string> elements) : elements_(std::move(elements)) {
    if (elements_.size() < 2) {
        throw std::invalid_argument("External path must have at least 2 elements (library and label)");
    }
    for (const auto& s : elements_) {
        if (s.empty()) {
            throw std::invalid_argument("External path elements cannot be empty");
        }
    }
}

const std::string& ExternalPath::getLibraryName() const {
    return elements_[0];
}

const std::string& ExternalPath::getName() const {
    return elements_.back();
}

std::vector<std::string> ExternalPath::getPathElements() const {
    return elements_;
}

std::string ExternalPath::toString() const {
    std::ostringstream oss;
    for (size_t i = 0; i < elements_.size(); ++i) {
        if (i > 0) oss << DELIMITER;
        oss << elements_[i];
    }
    return oss.str();
}

} // namespace ghidra
