/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourcePathTransformRecord.h
/// \brief Value class for a source path transformation record
/// Translated from: ghidra.program.model.sourcemap.SourcePathTransformRecord
#pragma once

#include <string>

namespace ghidra {

class SourceFile;

class SourcePathTransformRecord {
public:
    SourcePathTransformRecord(const std::string& source, SourceFile* sourceFile,
                              const std::string& target)
        : source_(source), sourceFile_(sourceFile), target_(target) {}

    const std::string& getSource() const { return source_; }
    SourceFile* getSourceFile() const { return sourceFile_; }
    const std::string& getTarget() const { return target_; }

    bool isDirectoryTransform() const {
        return !source_.empty() && source_.back() == '/';
    }

private:
    std::string source_;
    SourceFile* sourceFile_;
    std::string target_;
};

} // namespace ghidra
