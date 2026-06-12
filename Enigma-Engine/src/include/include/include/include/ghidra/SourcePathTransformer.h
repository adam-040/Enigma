/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourcePathTransformer.h
/// \brief Interface for transforming SourceFile paths
/// Translated from: ghidra.program.model.sourcemap.SourcePathTransformer
#pragma once

#include <string>
#include <vector>

namespace ghidra {

class SourceFile;
class SourcePathTransformRecord;

class SourcePathTransformer {
public:
    virtual ~SourcePathTransformer() = default;

    virtual void addFileTransform(SourceFile* sourceFile, const std::string& path) = 0;

    virtual void removeFileTransform(SourceFile* sourceFile) = 0;

    virtual void addDirectoryTransform(const std::string& sourceDir,
                                       const std::string& targetDir) = 0;

    virtual void removeDirectoryTransform(const std::string& sourceDir) = 0;

    virtual std::string getTransformedPath(SourceFile* sourceFile,
                                           bool useExistingAsDefault) = 0;

    virtual std::vector<SourcePathTransformRecord> getTransformRecords() = 0;
};

} // namespace ghidra
