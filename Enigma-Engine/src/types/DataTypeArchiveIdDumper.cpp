/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/DataTypeArchiveIdDumper.h>
#include <fstream>
#include <iostream>

namespace ghidra {

void DataTypeArchiveIdDumper::dumpIds(const std::string& archiveFile, const std::string& outputFile) {
    std::ifstream in(archiveFile, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open archive: " << archiveFile << std::endl;
        return;
    }
    std::ofstream out(outputFile);
    if (!out) {
        std::cerr << "Cannot open output: " << outputFile << std::endl;
        return;
    }
    out << "# DataType archive IDs from: " << archiveFile << std::endl;
    out << "# Dump: requires database layer" << std::endl;
}

} // namespace ghidra
