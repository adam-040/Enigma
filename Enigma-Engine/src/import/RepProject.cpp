/* ###
 * IP: Enigma Engine (original work)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/import/RepProject.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "ZipArchive.h"

namespace fs = std::filesystem;

namespace ghidra {

namespace {

std::string stripCR(std::string s) {
    if (!s.empty() && s.back() == '\r') {
        s.pop_back();
    }
    return s;
}

}  // namespace

RepProject::~RepProject() = default;

RepProject::RepProject(const std::string& sourcePath) {
    fs::path p(sourcePath);
    if (fs::is_directory(p)) {
        loadFromDirectory(sourcePath);
    } else if (fs::is_regular_file(p)) {
        loadFromZip(sourcePath);
    } else {
        throw std::runtime_error("Rep: no such project source: " + sourcePath);
    }
}

void RepProject::loadFromDirectory(const std::string& dir) {
    sourceDir_ = dir;
    projectName_ = fs::path(dir).filename().string();
    const std::string indexPath = dir + "/idata/~index.dat";
    std::ifstream in(indexPath, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Rep: no idata/~index.dat in " + dir);
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    parseIndex(ss.str());
}

void RepProject::loadFromZip(const std::string& path) {
    zip_ = ZipArchive::fromFile(path);
    zipNames_ = zip_->entryNames();

    // Find the "<name>.rep/idata/~index.dat" member.
    for (const std::string& name : zipNames_) {
        size_t pos = name.find("/idata/~index.dat");
        if (pos == std::string::npos) {
            continue;
        }
        std::string prefix = name.substr(0, pos);
        if (!prefix.empty() && prefix.back() != '/') {
            projectName_ = prefix;
            auto indexBytes = zip_->readEntry(name);
            parseIndex(std::string(indexBytes.begin(), indexBytes.end()));
            return;
        }
    }
    throw std::runtime_error("Rep: no idata/~index.dat member in archive " + path);
}

void RepProject::parseIndex(const std::string& indexText) {
    std::istringstream in(indexText);
    std::string line;
    while (std::getline(in, line)) {
        line = stripCR(line);
        if (line.size() < 3 || line[0] != ' ' || line[1] != ' ') {
            continue;
        }
        // "  <8 hex id>:<name>:<fileId>"
        size_t c1 = line.find(':');
        if (c1 == std::string::npos || c1 != 10) {
            continue;
        }
        size_t c2 = line.find(':', c1 + 1);
        if (c2 == std::string::npos) {
            continue;
        }
        std::string idHex = line.substr(2, 8);
        std::string name = line.substr(c1 + 1, c2 - c1 - 1);
        std::string fileId = line.substr(c2 + 1);
        if (name.empty() || idHex.empty()) {
            continue;
        }
        RepProgram program;
        try {
            program.id = static_cast<int32_t>(std::stoul(idHex, nullptr, 16));
        } catch (...) {
            continue;
        }
        program.name = name;
        program.fileId = fileId;
        // id is always 8 hex digits as written by Ghidra (lowercase)
        if (idHex.size() < 8) {
            idHex = std::string(8 - idHex.size(), '0') + idHex;
        }
        std::transform(idHex.begin(), idHex.end(), idHex.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        program.prpPath = "idata/00/" + idHex + ".prp";
        program.dbBase = "idata/00/~" + idHex + ".db";
        programs_.push_back(std::move(program));
    }

    // Check CONTENT_TYPE for each entry.
    for (RepProgram& program : programs_) {
        if (!fileExists(program.prpPath)) {
            continue;
        }
        std::vector<uint8_t> prp = readFile(program.prpPath);
        std::string text(prp.begin(), prp.end());
        if (text.find("CONTENT_TYPE") != std::string::npos &&
            text.find("Program") != std::string::npos) {
            program.isProgram = true;
        }
    }
}

bool RepProject::fileExists(const std::string& relPath) const {
    if (zip_) {
        return zip_->hasEntry(relPath);
    }
    return fs::exists(fs::path(sourceDir_) / relPath);
}

std::vector<uint8_t> RepProject::readFile(const std::string& relPath) const {
    if (zip_) {
        return zip_->readEntry(relPath);
    }
    fs::path full = fs::path(sourceDir_) / relPath;
    std::ifstream in(full, std::ios::binary | std::ios::ate);
    if (!in) {
        throw std::runtime_error("Rep: cannot read " + relPath);
    }
    std::streamsize n = in.tellg();
    if (n <= 0) {
        return {};
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(n));
    in.seekg(0);
    in.read(reinterpret_cast<char*>(bytes.data()), n);
    if (!in) {
        throw std::runtime_error("Rep: failed to read " + relPath);
    }
    return bytes;
}

std::vector<std::string> RepProject::listDirectory(const std::string& relDir) const {
    std::vector<std::string> out;
    if (zip_) {
        std::string prefix = relDir;
        if (!prefix.empty() && prefix.back() != '/') {
            prefix += '/';
        }
        for (const std::string& name : zipNames_) {
            if (name.compare(0, prefix.size(), prefix) == 0) {
                out.push_back(name);
            }
        }
        return out;
    }
    fs::path full = fs::path(sourceDir_) / relDir;
    if (!fs::is_directory(full)) {
        return out;
    }
    for (const auto& entryIt : fs::directory_iterator(full)) {
        out.push_back(relDir + "/" + entryIt.path().filename().string());
    }
    return out;
}

std::vector<uint8_t> RepProject::getDatabaseBytes(const RepProgram& program) const {
    // Pick the largest db.<N>.gbf version file in the program's database dir.
    int bestVersion = -1;
    std::string best;
    for (const std::string& name : listDirectory(program.dbBase)) {
        size_t slash = name.find_last_of('/');
        std::string base = slash == std::string::npos ? name : name.substr(slash + 1);
        if (base.rfind("db.", 0) != 0 || base.find(".gbf") == std::string::npos) {
            continue;
        }
        int version = 0;
        try {
            version = std::stoi(base.substr(3));
        } catch (...) {
            continue;
        }
        if (version > bestVersion) {
            bestVersion = version;
            best = name;
        }
    }
    if (best.empty()) {
        throw std::runtime_error("Rep: no db file for program " + program.name);
    }
    return readFile(best);
}

}  // namespace ghidra