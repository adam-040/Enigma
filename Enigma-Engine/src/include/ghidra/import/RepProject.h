/* ###
 * IP: Enigma Engine (original work)
 *
 * Discovery of Ghidra project (.rep) contents from either an exploded
 * project directory or a zipped .gzf export.  Parses idata/~index.dat and the
 * per-file .prp property files to locate stored programs.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {

class ZipArchive;

/**
 * Identifies one file entry inside a Ghidra project repository, as listed in
 * idata/~index.dat.
 */
struct RepProgram {
    int32_t id = 0;         // numeric id, printed as 8 hex digits
    std::string name;       // file name, e.g. "notepad_test.exe"
    std::string fileId;     // content file id (hex string)
    std::string prpPath;    // idata/00/<id>.prp
    std::string dbBase;     // idata/00/~<id>.db
    bool isProgram = false; // CONTENT_TYPE == "Program"
};

/**
 * A Ghidra project repository (.rep): either an exploded directory or the
 * zipped export inside a .gzf archive.  Provides access to the idata index
 * and the database files of stored programs.
 */
class RepProject {
public:
    /**
     * Opens a repository source: a directory (typically ending in ".rep") or
     * a zip file (.gzf or plain zip containing the ".rep" tree).
     * Throws std::runtime_error on failure.
     */
    explicit RepProject(const std::string& sourcePath);

    ~RepProject();

    const std::string& projectName() const { return projectName_; }

    /** Programs listed in ~index.dat (with the CONTENT_TYPE check applied). */
    const std::vector<RepProgram>& programs() const { return programs_; }

    /** Reads the largest db.<N>.gbf database file for the given program. */
    std::vector<uint8_t> getDatabaseBytes(const RepProgram& program) const;

private:
    void loadFromDirectory(const std::string& dir);
    void loadFromZip(const std::string& path);
    void parseIndex(const std::string& indexText);

    std::vector<uint8_t> readFile(const std::string& relPath) const;
    bool fileExists(const std::string& relPath) const;
    std::vector<std::string> listDirectory(const std::string& relDir) const;

    std::string projectName_;
    std::string sourceDir_;   // set when source is an exploded directory
    std::unique_ptr<ZipArchive> zip_;  // set when source is an archive
    std::vector<std::string> zipNames_;
    std::vector<RepProgram> programs_;
};

}  // namespace ghidra