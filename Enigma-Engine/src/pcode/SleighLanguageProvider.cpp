#include <ghidra/SleighLanguageProvider.h>
#include <ghidra/SleighLanguage.h>
#include <ghidra/SleighCompilerSpecDescription.h>
#include <ghidra/SleighLanguageFile.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/LanguageNotFoundException.h>
#include <ghidra/TaskMonitor.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>

#ifndef ENIGMA_SLEIGH_DIR
#define ENIGMA_SLEIGH_DIR ""
#endif

namespace ghidra {

SleighLanguageProvider& SleighLanguageProvider::getSleighLanguageProvider() {
    static SleighLanguageProvider instance;
    return instance;
}

SleighLanguageProvider::SleighLanguageProvider() {
    try {
        createLanguages();
    } catch (const std::exception& e) {
        std::cerr << "SleighLanguageProvider initialization failed: " << e.what() << "\n";
    }
}

SleighLanguageProvider::LanguageRec::~LanguageRec() {
    unloadLanguage();
    delete langDesc;
}

void SleighLanguageProvider::LanguageRec::loadLanguage(TaskMonitor* monitor) {
    if (failed) throw LanguageNotFoundException(langDesc->getLanguageID(), "Language previously failed to load");
    try {
        lang = new SleighLanguage(langDesc, monitor);
    } catch (const std::exception& e) {
        failed = true;
        throw LanguageNotFoundException(langDesc->getLanguageID(), e.what());
    }
}

void SleighLanguageProvider::LanguageRec::unloadLanguage() {
    delete lang;
    lang = nullptr;
}

Language* SleighLanguageProvider::getLanguage(const LanguageID& languageId, TaskMonitor* monitor) {
    auto it = languages_.find(languageId.toString());
    if (it == languages_.end()) {
        throw LanguageNotFoundException(languageId, "Language not found in definitions");
    }
    
    LanguageRec* langRec = it->second.get();
    if (!langRec->lang) {
        langRec->loadLanguage(monitor);
    }
    return langRec->lang;
}

std::vector<LanguageDescription*> SleighLanguageProvider::getLanguageDescriptions() {
    std::vector<LanguageDescription*> descs;
    for (const auto& pair : languages_) {
        descs.push_back(pair.second->langDesc);
    }
    return descs;
}

bool SleighLanguageProvider::hadLoadFailure() {
    return failureCount_ > 0;
}

bool SleighLanguageProvider::isLanguageLoaded(const LanguageID& languageId) {
    auto it = languages_.find(languageId.toString());
    if (it == languages_.end()) return false;
    return it->second->lang != nullptr;
}

static std::vector<std::filesystem::path> getSleighCandidates() {
    std::vector<std::filesystem::path> candidates;
    if (const char* envPath = std::getenv("ENIGMA_SLEIGH_DIR")) {
        if (*envPath != '\0') candidates.emplace_back(envPath);
    }
    if (std::string compilePath = ENIGMA_SLEIGH_DIR; !compilePath.empty()) {
        candidates.emplace_back(compilePath);
    }
    std::error_code ec;
    auto cwdSleigh = std::filesystem::current_path(ec) / "sleigh";
    if (!ec && std::filesystem::is_directory(cwdSleigh, ec)) {
        candidates.emplace_back(cwdSleigh);
    }
    return candidates;
}

void SleighLanguageProvider::createLanguages() {
    for (const auto& root : getSleighCandidates()) {
        std::error_code ec;
        if (!std::filesystem::is_directory(root, ec)) continue;
        
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root, ec)) {
            if (ec) break;
            if (entry.is_regular_file(ec) && entry.path().extension() == ".ldefs") {
                createLanguages(entry.path().string());
            }
        }
    }
}

void SleighLanguageProvider::createLanguages(const std::string& file) {
    try {
        createLanguageDescriptions(file);
    } catch (const std::exception& e) {
        failureCount_++;
        std::cerr << "Problem loading " << file << ": " << e.what() << "\n";
    }
}

void SleighLanguageProvider::createLanguageDescriptions(const std::string& specFile) {
    std::ifstream file(specFile);
    if (!file) throw std::runtime_error("Could not open file: " + specFile);
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    XmlPullParser parser(buffer.str());
    std::filesystem::path p(specFile);
    read(&parser, p.parent_path().string(), p.filename().string());
}

void SleighLanguageProvider::read(XmlPullParser* parser, const std::string& parentDirectory, const std::string& ldefs) {
    while (parser->hasNext()) {
        XmlElement elem = parser->nextElement();
        if (elem.getName() == "language" && !elem.isEnd()) {
            std::string idStr = elem.getAttribute("id");
            std::string processorName = elem.getAttribute("processor");
            std::string endianStr = elem.getAttribute("endian");
            std::string instructionEndianStr = elem.getAttribute("instructionEndian");
            if (instructionEndianStr.empty()) instructionEndianStr = endianStr;
            
            Endian endian = (endianStr == "little" || endianStr == "LITTLE") ? Endian::LITTLE : Endian::BIG;
            Endian instrEndian = (instructionEndianStr == "little" || instructionEndianStr == "LITTLE") ? Endian::LITTLE : Endian::BIG;
            
            int size = 32;
            try { size = std::stoi(elem.getAttribute("size")); } catch (...) {}
            
            std::string variant = elem.getAttribute("variant");
            std::string versionStr = elem.getAttribute("version");
            int version = 1;
            int minorVersion = 0;
            size_t dotPos = versionStr.find('.');
            try {
                if (dotPos != std::string::npos) {
                    version = std::stoi(versionStr.substr(0, dotPos));
                    minorVersion = std::stoi(versionStr.substr(dotPos + 1));
                } else {
                    version = std::stoi(versionStr);
                }
            } catch (...) {}
            
            bool deprecated = (elem.getAttribute("deprecated") == "true");
            std::string slafile = elem.getAttribute("slafile");
            std::string manualindexfile = elem.getAttribute("manualindexfile");
            std::string pspec = elem.getAttribute("processorspec");
            
            std::string descriptionText;
            std::vector<CompilerSpecDescription> compilerSpecs;
            
            // Look ahead for description and compiler
            while (parser->hasNext()) {
                XmlElement subElem = parser->peek();
                if (subElem.getName() == "language" && subElem.isEnd()) {
                    parser->nextElement();
                    break;
                }
                
                subElem = parser->nextElement();
                if (subElem.getName() == "description" && !subElem.isEnd()) {
                    descriptionText = subElem.getText();
                } else if (subElem.getName() == "compiler" && !subElem.isEnd()) {
                    CompilerSpecID compId(subElem.getAttribute("id"));
                    std::string compName = subElem.getAttribute("name");
                    std::string compSpec = subElem.getAttribute("spec");
                    compilerSpecs.push_back(SleighCompilerSpecDescription(compId, compName, compSpec));
                }
            }
            
            LanguageID id(idStr);
            auto desc = new SleighLanguageDescription(id, descriptionText, Processor(processorName),
                                                      endian, instrEndian, size, variant, version, minorVersion);
            desc->setDeprecated(deprecated);
            desc->setDefsFile(parentDirectory + "/" + ldefs);
            if (!pspec.empty()) desc->setSpecFile(parentDirectory + "/" + pspec);
            
            if (!slafile.empty()) {
                // Strip extension for SleighLanguageFile
                size_t extPos = slafile.find_last_of('.');
                std::string baseSla = (extPos != std::string::npos) ? slafile.substr(0, extPos) : slafile;
                desc->setLanguageFile(SleighLanguageFile(parentDirectory, baseSla));
            }
            if (!manualindexfile.empty()) desc->setManualIndexFile(parentDirectory + "/" + manualindexfile);
            
            if (languages_.find(idStr) != languages_.end()) {
                std::cerr << "Duplicate Sleigh Language ID: " << idStr << "\n";
                delete desc;
            } else {
                languages_[idStr] = std::make_unique<LanguageRec>(desc);
            }
        }
    }
}

} // namespace ghidra
