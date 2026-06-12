#pragma once

#include <string>

namespace ghidra {

class SleighLanguageFile {
public:
    SleighLanguageFile(const std::string& baseDir, const std::string& filename)
        : baseDir_(baseDir), filename_(filename) {}

    const std::string& getBaseDir() const { return baseDir_; }
    const std::string& getFilename() const { return filename_; }

    std::string getSlaFile() const {
        return baseDir_ + "/" + filename_ + ".sla";
    }

    std::string getSlaSpecFile() const {
        return baseDir_ + "/" + filename_ + ".slaspec";
    }

private:
    std::string baseDir_;
    std::string filename_;
};

} // namespace ghidra
