#pragma once

#include <ghidra/LanguageProvider.h>
#include <ghidra/SleighLanguageDescription.h>
#include <ghidra/LanguageID.h>
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace ghidra {

class SleighLanguage;
class XmlPullParser;

class SleighLanguageProvider : public LanguageProvider {
public:
    static SleighLanguageProvider& getSleighLanguageProvider();

    Language* getLanguage(const LanguageID& languageId, TaskMonitor* monitor) override;
    std::vector<LanguageDescription*> getLanguageDescriptions() override;
    bool hadLoadFailure() override;
    bool isLanguageLoaded(const LanguageID& languageId) override;

private:
    SleighLanguageProvider();
    ~SleighLanguageProvider() override = default;

    struct LanguageRec {
        SleighLanguageDescription* langDesc = nullptr;
        SleighLanguage* lang = nullptr;
        bool failed = false;

        LanguageRec() = default;
        LanguageRec(SleighLanguageDescription* desc) : langDesc(desc) {}
        ~LanguageRec();

        void loadLanguage(TaskMonitor* monitor);
        void unloadLanguage();
    };

    void createLanguages();
    void createLanguages(const std::string& file);
    void createLanguageDescriptions(const std::string& specFile);
    void read(XmlPullParser* parser, const std::string& parentDirectory, const std::string& ldefs);

    std::map<std::string, std::unique_ptr<LanguageRec>> languages_;
    int failureCount_ = 0;
};

} // namespace ghidra
