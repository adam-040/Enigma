#pragma once

#include <ghidra/Options.h>
#include <string>
#include <functional>
#include <memory>
#include <vector>

namespace ghidra {

class AnalysisOptionsUpdater {
public:
    class ReplaceableOption {
    public:
        ReplaceableOption(const std::string& newName, const std::string& oldName,
                          std::function<void(Options&)> replacer)
            : newName_(newName), oldName_(oldName), replacer_(std::move(replacer)) {}

        const std::string& getNewName() const { return newName_; }
        const std::string& getOldName() const { return oldName_; }

        void replace(Options& options) const {
            if (!options.hasOption(oldName_)) return;
            replacer_(options);
        }

    private:
        std::string newName_;
        std::string oldName_;
        std::function<void(Options&)> replacer_;
    };

    void registerReplacement(const std::string& newOptionName, const std::string& oldOptionName) {
        registerReplacement(newOptionName, oldOptionName,
                            [oldOptionName, newOptionName](Options& opts) {
                                Options::OptionType type = opts.getOptionType(oldOptionName);
                                switch (type) {
                                    case Options::TYPE_BOOL:
                                        opts.setBool(newOptionName, opts.getBool(oldOptionName));
                                        break;
                                    case Options::TYPE_INT:
                                        opts.setInt(newOptionName, opts.getInt(oldOptionName));
                                        break;
                                    case Options::TYPE_INT8:
                                        opts.setInt8(newOptionName, opts.getInt8(oldOptionName));
                                        break;
                                    case Options::TYPE_STRING:
                                        opts.setString(newOptionName, opts.getString(oldOptionName));
                                        break;
                                    default: break;
                                }
                            });
    }

    void registerReplacement(const std::string& newOptionName, const std::string& oldOptionName,
                             std::function<void(Options&)> replacer) {
        replacements_.push_back(
            std::make_unique<ReplaceableOption>(newOptionName, oldOptionName, std::move(replacer)));
    }

    const std::vector<std::unique_ptr<ReplaceableOption>>& getReplaceableOptions() const {
        return replacements_;
    }

private:
    std::vector<std::unique_ptr<ReplaceableOption>> replacements_;
};

} // namespace ghidra
