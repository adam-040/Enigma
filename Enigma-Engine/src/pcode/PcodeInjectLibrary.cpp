#include <ghidra/PcodeInjectLibrary.h>
#include <ghidra/SleighLanguage.h>
#include <ghidra/InjectPayloadSleigh.h>
#include <ghidra/InjectContext.h>
#include <ghidra/ConstantPool.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/PcodeParser.h>
#include <ghidra/Location.h>
#include <algorithm>

namespace ghidra {

PcodeInjectLibrary::PcodeInjectLibrary(SleighLanguage* lang)
    : language_(lang) {
    uniqueBase_ = UniqueLayout::getOffset(UniqueLayout::INJECT, lang);
}

PcodeInjectLibrary::PcodeInjectLibrary(const PcodeInjectLibrary& other)
    : language_(other.language_),
      uniqueBase_(other.uniqueBase_),
      callFixupMap_(other.callFixupMap_),
      callOtherFixupMap_(other.callOtherFixupMap_),
      callOtherOverride_(other.callOtherOverride_),
      callMechFixupMap_(other.callMechFixupMap_),
      exePcodeMap_(other.exePcodeMap_),
      programPayload_(other.programPayload_) {}

bool PcodeInjectLibrary::hasProgramPayload(const std::string& nm, int type) const {
    for (auto* payload : programPayload_) {
        if (payload->getType() == type && payload->getName() == nm) {
            return true;
        }
    }
    return false;
}

bool PcodeInjectLibrary::isOverride(const std::string& nm, int type) const {
    if (callOtherOverride_.empty() || type != InjectPayload::CALLOTHERFIXUP_TYPE) {
        return false;
    }
    for (auto* payload : callOtherOverride_) {
        if (payload->getName() == nm) return true;
    }
    return false;
}

InjectPayload* PcodeInjectLibrary::getPayload(int type, const std::string& name) const {
    PayloadMap::const_iterator it;
    switch (type) {
        case InjectPayload::CALLFIXUP_TYPE:
            it = callFixupMap_.find(name);
            return (it != callFixupMap_.end()) ? it->second : nullptr;
        case InjectPayload::CALLOTHERFIXUP_TYPE:
            it = callOtherFixupMap_.find(name);
            return (it != callOtherFixupMap_.end()) ? it->second : nullptr;
        case InjectPayload::CALLMECHANISM_TYPE:
            it = callMechFixupMap_.find(name);
            return (it != callMechFixupMap_.end()) ? it->second : nullptr;
        case InjectPayload::EXECUTABLEPCODE_TYPE:
            it = exePcodeMap_.find(name);
            return (it != exePcodeMap_.end()) ? it->second : nullptr;
        default:
            return nullptr;
    }
}

void PcodeInjectLibrary::parseInject(InjectPayload* payload) {
    std::string sourceName = payload->getSource();
    if (sourceName.empty()) sourceName = "unknown";
    auto* payloadSleigh = dynamic_cast<InjectPayloadSleigh*>(payload);
    if (!payloadSleigh) return;
    std::string pcodeText = payloadSleigh->releaseParseString();
    if (pcodeText.empty()) return;
    PcodeParser parser(language_, uniqueBase_);
    auto input = payload->getInput();
    for (auto& param : input) {
        parser.addOperand(Location(sourceName, 1), param.getName(), param.getIndex());
    }
    auto output = payload->getOutput();
    for (auto& param : output) {
        parser.addOperand(Location(sourceName, 1), param.getName(), param.getIndex());
    }
    ConstructTpl* constructTpl = parser.compilePcode(pcodeText, sourceName, 1);
    uniqueBase_ = parser.getNextTempOffset();
    payloadSleigh->setTemplate(constructTpl);
}

std::vector<std::string> PcodeInjectLibrary::getCallFixupNames() const {
    std::vector<std::string> names;
    for (auto& kv : callFixupMap_) {
        names.push_back(kv.first);
    }
    return names;
}

std::vector<std::string> PcodeInjectLibrary::getCallotherFixupNames() const {
    std::vector<std::string> names;
    for (auto& kv : callOtherFixupMap_) {
        if (kv.second) names.push_back(kv.first);
    }
    return names;
}

InjectContext* PcodeInjectLibrary::buildInjectContext() {
    auto* res = new InjectContext();
    res->language = language_;
    return res;
}

bool PcodeInjectLibrary::hasUserDefinedOp(const std::string& name) {
    if (callOtherFixupMap_.empty()) {
        int max = language_->getNumberOfUserDefinedOpNames();
        for (int i = 0; i < max; ++i) {
            std::string opname = language_->getUserDefinedOpName(i);
            callOtherFixupMap_[opname] = nullptr;
        }
    }
    return callOtherFixupMap_.find(name) != callOtherFixupMap_.end();
}

void PcodeInjectLibrary::registerInject(InjectPayload* payload) {
    parseInject(payload);
    switch (payload->getType()) {
        case InjectPayload::CALLFIXUP_TYPE:
            if (callFixupMap_.find(payload->getName()) != callFixupMap_.end()) {
                throw SleighException("CallFixup registered multiple times: " + payload->getName());
            }
            callFixupMap_[payload->getName()] = payload;
            break;
        case InjectPayload::CALLOTHERFIXUP_TYPE:
            if (!hasUserDefinedOp(payload->getName())) {
                throw SleighException("Unknown callother name: " + payload->getName());
            }
            if (callOtherFixupMap_[payload->getName()]) {
                throw SleighException("Duplicate <callotherfixup> tag: " + payload->getName());
            }
            callOtherFixupMap_[payload->getName()] = payload;
            break;
        case InjectPayload::CALLMECHANISM_TYPE:
            if (callMechFixupMap_.find(payload->getName()) != callMechFixupMap_.end()) {
                throw SleighException("CallMechanism registered multiple times: " + payload->getName());
            }
            callMechFixupMap_[payload->getName()] = payload;
            break;
        case InjectPayload::EXECUTABLEPCODE_TYPE:
            if (exePcodeMap_.find(payload->getName()) != exePcodeMap_.end()) {
                throw SleighException("Executable p-code registered multiple times: " + payload->getName());
            }
            exePcodeMap_[payload->getName()] = payload;
            break;
        default:
            throw SleighException("Unknown p-code inject type");
    }
}

bool PcodeInjectLibrary::removeMechanismPayload(const std::string& nm) {
    auto it = callMechFixupMap_.find(nm);
    if (it != callMechFixupMap_.end()) {
        callMechFixupMap_.erase(it);
        return true;
    }
    return false;
}

void PcodeInjectLibrary::uninstallProgramPayloads() {
    if (!programPayload_.empty()) {
        for (auto* payload : programPayload_) {
            if (payload->getType() == InjectPayload::CALLFIXUP_TYPE) {
                callFixupMap_.erase(payload->name);
            } else if (payload->getType() == InjectPayload::CALLOTHERFIXUP_TYPE) {
                callOtherFixupMap_[payload->name] = nullptr;
            }
        }
        programPayload_.clear();
        if (!callOtherOverride_.empty()) {
            for (auto* payload : callOtherOverride_) {
                callOtherFixupMap_[payload->getName()] = payload;
            }
            callOtherOverride_.clear();
        }
    }
}

void PcodeInjectLibrary::setupOverrides(std::vector<InjectPayloadSleigh*>& userPayloads) {
    int count = 0;
    for (auto* payload : userPayloads) {
        if (payload->getType() == InjectPayload::CALLOTHERFIXUP_TYPE) {
            if (callOtherFixupMap_.find(payload->name) != callOtherFixupMap_.end()) {
                ++count;
            }
        }
    }
    if (count == 0) return;
    callOtherOverride_.resize(count);
    count = 0;
    for (auto* payload : userPayloads) {
        if (payload->getType() == InjectPayload::CALLOTHERFIXUP_TYPE) {
            auto it = callOtherFixupMap_.find(payload->name);
            if (it != callOtherFixupMap_.end()) {
                callOtherFixupMap_[payload->name] = nullptr;
                callOtherOverride_[count] = it->second;
                ++count;
            }
        }
    }
}

void PcodeInjectLibrary::registerProgramInject(std::vector<InjectPayloadSleigh*>& userPayloads) {
    uninstallProgramPayloads();
    if (userPayloads.empty()) return;
    setupOverrides(userPayloads);
    programPayload_.resize(userPayloads.size());
    int count = 0;
    for (auto* payload : userPayloads) {
        try {
            registerInject(payload);
            programPayload_[count] = payload;
            ++count;
        } catch (SleighException& ex) {
            // payload not registered
        }
    }
    if (count != static_cast<int>(programPayload_.size())) {
        programPayload_.resize(count);
    }
}

InjectPayload* PcodeInjectLibrary::allocateInject(const std::string& sourceName,
                                                    const std::string& name, int tp) {
    return new InjectPayloadSleigh(name, tp, sourceName);
}

void PcodeInjectLibrary::encodeCompilerSpec(Encoder& encoder) {
    for (auto& kv : callFixupMap_) {
        auto* payloadSleigh = dynamic_cast<InjectPayloadSleigh*>(kv.second);
        if (payloadSleigh) payloadSleigh->encode(encoder);
    }
    for (auto& kv : callOtherFixupMap_) {
        auto* payloadSleigh = dynamic_cast<InjectPayloadSleigh*>(kv.second);
        if (payloadSleigh) payloadSleigh->encode(encoder);
    }
    for (auto& kv : exePcodeMap_) {
        auto* payloadSleigh = dynamic_cast<InjectPayloadSleigh*>(kv.second);
        if (payloadSleigh && payloadSleigh->getSource().find("cspec") == 0) {
            payloadSleigh->encode(encoder);
        }
    }
}

InjectPayload* PcodeInjectLibrary::restoreXmlInject(const std::string& source,
                                                     const std::string& name,
                                                     int tp, XmlPullParser* parser) {
    auto* payload = allocateInject(source, name, tp);
    payload->restoreXml(parser, language_);
    registerInject(payload);
    return payload;
}

ConstantPool* PcodeInjectLibrary::getConstantPool(Program* program) {
    return nullptr;
}

bool PcodeInjectLibrary::isEquivalent(const PcodeInjectLibrary* obj) const {
    if (callFixupMap_.size() != obj->callFixupMap_.size()) return false;
    for (auto& entry : callFixupMap_) {
        auto it = obj->callFixupMap_.find(entry.first);
        if (it == obj->callFixupMap_.end()) return false;
        if (!entry.second->isEquivalent(it->second)) return false;
    }
    if (callMechFixupMap_.size() != obj->callMechFixupMap_.size()) return false;
    for (auto& entry : callMechFixupMap_) {
        auto it = obj->callMechFixupMap_.find(entry.first);
        if (it == obj->callMechFixupMap_.end()) return false;
        if (!entry.second->isEquivalent(it->second)) return false;
    }
    if (callOtherFixupMap_.size() != obj->callOtherFixupMap_.size()) return false;
    for (auto& entry : callOtherFixupMap_) {
        auto it = obj->callOtherFixupMap_.find(entry.first);
        if (it == obj->callOtherFixupMap_.end()) return false;
        if (entry.second && it->second) {
            if (!entry.second->isEquivalent(it->second)) return false;
        } else if (entry.second || it->second) {
            return false;
        }
    }
    if (!callOtherOverride_.empty() && !obj->callOtherOverride_.empty()) {
        if (callOtherOverride_.size() != obj->callOtherOverride_.size()) return false;
        for (size_t i = 0; i < callOtherOverride_.size(); ++i) {
            if (!callOtherOverride_[i]->isEquivalent(obj->callOtherOverride_[i])) return false;
        }
    } else if (callOtherOverride_.empty() != obj->callOtherOverride_.empty()) {
        return false;
    }
    if (exePcodeMap_.size() != obj->exePcodeMap_.size()) return false;
    for (auto& entry : exePcodeMap_) {
        auto it = obj->exePcodeMap_.find(entry.first);
        if (it == obj->exePcodeMap_.end()) return false;
        if (!entry.second->isEquivalent(it->second)) return false;
    }
    if (!programPayload_.empty() && !obj->programPayload_.empty()) {
        if (programPayload_.size() != obj->programPayload_.size()) return false;
        for (size_t i = 0; i < programPayload_.size(); ++i) {
            if (!programPayload_[i]->isEquivalent(obj->programPayload_[i])) return false;
        }
    } else if (programPayload_.empty() != obj->programPayload_.empty()) {
        return false;
    }
    return true;
}

} // namespace ghidra
