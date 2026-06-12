/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ParamListStandard.h>
#include <ghidra/Language.h>
#include <ghidra/DefaultDataType.h>
#include <ghidra/TypeDef.h>
#include <ghidra/VariableStorage.h>
#include <algorithm>

namespace ghidra {

ParamListStandard::~ParamListStandard() {
    for (auto* rule : modelRules_) {
        delete rule;
    }
}

ParamList* ParamListStandard::clone() const {
    auto* c = new ParamListStandard(*this);
    // modelRules_ pointers are shallow-copied; aliases share rule instances
    return c;
}

void ParamListStandard::addEntry(const ParamEntry& pe) {
    entry_.push_back(pe);
    const auto& groups = pe.getAllGroups();
    if (!groups.empty()) {
        int maxgroup = groups.back() + 1;
        if (maxgroup > numgroup_) {
            numgroup_ = maxgroup;
        }
    }
}

void ParamListStandard::addModelRule(ModelRule* rule) {
    modelRules_.push_back(rule);
}

int ParamListStandard::findEntry(const Address& loc, int size) const {
    for (int i = 0; i < static_cast<int>(entry_.size()); ++i) {
        if (entry_[i].getMinSize() > size) {
            continue;
        }
        if (entry_[i].justifiedContain(loc, size) == 0) {
            return i;
        }
    }
    return -1;
}

bool ParamListStandard::isBigEndian() const {
    if (entry_.empty()) return false;
    return entry_[0].isBigEndian();
}

int ParamListStandard::assignAddressFallback(StorageClass resource, DataType* tp, bool matchExact,
                                              int* status, ParameterPieces& param) {
    for (auto& element : entry_) {
        int grp = element.getGroup();
        if (status[grp] < 0) {
            continue;
        }
        if (resource != element.getType()) {
            if (matchExact || element.getType() != StorageClass::GENERAL) {
                continue;
            }
        }

        status[grp] = element.getAddrBySlot(status[grp], tp->getAlignedLength(),
                                             tp->getAlignment(), param);
        if (param.address == Address::NO_ADDRESS) {
            continue;
        }
        if (element.isExclusion()) {
            const auto& groups = element.getAllGroups();
            for (int group : groups) {
                status[group] = -1;
            }
        }
        param.type = tp;
        return AssignAction::SUCCESS;
    }
    param.address = Address::NO_ADDRESS;
    return AssignAction::FAIL;
}

int ParamListStandard::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                                      DataTypeManager* dtManager, int* status,
                                      ParameterPieces& res) {
    if (dt->isZeroLength()) {
        return AssignAction::NO_ASSIGNMENT;
    }
    if (dt == &DefaultDataType::dataType()) {
        return AssignAction::NO_ASSIGNMENT;
    }
    auto* td = dynamic_cast<TypeDef*>(dt);
    if (td && td->getBaseDataType() == &DefaultDataType::dataType()) {
        return AssignAction::NO_ASSIGNMENT;
    }
    for (auto* modelRule : modelRules_) {
        int responseCode = modelRule->assignAddress(dt, proto, pos, dtManager, status, res);
        if (responseCode != AssignAction::FAIL) {
            return responseCode;
        }
    }
    StorageClass store = ParamEntry::getBasicTypeClass(dt);
    return assignAddressFallback(store, dt, false, status, res);
}

void ParamListStandard::assignMap(const PrototypePieces& proto, DataTypeManager* dtManage,
                                   std::vector<ParameterPieces>& res, bool addAutoParams) {
    std::vector<int> status(numgroup_, 0);

    if (addAutoParams && res.size() == 2) {
        ParameterPieces& last = res[res.size() - 1];
        if (last.hiddenReturnPtr) {
            assignAddressFallback(StorageClass::HIDDENRET, last.type, false, status.data(), last);
        } else {
            assignAddress(last.type, proto, 0, dtManage, status.data(), last);
        }
        last.hiddenReturnPtr = true;
    }
    for (int i = 0; i < static_cast<int>(proto.intypes.size()); ++i) {
        ParameterPieces store;
        int resCode = assignAddress(proto.intypes[i], proto, i, dtManage, status.data(), store);
        if (resCode == AssignAction::FAIL || resCode == AssignAction::NO_ASSIGNMENT) {
            res.push_back(store);
            ++i;
            while (i < static_cast<int>(proto.intypes.size())) {
                ParameterPieces unassigned;
                res.push_back(unassigned);
                ++i;
            }
            return;
        }
        res.push_back(store);
    }
}

void ParamListStandard::encode(Encoder* encoder, bool isInput) {
    // Stub
}

void ParamListStandard::restoreXml(class XmlPullParser* parser, CompilerSpec* cspec) {
    // Stub
}

std::vector<VariableStorage> ParamListStandard::getPotentialRegisterStorage(Program* prog) {
    std::vector<VariableStorage> result;
    for (auto& pe : entry_) {
        if (!pe.isExclusion()) {
            continue;
        }
        if (pe.getSpace() && pe.getSpace()->isRegisterSpace()) {
            try {
                Address addr(pe.getSpace(), pe.getAddressBase());
                VariableStorage var(prog, addr, pe.getSize());
                result.push_back(var);
            } catch (...) {
                // Skip this particular storage location
            }
        }
    }
    return result;
}

int ParamListStandard::getStackParameterAlignment() const {
    for (const auto& pentry : entry_) {
        if (pentry.getSpace() && pentry.getSpace()->isStackSpace()) {
            return pentry.getAlign();
        }
    }
    return -1;
}

int64_t ParamListStandard::getStackParameterOffset() const {
    for (const auto& pentry : entry_) {
        if (pentry.isExclusion()) continue;
        if (!pentry.getSpace() || !pentry.getSpace()->isStackSpace()) continue;
        int64_t res = pentry.getAddressBase();
        if (pentry.isReverseStack()) {
            res += pentry.getSize();
        }
        res = pentry.getSpace()->truncateOffset(res);
        return res;
    }
    return -1;
}

bool ParamListStandard::possibleParamWithSlot(const Address& loc, int size, WithSlotRec& rec) {
    if (loc == Address::NO_ADDRESS) return false;
    int num = findEntry(loc, size);
    if (num == -1) return false;
    ParamEntry& curentry = entry_[num];
    rec.slot = curentry.getSlot(loc, 0);
    if (curentry.isExclusion()) {
        rec.slotsize = static_cast<int>(curentry.getAllGroups().size());
    } else {
        rec.slotsize = ((size - 1) / curentry.getAlign()) + 1;
    }
    return true;
}

Language* ParamListStandard::getLanguage() {
    return language_;
}

AddressSpace* ParamListStandard::getSpacebase() {
    return spacebase_;
}

bool ParamListStandard::isThisBeforeRetPointer() const {
    return thisbeforeret_;
}

bool ParamListStandard::isEquivalent(const ParamList* obj) const {
    const auto* other = dynamic_cast<const ParamListStandard*>(obj);
    if (!other) return false;
    if (entry_.size() != other->entry_.size()) return false;
    for (size_t i = 0; i < entry_.size(); ++i) {
        if (!entry_[i].isEquivalent(other->entry_[i])) return false;
    }
    if (modelRules_.size() != other->modelRules_.size()) return false;
    for (size_t i = 0; i < modelRules_.size(); ++i) {
        if (!modelRules_[i]->isEquivalent(*other->modelRules_[i])) return false;
    }
    if (numgroup_ != other->numgroup_) return false;
    if (spacebase_ != other->spacebase_) return false;
    if (thisbeforeret_ != other->thisbeforeret_) return false;
    if (autoKilledByCall_ != other->autoKilledByCall_) return false;
    return true;
}

std::vector<ParamEntry> ParamListStandard::extractTiles(StorageClass resType) const {
    std::vector<ParamEntry> result;
    for (const auto& pentry : entry_) {
        if (!pentry.isExclusion() || pentry.getAllGroups().size() != 1 ||
            pentry.getType() != resType) {
            continue;
        }
        result.push_back(pentry);
    }
    return result;
}

ParamEntry* ParamListStandard::extractStack() {
    for (int i = static_cast<int>(entry_.size()) - 1; i >= 0; --i) {
        ParamEntry& pentry = entry_[i];
        if (!pentry.isExclusion() && pentry.getSpace() && pentry.getSpace()->isStackSpace()) {
            return &pentry;
        }
    }
    return nullptr;
}

} // namespace ghidra
