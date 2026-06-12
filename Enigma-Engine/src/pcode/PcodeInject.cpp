#include <ghidra/PcodeInject.h>

namespace ghidra {

PcodeInject::PcodeInject(InjectType t, const std::string& n, int4 id)
    : type(t), name(n), callotherId(id), hasPcode(false) {
}

PcodeInjectLibrary::~PcodeInjectLibrary() {
    clear();
}

void PcodeInjectLibrary::registerInject(PcodeInject* inject) {
    if (!inject) return;
    injectMap[inject->getName()] = inject;
    if (inject->getCallotherId() >= 0) {
        callotherMap[inject->getCallotherId()] = inject;
    }
    allInjects.push_back(inject);
}

PcodeInject* PcodeInjectLibrary::getInject(const std::string& name) const {
    auto it = injectMap.find(name);
    return (it != injectMap.end()) ? it->second : nullptr;
}

PcodeInject* PcodeInjectLibrary::getCallotherInject(int4 id) const {
    auto it = callotherMap.find(id);
    return (it != callotherMap.end()) ? it->second : nullptr;
}

void PcodeInjectLibrary::clear() {
    for (auto* inject : allInjects) {
        delete inject;
    }
    injectMap.clear();
    callotherMap.clear();
    allInjects.clear();
}

} // namespace ghidra
