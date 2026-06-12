#include <ghidra/Architecture.h>
#include <ghidra/Sleigh.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Types.h>
#include <sstream>

namespace ghidra {

Architecture::Architecture(const std::string& nm, ArchitectureType t)
    : name(nm), type(t), initialized(false), m_bigEndian(false), pointerSize(4),
      loader(nullptr), translate(nullptr), globalScope(nullptr) {
}

Architecture::~Architecture() {
    delete globalScope;
}

Address Architecture::getDefaultCodeAddress(uintb offset) const {
    AddressSpace* codeSpace = spaceManager.getCodeSpace();
    if (!codeSpace) codeSpace = spaceManager.getDefaultSpace();
    if (!codeSpace) return Address::NO_ADDRESS;
    return Address(codeSpace, static_cast<int64_t>(offset));
}

Address Architecture::getConstantAddress(uintb val, int4 size) const {
    AddressSpace* constSpace = spaceManager.getConstantSpace();
    if (!constSpace) return Address::NO_ADDRESS;
    (void)size;
    return Address(constSpace, static_cast<int64_t>(val));
}

Address Architecture::getUniqueAddress(uintb offset, int4 size) const {
    AddressSpace* uniqueSpace = spaceManager.getUniqueSpace();
    if (!uniqueSpace) return Address::NO_ADDRESS;
    (void)size;
    return Address(uniqueSpace, static_cast<int64_t>(offset));
}

void Architecture::saveXml(std::string& output) const {
    output += "<architecture name=\"" + name + "\"";
    output += " type=\"" + std::to_string(static_cast<int>(type)) + "\"";
    output += " bigendian=\"" + std::string(m_bigEndian ? "true" : "false") + "\"";
    output += " pointersize=\"" + std::to_string(pointerSize) + "\">\n";

    output += "  <spaces>\n";
    for (int4 i = 0; i < spaceManager.getNumSpaces(); i++) {
        AddressSpace* space = spaceManager.getSpace(i);
        if (space) {
            output += "    <space name=\"" + space->getName() + "\"";
            output += " index=\"" + std::to_string(space->getSpaceID()) + "\"";
            output += " type=\"" + std::to_string(space->getType()) + "\"";
            output += " size=\"" + std::to_string(space->getPointerSize()) + "\"/>\n";
        }
    }
    output += "  </spaces>\n";

    if (globalScope) {
        output += "  <globalscope>\n";
        globalScope->saveXml(output);
        output += "  </globalscope>\n";
    }

    output += "</architecture>\n";
}

void Architecture::restoreXml(const std::string& input) {
    (void)input;
}

ArchitectureSleigh::ArchitectureSleigh(const std::string& nm, LoadImage* ld, const std::string& slaPath)
    : Architecture(nm, ARCH_SLEIGH), slaFile(slaPath), sleighEngine(nullptr) {
    loader = ld;
}

ArchitectureSleigh::~ArchitectureSleigh() {
    delete sleighEngine;
}

bool ArchitectureSleigh::initialize() {
    spaceManager.setBigEndian(m_bigEndian);
    spaceManager.setDefaultPointerSize(pointerSize);

    AddressSpace* ram = spaceManager.addSpace("ram", AddressSpace::TYPE_RAM, pointerSize);
    spaceManager.addSpace("rom", AddressSpace::TYPE_CODE, pointerSize);
    spaceManager.addSpace("register", AddressSpace::TYPE_REGISTER, pointerSize);
    spaceManager.addSpace("unique", AddressSpace::TYPE_UNIQUE, 8);
    spaceManager.addSpace("const", AddressSpace::TYPE_CONSTANT, 8);
    spaceManager.addSpace("spacebase", AddressSpace::TYPE_STACK, pointerSize);

    spaceManager.setDefaultSpace(ram);
    spaceManager.setCodeSpace(ram);
    spaceManager.setDataSpace(ram);

    globalScope = new ScopeInternal("global", 0, true, &typeFactory);

    translate = new Sleigh(loader, slaFile);
    sleighEngine = static_cast<Sleigh*>(translate);

    if (!sleighEngine->initialize()) {
        addWarning("SLEIGH engine initialization failed, using stub mode");
    }

    initialized = true;
    return true;
}

ArchitectureRaw::ArchitectureRaw(const std::string& nm, LoadImage* ld, int4 ptrSize, bool endian)
    : Architecture(nm, ARCH_RAW) {
    loader = ld;
    pointerSize = ptrSize;
    m_bigEndian = endian;
}

ArchitectureRaw::~ArchitectureRaw() {
    delete translate;
}

bool ArchitectureRaw::initialize() {
    spaceManager.setBigEndian(m_bigEndian);
    spaceManager.setDefaultPointerSize(pointerSize);

    AddressSpace* ram = spaceManager.addSpace("ram", AddressSpace::TYPE_RAM, pointerSize);
    spaceManager.addSpace("register", AddressSpace::TYPE_REGISTER, pointerSize);
    spaceManager.addSpace("unique", AddressSpace::TYPE_UNIQUE, 8);
    spaceManager.addSpace("const", AddressSpace::TYPE_CONSTANT, 8);

    spaceManager.setDefaultSpace(ram);
    spaceManager.setCodeSpace(ram);
    spaceManager.setDataSpace(ram);

    globalScope = new ScopeInternal("global", 0, true, &typeFactory);

    translate = nullptr;

    initialized = true;
    return true;
}

} // namespace ghidra
