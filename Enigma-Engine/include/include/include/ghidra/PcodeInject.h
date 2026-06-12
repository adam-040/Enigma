#pragma once

#include <ghidra/Address.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/VarnodeAST.h>
#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace ghidra {

typedef int32_t int4;

class Funcdata;

class PcodeInject {
public:
    enum InjectType {
        CALLFIXUP_TYPE,
        CALLOTHERFIXUP_TYPE,
        UNIMPLEMENTED_TYPE,
        NORETURN_TYPE,
        RELATIVECALL_TYPE,
        INDIRECTCALL_TYPE,
        USERDEFINED_TYPE
    };

private:
    InjectType type;
    std::string name;
    int4 callotherId;
    bool hasPcode;

public:
    PcodeInject(InjectType t, const std::string& n, int4 id = -1);
    virtual ~PcodeInject() = default;

    InjectType getType() const { return type; }
    const std::string& getName() const { return name; }
    int4 getCallotherId() const { return callotherId; }
    bool hasPcodeBody() const { return hasPcode; }

    virtual void inject(Funcdata& fd, const Address& addr, std::vector<PcodeOpAST*>& ops) = 0;
};

class PcodeInjectLibrary {
private:
    std::map<std::string, PcodeInject*> injectMap;
    std::map<int4, PcodeInject*> callotherMap;
    std::vector<PcodeInject*> allInjects;

public:
    PcodeInjectLibrary() = default;
    ~PcodeInjectLibrary();

    void registerInject(PcodeInject* inject);
    PcodeInject* getInject(const std::string& name) const;
    PcodeInject* getCallotherInject(int4 id) const;
    int4 getNumInjects() const { return static_cast<int4>(allInjects.size()); }

    void clear();
};

} // namespace ghidra
