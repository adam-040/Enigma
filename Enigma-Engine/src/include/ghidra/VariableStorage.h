#pragma once

#include <ghidra/Address.h>
#include <ghidra/Register.h>
#include <ghidra/Varnode.h>
#include <ghidra/AutoParameterType.h>
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class Program;
class AddressSetView;

enum class StorageType {
    MAPPED,
    UNASSIGNED,
    BAD,
    VOID
};

class VariableStorage {
public:
    static const VariableStorage BAD_STORAGE;
    static const VariableStorage UNASSIGNED_STORAGE;
    static const VariableStorage VOID_STORAGE;

    // Constructors
    VariableStorage(); // Constructs UNASSIGNED_STORAGE
    VariableStorage(Program* program, const std::vector<Varnode>& varnodes);
    VariableStorage(Program* program, const std::vector<Register*>& registers);
    VariableStorage(Program* program, int stackOffset, int size);
    VariableStorage(Program* program, Address address, int size);

    virtual ~VariableStorage() = default;

    Program* getProgram() const { return program_; }
    int size() const { return size_; }

    int getVarnodeCount() const;
    std::vector<Varnode> getVarnodes() const;
    Varnode getFirstVarnode() const;
    Varnode getLastVarnode() const;

    bool isStackStorage() const;
    bool hasStackStorage() const;
    bool isRegisterStorage() const;
    Register* getRegister() const;
    std::vector<Register*> getRegisters() const;
    long getRegisterOffset(Register* reg) const;
    int getStackOffset() const;
    Address getMinAddress() const;
    bool isMemoryStorage() const;
    bool isConstantStorage() const;
    bool isHashStorage() const;
    bool isUniqueStorage() const;
    bool isCompoundStorage() const;

    virtual bool isBadStorage() const { return type_ == StorageType::BAD; }
    virtual bool isUnassignedStorage() const { return type_ == StorageType::UNASSIGNED; }
    virtual bool isValid() const { return !isUnassignedStorage() && !isBadStorage(); }
    virtual bool isVoidStorage() const { return type_ == StorageType::VOID; }

    virtual bool isAutoStorage() const;
    virtual AutoParameterType getAutoParameterType() const;
    virtual bool isForcedIndirect() const;

    bool contains(Address address) const;
    bool intersects(const VariableStorage& other) const;
    bool intersects(const AddressSetView& set) const;
    bool intersects(Register* reg) const;

    int compareTo(const VariableStorage& other) const;
    std::string getSerializationString() const;
    virtual std::string toString() const;

    bool operator==(const VariableStorage& other) const;
    bool operator!=(const VariableStorage& other) const { return !(*this == other); }
    bool operator<(const VariableStorage& other) const;

    static VariableStorage deserialize(Program* program, const std::string& serialization);
    static std::string getSerializationString(const std::vector<Varnode>& varnodes);
    static std::vector<Varnode> getVarnodes(Program* program, const std::string& serialization);

protected:
    // Special internal constructor
    VariableStorage(StorageType type);

    StorageType type_;
    std::vector<Varnode> varnodes_;
    Program* program_ = nullptr;
    std::vector<Register*> registers_;
    int size_ = 0;
    mutable std::string serialization_;

private:
    void checkVarnodes();
};

} // namespace ghidra
