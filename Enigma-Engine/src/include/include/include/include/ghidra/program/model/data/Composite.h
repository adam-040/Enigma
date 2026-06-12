/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file Composite.h
/// \brief Interface for composite data types (structures, unions)
#pragma once

#include <memory>
#include <string>
#include <vector>

namespace ghidra {

class DataType;
class DataTypeComponent;
class CompositeInternal;

class Composite {
public:
    virtual ~Composite() = default;

    virtual std::shared_ptr<DataTypeComponent> add(const std::shared_ptr<DataType>& dataType, int length, const std::string& fieldName, const std::string& comment) = 0;
    virtual std::shared_ptr<DataTypeComponent> insert(int ordinal, const std::shared_ptr<DataType>& dataType, int length, const std::string& fieldName, const std::string& comment) = 0;
    virtual void delete_() = 0;
    virtual void deleteAll() = 0;

    virtual std::shared_ptr<DataTypeComponent> getComponent(int ordinal) const = 0;
    virtual std::shared_ptr<DataTypeComponent> getComponentAtOffset(int offset) const = 0;
    virtual std::shared_ptr<DataTypeComponent> getComponentContainingOffset(int offset) const = 0;
    virtual int getNumComponents() const = 0;
    virtual int getNumDefinedComponents() const = 0;
    virtual int getLength() const = 0;
    virtual int getAlignedLength() const = 0;
    virtual int getAlignment() const = 0;

    virtual void clearComponent(int ordinal) = 0;
    virtual void moveComponent(int fromOrdinal, int toOrdinal) = 0;
    virtual bool isPackingEnabled() const = 0;
    virtual void setPackingEnabled(bool enabled) = 0;
    virtual bool isNotYetDefined() const = 0;

    // Flex array support
    virtual std::shared_ptr<DataTypeComponent> getFlexibleArrayComponent() const = 0;
    virtual bool hasFlexibleArray() const = 0;
    virtual void setFlexibleArrayComponent(const std::shared_ptr<DataTypeComponent>& component) = 0;
};

} // namespace ghidra
