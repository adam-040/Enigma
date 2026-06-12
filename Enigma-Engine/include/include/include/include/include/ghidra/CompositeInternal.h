#pragma once

#include <ghidra/Composite.h>
#include <string>
#include <vector>

namespace ghidra {

class DataTypeComponent;

class CompositeInternal : public virtual Composite {
public:
    static const std::string ALIGN_NAME;
    static const std::string PACKING_NAME;
    static const std::string DISABLED_PACKING_NAME;
    static const std::string DEFAULT_PACKING_NAME;

    static constexpr int DEFAULT_PACKING = 0;
    static constexpr int NO_PACKING = -1;
    static constexpr int DEFAULT_ALIGNMENT = 0;
    static constexpr int MACHINE_ALIGNMENT = -1;

    virtual int getStoredPackingValue() = 0;
    virtual int getStoredMinimumAlignment() = 0;

    class ComponentComparator {
    public:
        static const ComponentComparator INSTANCE;
        int compare(const DataTypeComponent& dtc1, const DataTypeComponent& dtc2) const;
    };

    class OffsetComparator {
    public:
        static const OffsetComparator INSTANCE;
        int compare(const DataTypeComponent* dtc, int offset) const;
    };

    class OrdinalComparator {
    public:
        static const OrdinalComparator INSTANCE;
        int compare(const DataTypeComponent* dtc, int ordinal) const;
    };

    static std::string toString(const Composite* composite);
    static std::string getAlignmentAndPackingString(const Composite* composite);
    static std::string getMinAlignmentString(const Composite* composite);
    static std::string getPackingString(const Composite* composite);
};

} // namespace ghidra
