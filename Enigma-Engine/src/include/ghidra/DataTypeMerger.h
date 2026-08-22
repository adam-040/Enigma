#pragma once

#include <ghidra/DataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeConflictHandler.h>
#include <unordered_map>
#include <vector>

namespace ghidra {

/**
 * Merges data types from a source DataTypeManager into a target DataTypeManager.
 * Handles conflicts via DataTypeConflictHandler and maintains old-to-new ID mapping.
 */
class DataTypeMerger {
public:
    DataTypeMerger(DataTypeManager* target, DataTypeManager* source,
                   DataTypeConflictHandler* handler);
    ~DataTypeMerger() = default;

    /**
     * Execute the merge. Returns true if all types merged successfully.
     * Throws DataTypeMergeException on fatal errors.
     */
    bool merge();

    /**
     * Get the old-to-new ID map after merge.
     * Maps source type IDs to target type IDs.
     */
    const std::unordered_map<int64_t, int64_t>& getIdMap() const { return idMap_; }

    /**
     * Get the number of types that were successfully merged.
     */
    int getMergeCount() const { return mergeCount_; }

    /**
     * Get the number of types that were skipped due to conflicts.
     */
    int getSkipCount() const { return skipCount_; }

private:
    DataTypeManager* target_;
    DataTypeManager* source_;
    DataTypeConflictHandler* handler_;
    std::unordered_map<int64_t, int64_t> idMap_;
    int mergeCount_ = 0;
    int skipCount_ = 0;

    /**
     * Merge a single type into the target.
     * Returns the resolved type in the target, or nullptr on failure.
     */
    DataType* mergeType(DataType* srcType);

    /**
     * Clone a type for the target DTM, resolving any referenced types first.
     */
    DataType* cloneForTarget(DataType* srcType);

    /**
     * Check if two types are equivalent.
     */
    bool isEquivalent(DataType* a, DataType* b);
};

} // namespace ghidra
