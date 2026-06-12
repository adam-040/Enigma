#pragma once

#include <ghidra/Address.h>
#include <ghidra/Cover.h>
#include <ghidra/Types.h>
#include <vector>
#include <unordered_map>
#include <set>

namespace ghidra {

class VarnodeAST;
class PcodeOpAST;
class PcodeBlockBasic;
class BlockGraph;
class Funcdata;

class Heritage {
public:
    struct HeritageRecord {
        VarnodeAST* varnode;
        Cover cover;
        int4 mergeGroup;
        bool isInput;
        bool isPersist;
    };

    using VariableStack = std::unordered_map<int16_t, std::vector<int>>;

private:
    std::vector<HeritageRecord> records;
    std::vector<int16_t> mergeGroupForBlock;
    Funcdata* fd;
    int4 nextMergeGroup;
    int16_t nextVersion;
    VariableStack varStack;
    bool ssaBuilt;

    void pushVersion(int16_t mergeGroup, int16_t version);
    int16_t popVersion(int16_t mergeGroup);
    int16_t currentVersion(int16_t mergeGroup) const;

    void insertPielementsForGroup(int4 groupId, const std::vector<VarnodeAST*>& groupVns, const BlockGraph& bg);
    void renameBlock(PcodeBlockBasic* block, const BlockGraph& bg);
    void collectDefiningBlocks(int4 groupId, std::set<int>& defBlocks) const;

public:
    Heritage(Funcdata* f);
    ~Heritage() = default;

    void initialize();
    void execute();

    int4 getNumRecords() const { return static_cast<int4>(records.size()); }
    const HeritageRecord* getRecord(int4 index) const;
    HeritageRecord* getRecord(int4 index);

    int4 assignMergeGroup(VarnodeAST* vn);
    int4 getMergeGroup(VarnodeAST* vn) const;

    void markInput(VarnodeAST* vn);
    void markPersist(VarnodeAST* vn);

    bool isInput(VarnodeAST* vn) const;
    bool isPersist(VarnodeAST* vn) const;

    void buildCover(VarnodeAST* vn);
    const Cover* getCover(VarnodeAST* vn) const;

    void clear();

    Funcdata* getFuncdata() const { return fd; }
    int4 getNextMergeGroup() const { return nextMergeGroup; }

    bool hasSSA() const { return ssaBuilt; }
};

class Merge {
public:
    struct MergeGroup {
        int4 id;
        std::vector<VarnodeAST*> varnodes;
        Cover cover;
        bool isInput;
        bool isPersist;
    };

private:
    std::vector<MergeGroup> groups;
    Funcdata* fd;
    int4 nextGroupId;

public:
    Merge(Funcdata* f);
    ~Merge() = default;

    void initialize();
    void execute();

    int4 getNumGroups() const { return static_cast<int4>(groups.size()); }
    const MergeGroup* getGroup(int4 index) const;
    MergeGroup* getGroup(int4 index);

    int4 createGroup();
    void addVarnodeToGroup(int4 groupId, VarnodeAST* vn);
    void mergeGroups(int4 groupId1, int4 groupId2);

    int4 getGroupId(VarnodeAST* vn) const;
    VarnodeAST* getGroupVarnode(int4 groupId, int4 index) const;
    int4 getGroupSize(int4 groupId) const;

    void markGroupInput(int4 groupId);
    void markGroupPersist(int4 groupId);

    bool isGroupInput(int4 groupId) const;
    bool isGroupPersist(int4 groupId) const;

    void buildGroupCover(int4 groupId);
    const Cover* getGroupCover(int4 groupId) const;

    void clear();

    Funcdata* getFuncdata() const { return fd; }
    int4 getNextGroupId() const { return nextGroupId; }
};

} // namespace ghidra
