#include <ghidra/NewExt4Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>

namespace ghidra {

static constexpr int SUPERBLOCK_OFFSET = 0x400;

NewExt4Analyzer::NewExt4Analyzer()
    : AbstractAnalyzer("Ext4 Analyzer NEW",
                       "Annotates Ext4 file systems (supports large files).",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool NewExt4Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;

    static constexpr int magicOff = SUPERBLOCK_OFFSET + 0x38;
    Address magicAddr(minAddr.getAddressSpace(), minAddr.getOffset() + magicOff);
    uint8_t buf[2] = {0};
    if (program->getMemory()->getBytes(magicAddr, buf, 2) != 2) return false;
    return buf[0] == 0x53 && buf[1] == 0xEF;
}

bool NewExt4Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool NewExt4Analyzer::added(Program* program, const AddressSetView& set,
                             TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Annotating ext4 filesystem...");

    auto* memory = program->getMemory();
    auto* listing = program->getListing();
    auto* dtm = program->getDataTypeManager();
    auto* symTable = program->getSymbolTable();
    if (!memory || !listing || !dtm || !symTable) return false;

    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;

    Address sbAddr(minAddr.getAddressSpace(), minAddr.getOffset() + SUPERBLOCK_OFFSET);

    // Create minimal ext4 superblock struct
    auto sb = std::make_unique<StructureDataType>("ext4_super_block_new", 0, dtm);
    sb->add(&DWordDataType::dataType(), 4, "s_inodes_count", "");
    sb->add(&DWordDataType::dataType(), 4, "s_blocks_count_lo", "");
    sb->add(&DWordDataType::dataType(), 4, "s_r_blocks_count_lo", "");
    sb->add(&DWordDataType::dataType(), 4, "s_free_blocks_count_lo", "");
    sb->add(&DWordDataType::dataType(), 4, "s_free_inodes_count", "");
    sb->add(&DWordDataType::dataType(), 4, "s_first_data_block", "");
    sb->add(&DWordDataType::dataType(), 4, "s_log_block_size", "");
    sb->add(&DWordDataType::dataType(), 4, "s_blocks_per_group", "");
    sb->add(&DWordDataType::dataType(), 4, "s_clusters_per_group", "");
    sb->add(&DWordDataType::dataType(), 4, "s_inodes_per_group", "");
    sb->add(&DWordDataType::dataType(), 4, "s_mtime", "");
    sb->add(&DWordDataType::dataType(), 4, "s_wtime", "");
    sb->add(&WordDataType::dataType(), 2, "s_mnt_count", "");
    sb->add(&WordDataType::dataType(), 2, "s_max_mnt_count", "");
    sb->add(&WordDataType::dataType(), 2, "s_magic", "");
    sb->add(&WordDataType::dataType(), 2, "s_state", "");
    sb->add(&WordDataType::dataType(), 2, "s_errors", "");
    sb->add(&WordDataType::dataType(), 2, "s_minor_rev_level", "");
    sb->add(&DWordDataType::dataType(), 4, "s_lastcheck", "");
    sb->add(&DWordDataType::dataType(), 4, "s_checkinterval", "");
    sb->add(&DWordDataType::dataType(), 4, "s_creator_os", "");
    sb->add(&DWordDataType::dataType(), 4, "s_rev_level", "");
    sb->add(&WordDataType::dataType(), 2, "s_def_resuid", "");
    sb->add(&WordDataType::dataType(), 2, "s_def_resgid", "");

    DataType* resolved = dtm->resolve(sb.get(), nullptr);
    if (!resolved) {
        log.append("Failed to resolve ext4 superblock type");
        return false;
    }

    Data* sbData = listing->createData(sbAddr, resolved);
    if (!sbData) {
        log.append("Failed to create ext4 superblock data");
        return false;
    }
    sbData->setComment("ext4 Superblock (New Analyzer)");

    symTable->createLabel(sbAddr, "ext4_superblock", SourceType::ANALYSIS);

    if (monitor) {
        monitor->setMessage("Annotated ext4 filesystem (new) at " + minAddr.toString());
    }
    return true;
}

} // namespace ghidra
