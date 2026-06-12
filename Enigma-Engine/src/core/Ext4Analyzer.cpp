#include <ghidra/Ext4Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>

namespace ghidra {

static constexpr int SUPERBLOCK_OFFSET = 0x400;
static constexpr int MAGIC_OFFSET_IN_SB = 0x38;

Ext4Analyzer::Ext4Analyzer()
    : AbstractAnalyzer("Ext4 Analyzer",
                       "Annotates Ext4 file systems.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool Ext4Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    static constexpr int magicOff = SUPERBLOCK_OFFSET + MAGIC_OFFSET_IN_SB;
    Address magicAddr(minAddr.getAddressSpace(), minAddr.getOffset() + magicOff);
    uint8_t buf[2] = {0};
    if (program->getMemory()->getBytes(magicAddr, buf, 2) != 2) return false;
    return buf[0] == 0xEF && buf[1] == 0x53;
}

bool Ext4Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool Ext4Analyzer::added(Program* program, const AddressSetView& set,
                         TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;

    Address sbAddr = minAddr.add(SUPERBLOCK_OFFSET);
    DataTypeManager* dtm = program->getDataTypeManager();

    StructureDataType* sb = new StructureDataType("ext4_super_block", 0, dtm);
    sb->add(&DWordDataType::dataType(), 4, "s_inodes_count", "");
    sb->add(&DWordDataType::dataType(), 4, "s_blocks_count_lo", "");
    sb->add(&DWordDataType::dataType(), 4, "s_r_blocks_count_lo", "");
    sb->add(&DWordDataType::dataType(), 4, "s_free_blocks_count_lo", "");
    sb->add(&DWordDataType::dataType(), 4, "s_free_inodes_count", "");
    sb->add(&DWordDataType::dataType(), 4, "s_first_data_block", "");
    sb->add(&DWordDataType::dataType(), 4, "s_log_block_size", "");
    sb->add(&DWordDataType::dataType(), 4, "s_log_cluster_size", "");
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

    // EXT4_DYNAMIC_REV fields (s_rev_level >= 1)
    sb->add(&DWordDataType::dataType(), 4, "s_first_ino", "");
    sb->add(&WordDataType::dataType(), 2, "s_inode_size", "");
    sb->add(&WordDataType::dataType(), 2, "s_block_group_nr", "");
    sb->add(&DWordDataType::dataType(), 4, "s_feature_compat", "");
    sb->add(&DWordDataType::dataType(), 4, "s_feature_incompat", "");
    sb->add(&DWordDataType::dataType(), 4, "s_feature_ro_compat", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "s_uuid", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "s_volume_name", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 64, 1, dtm), 64, "s_last_mounted", "");
    sb->add(&DWordDataType::dataType(), 4, "s_algorithm_usage_bitmap", "");
    sb->add(&ByteDataType::dataType(), 1, "s_prealloc_blocks", "");
    sb->add(&ByteDataType::dataType(), 1, "s_prealloc_dir_blocks", "");
    sb->add(&WordDataType::dataType(), 2, "s_reserved_gdt_blocks", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "s_journal_uuid", "");
    sb->add(&DWordDataType::dataType(), 4, "s_journal_inum", "");
    sb->add(&DWordDataType::dataType(), 4, "s_journal_dev", "");
    sb->add(&DWordDataType::dataType(), 4, "s_last_orphan", "");
    sb->add(new ArrayDataType(&DWordDataType::dataType(), 4, 4, dtm), 16, "s_hash_seed", "");
    sb->add(&ByteDataType::dataType(), 1, "s_def_hash_version", "");
    sb->add(&ByteDataType::dataType(), 1, "s_jnl_backup_type", "");
    sb->add(&WordDataType::dataType(), 2, "s_desc_size", "");
    sb->add(&DWordDataType::dataType(), 4, "s_default_mount_opts", "");
    sb->add(&DWordDataType::dataType(), 4, "s_first_meta_bg", "");
    sb->add(&DWordDataType::dataType(), 4, "s_mkfs_time", "");
    sb->add(new ArrayDataType(&DWordDataType::dataType(), 17, 4, dtm), 68, "s_jnl_blocks", "");

    // 64bit support fields
    sb->add(&DWordDataType::dataType(), 4, "s_blocks_count_hi", "");
    sb->add(&DWordDataType::dataType(), 4, "s_r_blocks_count_hi", "");
    sb->add(&DWordDataType::dataType(), 4, "s_free_blocks_count_hi", "");
    sb->add(&WordDataType::dataType(), 2, "s_min_extra_isize", "");
    sb->add(&WordDataType::dataType(), 2, "s_want_extra_isize", "");
    sb->add(&DWordDataType::dataType(), 4, "s_flags", "");
    sb->add(&WordDataType::dataType(), 2, "s_raid_stride", "");
    sb->add(&WordDataType::dataType(), 2, "s_mmp_interval", "");
    sb->add(&QWordDataType::dataType(), 8, "s_mmp_block", "");
    sb->add(&DWordDataType::dataType(), 4, "s_raid_stripe_width", "");
    sb->add(&ByteDataType::dataType(), 1, "s_log_groups_per_flex", "");
    sb->add(&ByteDataType::dataType(), 1, "s_checksum_type", "");
    sb->add(&WordDataType::dataType(), 2, "s_reserved_pad", "");
    sb->add(&QWordDataType::dataType(), 8, "s_kbytes_written", "");
    sb->add(&DWordDataType::dataType(), 4, "s_snapshot_inum", "");
    sb->add(&DWordDataType::dataType(), 4, "s_snapshot_id", "");
    sb->add(&QWordDataType::dataType(), 8, "s_snapshot_r_blocks_count", "");
    sb->add(&DWordDataType::dataType(), 4, "s_snapshot_list", "");
    sb->add(&DWordDataType::dataType(), 4, "s_error_count", "");
    sb->add(&DWordDataType::dataType(), 4, "s_first_error_time", "");
    sb->add(&DWordDataType::dataType(), 4, "s_first_error_ino", "");
    sb->add(&QWordDataType::dataType(), 8, "s_first_error_block", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 32, 1, dtm), 32, "s_first_error_func", "");
    sb->add(&DWordDataType::dataType(), 4, "s_first_error_line", "");
    sb->add(&DWordDataType::dataType(), 4, "s_last_error_time", "");
    sb->add(&DWordDataType::dataType(), 4, "s_last_error_ino", "");
    sb->add(&DWordDataType::dataType(), 4, "s_last_error_line", "");
    sb->add(&QWordDataType::dataType(), 8, "s_last_error_block", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 32, 1, dtm), 32, "s_last_error_func", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 64, 1, dtm), 64, "s_mount_opts", "");
    sb->add(&DWordDataType::dataType(), 4, "s_usr_quota_inum", "");
    sb->add(&DWordDataType::dataType(), 4, "s_grp_quota_inum", "");
    sb->add(&DWordDataType::dataType(), 4, "s_overhead_blocks", "");
    sb->add(new ArrayDataType(&DWordDataType::dataType(), 2, 4, dtm), 8, "s_backup_blocks", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "s_encrypt_algos", "");
    sb->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "s_encrypt_pw_salt", "");
    sb->add(&DWordDataType::dataType(), 4, "s_lpf_ino", "");
    sb->add(&DWordDataType::dataType(), 4, "s_prj_quota_inum", "");
    sb->add(&DWordDataType::dataType(), 4, "s_checksum_seed", "");
    sb->add(new ArrayDataType(&DWordDataType::dataType(), 98, 4, dtm), 392, "s_reserved", "");
    sb->add(&DWordDataType::dataType(), 4, "s_checksum", "");

    DataType* resolved = dtm->resolve(sb, nullptr);
    if (!resolved) {
        log.append("Failed to resolve ext4 superblock type");
        return false;
    }

    Data* data = program->getListing()->createData(sbAddr, resolved);
    if (!data) {
        log.append("Failed to create ext4 superblock data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Created ext4 superblock at " + sbAddr.toString());
    }
    return true;
}

} // namespace ghidra
