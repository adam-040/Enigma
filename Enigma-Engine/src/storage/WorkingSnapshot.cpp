#include <ghidra/storage/WorkingSnapshot.h>
#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/storage/SnapshotReader.h>
#include <fstream>
#include <filesystem>

namespace ghidra {
namespace storage {

bool WorkingSnapshot::save(const ProgramDB& program, const std::string& snapshotPath) {
    auto data = SnapshotWriter::serialize(program);
    std::string tmpPath = snapshotPath + ".tmp";
    if (!SnapshotWriter::writeFile(tmpPath, data)) return false;

    // Best-effort fsync via flushing
    {
        std::ofstream tmpOut(tmpPath, std::ios::binary | std::ios::app);
        if (tmpOut) {
            tmpOut.flush();
            tmpOut.close();
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmpPath, snapshotPath, ec);
    return !ec;
}

std::unique_ptr<ProgramDB> WorkingSnapshot::load(const std::string& snapshotPath) {
    return SnapshotReader::loadFromFile(snapshotPath);
}

} // namespace storage
} // namespace ghidra
