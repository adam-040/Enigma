#pragma once

#include "FieldView.h"
#include <cstdint>
#include <vector>

namespace ghidra { class ProgramDB; }
namespace ghidra::patch { class PatchMemory; }

class HexView : public FieldView {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);
    void setData(uint64_t baseAddr, const std::vector<uint8_t>& data);
    void buildFullHex(ghidra::ProgramDB* program, const QString& binaryPath = QString());
    bool containsAddress(uint64_t addr) const;
    void clear();

    void setPatchMemory(ghidra::patch::PatchMemory* pm) { patchMemory_ = pm; }

signals:
    void patchByteRequested(uint64_t addr);
    void patchNopFillRequested(uint64_t startAddr, uint64_t endAddr);
    void patchStringRequested(uint64_t addr);

protected:
    void paintEvent(QPaintEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;

private:
    int byteIndexAt(int line, int col) const;

    uint64_t baseAddr_ = 0;
    uint64_t endAddr_ = 0;
    ghidra::patch::PatchMemory* patchMemory_ = nullptr;
};
