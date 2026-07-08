#pragma once

#include "FieldView.h"
#include <cstdint>
#include <vector>

namespace ghidra { class ProgramDB; }

class HexView : public FieldView {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);
    void setData(uint64_t baseAddr, const std::vector<uint8_t>& data);
    void buildFullHex(ghidra::ProgramDB* program, const QString& binaryPath = QString());
    bool containsAddress(uint64_t addr) const;
    void clear();

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    int byteIndexAt(int line, int col) const;

    uint64_t baseAddr_ = 0;
    uint64_t endAddr_ = 0;
};
