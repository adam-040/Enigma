#pragma once

#include "FieldView.h"
#include <cstdint>
#include <vector>

class HexView : public FieldView {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);
    void setData(uint64_t baseAddr, const std::vector<uint8_t>& data);
    bool containsAddress(uint64_t addr) const;
    void clear();

private:
    uint64_t baseAddr_ = 0;
    uint64_t endAddr_ = 0;
};
