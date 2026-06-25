#pragma once

#include "FieldView.h"
#include <cstdint>
#include <vector>

class HexView : public FieldView {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);
    void setData(uint64_t baseAddr, const std::vector<uint8_t>& data);
    void clear();
};
