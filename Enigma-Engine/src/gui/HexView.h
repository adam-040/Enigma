#pragma once

#include <QAbstractScrollArea>
#include <QFont>
#include <cstdint>
#include <vector>

class HexView : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);
    void setData(uint64_t baseAddr, const std::vector<uint8_t>& data);
    void clear();

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    uint64_t baseAddr_ = 0;
    std::vector<uint8_t> data_;
    int bytesPerLine_ = 16;
    QFont font_;
};
