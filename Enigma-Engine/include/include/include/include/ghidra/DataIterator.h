#pragma once

#include <ghidra/Data.h>
#include <vector>

namespace ghidra {

class DataIterator {
public:
    virtual ~DataIterator() = default;

    virtual bool hasNext() = 0;
    virtual Data* next() = 0;

    static DataIterator& empty();
    static DataIterator* of(const std::vector<Data*>& data);
};

class DataIteratorWrapper : public DataIterator {
public:
    DataIteratorWrapper(std::vector<Data*> data) : data_(std::move(data)), pos_(0) {}
    bool hasNext() override { return pos_ < data_.size(); }
    Data* next() override { return (pos_ < data_.size()) ? data_[pos_++] : nullptr; }
private:
    std::vector<Data*> data_;
    size_t pos_;
};

} // namespace ghidra
