#include <ghidra/DataIterator.h>

namespace ghidra {

class EmptyDataIterator : public DataIterator {
public:
    bool hasNext() override { return false; }
    Data* next() override { return nullptr; }
};

DataIterator& DataIterator::empty() {
    static EmptyDataIterator inst;
    return inst;
}

DataIterator* DataIterator::of(const std::vector<Data*>& data) {
    if (data.empty()) {
        return &empty();
    }
    return new DataIteratorWrapper(data);
}

} // namespace ghidra
