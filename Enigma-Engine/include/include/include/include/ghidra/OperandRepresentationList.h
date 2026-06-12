#pragma once

#include <vector>
#include <string>
#include <memory>

namespace ghidra {

class OperandRepresentationList : public std::vector<void*> {
public:
    OperandRepresentationList() : primaryReferenceIsHidden_(false), hasError_(false) {}

    explicit OperandRepresentationList(bool primaryReferenceIsHidden)
        : primaryReferenceIsHidden_(primaryReferenceIsHidden), hasError_(false) {}

    OperandRepresentationList(const std::vector<void*>& opList, bool primaryReferenceIsHidden)
        : std::vector<void*>(opList), primaryReferenceIsHidden_(primaryReferenceIsHidden),
          hasError_(false) {}

    explicit OperandRepresentationList(const std::string& error)
        : hasError_(true) {
        push_back(new std::string(error));
    }

    void setPrimaryReferenceHidden(bool hidden) { primaryReferenceIsHidden_ = hidden; }
    bool isPrimaryReferenceHidden() const { return primaryReferenceIsHidden_; }

    void setHasError(bool hasError) { hasError_ = hasError; }
    bool hasError() const { return hasError_; }

    std::string toString() const {
        std::string result;
        for (auto* elem : *this) {
            if (elem) {
                auto* s = static_cast<std::string*>(elem);
                result += *s;
            }
        }
        return result;
    }

private:
    bool primaryReferenceIsHidden_;
    bool hasError_;
};

} // namespace ghidra
