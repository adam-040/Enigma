#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DWARFExpression;

class DWARFExpressionException : public std::exception {
private:
    std::string message_;
    const DWARFExpression* expr = nullptr;
    int instrIndex = -1;

public:
    DWARFExpressionException() {}

    explicit DWARFExpressionException(const std::string& message) : message_(message) {}

    DWARFExpressionException(const std::string& message, const std::exception& cause)
        : message_(message + " (caused by: " + std::string(cause.what()) + ")") {}

    DWARFExpressionException(const std::string& message, const DWARFExpression* expr, int instrIndex, const std::exception& cause)
        : message_(message + " (caused by: " + std::string(cause.what()) + ")"), expr(expr), instrIndex(instrIndex) {}

    const char* what() const noexcept override { return message_.c_str(); }

    const DWARFExpression* getExpression() const { return expr; }
    void setExpression(const DWARFExpression* expr) { this->expr = expr; }
    int getInstructionIndex() const { return instrIndex; }
    void setInstructionIndex(int idx) { instrIndex = idx; }
};

} // namespace ghidra
