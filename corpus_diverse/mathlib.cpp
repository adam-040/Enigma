// Shared library sample: extern "C" exports + a C++ class export +
// internal state. Built as a DLL.
#include <cmath>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#if defined(_WIN32)
#define MATHLIB_API extern "C" __declspec(dllexport)
#else
#define MATHLIB_API extern "C"
#endif

namespace mathlib {

class Polynomial {
public:
    Polynomial(std::initializer_list<double> coeffs) : coeffs_(coeffs) {}
    double evaluate(double x) const {
        double result = 0.0;
        for (double c : coeffs_) result = result * x + c;
        return result;
    }
    size_t degree() const { return coeffs_.empty() ? 0 : coeffs_.size() - 1; }

private:
    std::vector<double> coeffs_;
};

static unsigned long long callCount = 0;

}  // namespace mathlib

MATHLIB_API double mathlib_quadratic_root(double a, double b, double c) {
    mathlib::callCount++;
    double disc = b * b - 4.0 * a * c;
    if (disc < 0.0 || a == 0.0) return 0.0;
    return (-b + std::sqrt(disc)) / (2.0 * a);
}

MATHLIB_API int mathlib_polynomial_eval(const double* coeffs, int n, double x,
                                        double* out) {
    if (!coeffs || !out || n <= 0) return -1;
    mathlib::callCount++;
    double result = 0.0;
    for (int i = 0; i < n; ++i) result = result * x + coeffs[i];
    *out = result;
    return 0;
}

MATHLIB_API unsigned long long mathlib_call_count() {
    return mathlib::callCount;
}

MATHLIB_API size_t mathlib_format_report(char* buffer, size_t bufferLen,
                                         unsigned long long count) {
    std::string report = "calls=" + std::to_string(count);
    if (!buffer || bufferLen == 0) return report.size() + 1;
    size_t n = std::min(bufferLen - 1, report.size());
    std::memcpy(buffer, report.c_str(), n);
    buffer[n] = '\0';
    return n;
}
