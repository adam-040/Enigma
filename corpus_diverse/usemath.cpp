// Consumer of mathlib.dll: load-time linking + one LoadLibrary path.
#include <cstdio>
#include <windows.h>

extern "C" __declspec(dllimport) double mathlib_quadratic_root(double a, double b,
                                                               double c);
extern "C" __declspec(dllimport) int mathlib_polynomial_eval(const double* coeffs,
                                                             int n, double x,
                                                             double* out);
extern "C" __declspec(dllimport) unsigned long long mathlib_call_count();

typedef unsigned long long (*count_fn)();
typedef size_t (*format_fn)(char*, size_t, unsigned long long);

int main() {
    double r1 = mathlib_quadratic_root(1.0, -3.0, 2.0);   // roots 1 and 2
    double out = 0.0;
    double coeffs[4] = {2.0, 0.0, -1.0, 1.0};             // x^3 - x^2 + 2
    mathlib_polynomial_eval(coeffs, 4, 1.5, &out);

    HMODULE lib = LoadLibraryA("mathlib.dll");
    if (lib) {
        auto count = reinterpret_cast<count_fn>(GetProcAddress(lib, "mathlib_call_count"));
        auto format = reinterpret_cast<format_fn>(GetProcAddress(lib, "mathlib_format_report"));
        if (count && format) {
            char buf[64];
            format(buf, sizeof(buf), count());
            std::printf("report: %s\n", buf);
        }
        FreeLibrary(lib);
    }
    std::printf("root=%g poly=%g calls=%llu\n", r1, out,
                (unsigned long long)mathlib_call_count());
    return 0;
}
