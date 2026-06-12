#include <iostream>
#include <cstring>
int main() {
    const char* s = "int * *";
    std::cout << "len=" << strlen(s) << "\n";
    for (int i = 0; i < (int)strlen(s); ++i) {
        std::cout << "i=" << i << " c='" << s[i] << "' (0x" << std::hex << (int)(unsigned char)s[i] << std::dec << ")\n";
    }
    return 0;
}
