#include <ghidra/CommentHistory.h>
#include <sstream>
#include <iomanip>

namespace ghidra {

std::string CommentHistory::toString() const {
    std::ostringstream oss;
    auto timeT = std::chrono::system_clock::to_time_t(modificationDate_);
    std::tm tm = *std::localtime(&timeT);

    oss << "{\n"
        << "\tuser: " << userName_ << ",\n"
        << "\tdate: " << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << ",\n"
        << "\taddress: " << addr_.toString() << ",\n"
        << "\tcomment: " << comments_.substr(0, 10) << "\n"
        << "}";
    return oss.str();
}

} // namespace ghidra
