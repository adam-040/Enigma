#include <ghidra/MsvcDemangler.h>
#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace ghidra {

bool MsvcDemangler::isMsvcMangled(const std::string& name) {
    if (name.empty()) return false;
    if (name[0] == '?') return true;
    if (name.size() > 1 && name[0] == '_' && name[1] == '?') return true;
    return false;
}

std::string MsvcDemangler::demangle(const std::string& mangled) {
    if (mangled.empty()) return mangled;
    MsvcDemangler d;
    d.input_ = mangled;
    d.pos_ = 0;

    std::string result;
    try {
        result = d.parse();
    } catch (...) {
        return mangled;
    }

    if (result.empty() || result == mangled) return mangled;
    return result;
}

char MsvcDemangler::peek() const {
    if (pos_ >= input_.size()) return '\0';
    return input_[pos_];
}

char MsvcDemangler::get() {
    if (pos_ >= input_.size()) return '\0';
    return input_[pos_++];
}

bool MsvcDemangler::match(char c) {
    if (peek() == c) { ++pos_; return true; }
    return false;
}

bool MsvcDemangler::matchStr(const std::string& s) {
    if (pos_ + s.size() > input_.size()) return false;
    if (input_.substr(pos_, s.size()) == s) { pos_ += s.size(); return true; }
    return false;
}

int MsvcDemangler::parseNumber() {
    int val = 0;
    bool neg = false;
    if (peek() == '-') { neg = true; ++pos_; }
    if (peek() == '?') {
        ++pos_;
        val = parseNumber();
        return neg ? -val : val;
    }
    while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
        val = val * 10 + (input_[pos_] - '0');
        ++pos_;
    }
    return neg ? -val : val;
}

std::string MsvcDemangler::parseDigits() {
    std::string s;
    while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
        s += input_[pos_++];
    }
    return s;
}

void MsvcDemangler::expect(char c) {
    if (!match(c)) throw std::runtime_error(std::string("expected '") + c + "'");
}

// --- Top-level parse ---
std::string MsvcDemangler::parse() {
    if (peek() == '?') {
        ++pos_;
        return parseName();
    }
    return input_.substr(pos_);
}

// --- Name parsing ---
std::string MsvcDemangler::parseName() {
    if (peek() == '?' || std::isalpha(static_cast<unsigned char>(peek()))) {
        return parseOperatorName();
    }
    if (std::isdigit(static_cast<unsigned char>(peek()))) {
        int n = parseNumber();
        if (n > 0 && pos_ + n <= input_.size()) {
            std::string name = input_.substr(pos_, n);
            pos_ += n;
            if (peek() == '@' || peek() == '?' || peek() == '$') {
                std::string rest = parseQualifiedType();
                if (!rest.empty()) return name + "::" + rest;
            }
            return name;
        }
    }
    return "";
}

// --- Operator name ---
std::string MsvcDemangler::parseOperatorName() {
    if (peek() == '$') {
        ++pos_;
        std::string tag;
        if (matchStr("T")) tag = "typeinfo";
        else if (matchStr("R")) tag = "rtti";
        else if (matchStr("V")) tag = "vftable";
        else if (matchStr("C")) tag = "vcall";
        else if (matchStr("I")) tag = "sinh";
        else if (matchStr("J")) tag = "cosh";
        else if (matchStr("K")) tag = "tanh";
        else if (matchStr("L")) tag = "log";
        else if (matchStr("M")) tag = "log10";
        else if (matchStr("O")) tag = "pow";
        else if (matchStr("P")) tag = "sqrt";
        else if (matchStr("Q")) tag = "sin";
        else if (matchStr("S")) tag = "cos";
        else if (matchStr("T")) tag = "tan";
        else if (matchStr("U")) tag = "atan";
        else {
            if (std::isdigit(static_cast<unsigned char>(peek()))) {
                tag = "$" + parseDigits();
            }
        }
        return tag;
    }

    char c1 = get();
    char c2 = get();

    switch (c1) {
        case '0': return "~" + std::string(1, c2);  // destructor
        case '1': return std::string(1, c2);          // constructor
        case '2': return "operator new";
        case '3': return "operator delete";
        case '4': return "operator=";
        case '5': return "operator>>";
        case '6': return "operator<<";
        case '7': return "operator!";
        case '8': return "operator==";
        case '9': return "operator!=";
        case 'A': return "operator[]";
        case 'B': return "operator*";
        case 'C': return "operator->";
        case 'D': return "operator cast";
        case 'E': return "operator+";
        case 'F': return "operator-";
        case 'G': return "operator*";
        case 'H': return "operator%";
        case 'I': return "operator&";
        case 'J': return "operator|";
        case 'K': return "operator^";
        case 'L': return "operator~";
        case 'M': return "operator=";
        case 'N': return "operator+=";
        case 'O': return "operator-=";
        case 'P': return "operator*=";
        case 'Q': return "operator/=";
        case 'R': return "operator%=";
        case 'S': return "operator&=";
        case 'T': return "operator|=";
        case 'U': return "operator^=";
        case 'V': return "operator<<=";
        case 'W': return "operator>>=";
        case 'X': return "operator,";
        case 'Y': return "operator->*";
        case 'Z': return "()";
        case '_':
            switch (c2) {
                case '0': return "operator new[]";
                case '1': return "operator delete[]";
                case '2': return "operator coawait";
                case '3': return "operator await";
                case '4': return "operator yield";
                case '5': return "operator driver";
                case '6': return "operator uniform_distribution";
                default: return "?" + std::string(1, c2);
            }
        default:
            return "?" + std::string(1, c1) + std::string(1, c2);
    }
}

// --- Built-in type ---
std::string MsvcDemangler::parseBuiltInType() {
    char c = peek();
    switch (c) {
        case 'X': ++pos_; return "void";
        case 'D': ++pos_; return "char";
        case 'C': ++pos_; return "unsigned char";
        case 'E': ++pos_; return "wchar_t";
        case 'F': ++pos_; return "bool";
        case 'G': ++pos_; return "short";
        case 'H': ++pos_; return "int";
        case 'I': ++pos_; return "unsigned int";
        case 'J': ++pos_; return "long";
        case 'K': ++pos_; return "unsigned long";
        case 'L': ++pos_; return "__int64";
        case 'M': ++pos_; return "float";
        case 'N': ++pos_; return "double";
        case 'O': ++pos_; return "long double";
        case 'W': {
            ++pos_;
            char variant = get();
            switch (variant) {
                case '0': return "unsigned short";
                case '1': return "unsigned int";
                case '2': return "unsigned long";
                default: return "wchar_t";
            }
        }
        default: return "";
    }
}

// --- CV qualifiers ---
std::string MsvcDemangler::parseCVQualifiers() {
    std::string quals;
    while (pos_ < input_.size()) {
        char c = peek();
        if (c == 'B') { quals += " const"; ++pos_; }
        else if (c == 'C') { quals += " volatile"; ++pos_; }
        else if (c == 'D') { quals += " const volatile"; ++pos_; }
        else break;
    }
    return quals;
}

// --- Calling convention ---
std::string MsvcDemangler::parseCallingConv() {
    char c = get();
    switch (c) {
        case 'A': return "__cdecl";
        case 'B': return "__pascal";
        case 'C': return "__thiscall";
        case 'D': return "__stdcall";
        case 'E': return "__fastcall";
        case 'F': return "__thiscall";  // alt
        case 'G': return "enum class";
        case 'H': return "__clrcall";
        case 'I': return "member function";
        case 'J': return "member function";
        case 'K': return "member function";
        case 'L': return "member function";
        case 'M': return "member function";
        default: return "";
    }
}

// --- Access specifier ---
std::string MsvcDemangler::parseAccess() {
    char c = peek();
    if (c == '0') { ++pos_; return "private: "; }
    if (c == '1') { ++pos_; return "protected: "; }
    if (c == '2') { ++pos_; return "public: "; }
    return "";
}

// --- Pointer/reference type ---
std::string MsvcDemangler::parsePointerType() {
    std::string quals = parseCVQualifiers();
    std::string type = parseQualifiedType();
    return type + "*" + quals;
}

std::string MsvcDemangler::parseReferenceType() {
    std::string quals = parseCVQualifiers();
    std::string type = parseQualifiedType();
    char c = peek();
    if (c == 'R') { ++pos_; return type + "&&" + quals; }
    return type + "&" + quals;
}

// --- Array type ---
std::string MsvcDemangler::parseArrayType() {
    std::string type = parseQualifiedType();
    int rank = parseNumber();
    std::string dims;
    if (rank > 0) {
        dims = "[";
        for (int i = 0; i < rank; ++i) {
            if (i > 0) dims += ", ";
            if (peek() == '?') {
                ++pos_;
                dims += parseDigits();
            } else {
                dims += parseDigits();
            }
        }
        dims += "]";
    }
    return type + dims;
}

// --- Template arguments ---
std::string MsvcDemangler::parseTemplateArgs() {
    std::string args;
    expect('?');
    while (pos_ < input_.size() && peek() != '@') {
        if (!args.empty()) args += ", ";
        args += parseQualifiedType();
    }
    if (peek() == '@') ++pos_;
    return "<" + args + ">";
}

// --- Class type (qualified name) ---
std::string MsvcDemangler::parseClassType() {
    std::string result;
    while (pos_ < input_.size() && peek() != '\0') {
        if (peek() == '@') {
            ++pos_;
            break;
        }
        if (peek() == '?') {
            ++pos_;
            result += parseOperatorName();
        } else if (std::isdigit(static_cast<unsigned char>(peek()))) {
            int n = parseNumber();
            if (n > 0 && pos_ + n <= input_.size()) {
                if (!result.empty()) result += "::";
                result += input_.substr(pos_, n);
                pos_ += n;
            }
        } else if (peek() == '$') {
            ++pos_;
            std::string tmplName;
            if (peek() == '?') { ++pos_; tmplName = parseOperatorName(); }
            else if (std::isdigit(static_cast<unsigned char>(peek()))) {
                int n = parseNumber();
                if (n > 0 && pos_ + n <= input_.size()) {
                    tmplName = input_.substr(pos_, n);
                    pos_ += n;
                }
            }
            std::string args = parseTemplateArgs();
            if (!result.empty()) result += "::";
            result += tmplName + args;
        } else {
            ++pos_;
        }
    }
    return result;
}

// --- Qualified type (nested name + type) ---
std::string MsvcDemangler::parseQualifiedType() {
    if (peek() == '?') {
        ++pos_;
        if (peek() == '?') {
            ++pos_;
            return parseClassType();
        }
        if (std::isdigit(static_cast<unsigned char>(peek()))) {
            int n = parseNumber();
            if (n > 0 && pos_ + n <= input_.size()) {
                std::string name = input_.substr(pos_, n);
                pos_ += n;
                if (peek() == '@' || peek() == '?') {
                    std::string rest = parseQualifiedType();
                    if (!rest.empty()) return name + "::" + rest;
                }
                return name;
            }
        }
        return parseOperatorName();
    }
    return parseBuiltInType();
}

// --- Function type ---
std::string MsvcDemangler::parseFunctionType() {
    std::string retType;
    std::string cc;
    std::string access;
    std::string quals;

    // Calling convention
    if (peek() == 'E') { cc = "__fastcall "; ++pos_; }
    else if (peek() == 'A') { cc = "__cdecl "; ++pos_; }
    else if (peek() == 'B') { cc = "__pascal "; ++pos_; }
    else if (peek() == 'C') { cc = "__thiscall "; ++pos_; }
    else if (peek() == 'D') { cc = "__stdcall "; ++pos_; }

    // Return type
    retType = parseQualifiedType();

    // Parameter list
    std::string params;
    while (pos_ < input_.size() && peek() != '@') {
        if (!params.empty()) params += ", ";
        params += parseQualifiedType();
    }
    if (peek() == '@') ++pos_;

    // Throw types
    if (peek() == '$') {
        ++pos_;
        parseCVQualifiers();
        while (pos_ < input_.size() && peek() != '@') {
            parseQualifiedType();
        }
        if (peek() == '@') ++pos_;
    }

    // cv-qualifiers
    quals = parseCVQualifiers();

    return cc + retType + " (" + params + ")" + quals;
}

// --- Throwing function type ---
std::string MsvcDemangler::parseThrowingFuncType() {
    std::string cc;
    if (peek() == 'E') { cc = "__fastcall "; ++pos_; }
    else if (peek() == 'A') { cc = "__cdecl "; ++pos_; }

    std::string retType = parseQualifiedType();

    std::string params;
    while (pos_ < input_.size() && peek() != '@') {
        if (!params.empty()) params += ", ";
        params += parseQualifiedType();
    }
    if (peek() == '@') ++pos_;

    return cc + retType + " (" + params + ")";
}

// --- Data member ---
std::string MsvcDemangler::parseDataMember() {
    std::string className = parseClassType();
    std::string memberName;
    if (std::isdigit(static_cast<unsigned char>(peek()))) {
        int n = parseNumber();
        if (n > 0 && pos_ + n <= input_.size()) {
            memberName = input_.substr(pos_, n);
            pos_ += n;
        }
    } else if (peek() == '?') {
        ++pos_;
        memberName = parseOperatorName();
    }
    std::string quals = parseCVQualifiers();
    std::string type = parseQualifiedType();
    return className + "::" + memberName + quals + " " + type;
}

// --- Static data member ---
std::string MsvcDemangler::parseStaticDataMember() {
    std::string className = parseClassType();
    std::string memberName;
    if (std::isdigit(static_cast<unsigned char>(peek()))) {
        int n = parseNumber();
        if (n > 0 && pos_ + n <= input_.size()) {
            memberName = input_.substr(pos_, n);
            pos_ += n;
        }
    }
    std::string type = parseQualifiedType();
    return className + "::" + memberName + " " + type;
}

// --- Enum type ---
std::string MsvcDemangler::parseEnumType() {
    std::string enumName = parseClassType();
    std::string quals = parseCVQualifiers();
    std::string type = parseQualifiedType();
    return "enum " + enumName + quals + " " + type;
}

} // namespace ghidra
