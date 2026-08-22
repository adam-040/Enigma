#pragma once

#include <string>

namespace ghidra {

class MsvcDemangler {
public:
    static std::string demangle(const std::string& mangled);
    static bool isMsvcMangled(const std::string& name);

private:
    std::string input_;
    size_t pos_ = 0;

    std::string parse();
    std::string parseName();
    std::string parseOperatorName();
    std::string parseType();
    std::string parseFunctionType();
    std::string parseQualifiedType();
    std::string parseCVQualifiers();
    std::string parsePointerType();
    std::string parseReferenceType();
    std::string parseArrayType();
    std::string parseTemplateArgs();
    std::string parseDataMember();
    std::string parseStaticDataMember();
    std::string parseEnumType();
    std::string parseClassType();
    std::string parseBuiltInType();
    std::string parseCallingConv();
    std::string parseAccess();
    std::string parseThrowingFuncType();

    char peek() const;
    char get();
    bool match(char c);
    bool matchStr(const std::string& s);
    int parseNumber();
    std::string parseDigits();
    void expect(char c);
};

} // namespace ghidra
