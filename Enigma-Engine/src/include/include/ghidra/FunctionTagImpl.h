#pragma once

#include <ghidra/FunctionTag.h>

namespace ghidra {

class FunctionTagManager;

class FunctionTagImpl : public FunctionTag {
public:
    FunctionTagImpl(long id, const std::string& name, const std::string& comment, FunctionTagManager* manager);
    ~FunctionTagImpl() override = default;

    long getId() const override { return id_; }
    std::string getName() const override { return name_; }
    std::string getComment() const override { return comment_; }

    void setName(const std::string& name) override { name_ = name; }
    void setComment(const std::string& comment) override { comment_ = comment; }
    void deleteTag() override;

private:
    long id_;
    std::string name_;
    std::string comment_;
    FunctionTagManager* manager_ = nullptr;
};

} // namespace ghidra
