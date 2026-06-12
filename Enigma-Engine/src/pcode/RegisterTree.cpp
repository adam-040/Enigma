#include <ghidra/RegisterTree.h>
#include <algorithm>

namespace ghidra {

RegisterTree::RegisterTree(Register* reg)
    : register_(reg), name_(reg->getName()) {
    auto registerChildren = reg->getChildRegisters();
    for (auto* childReg : registerChildren) {
        auto* tree = new RegisterTree(childReg);
        tree->parent_ = this;
        children_.push_back(tree);
    }
}

RegisterTree::RegisterTree(const std::string& name, const std::vector<Register*>& regs)
    : name_(name) {
    for (auto* reg : regs) {
        if (reg->isBaseRegister()) {
            auto* tree = new RegisterTree(reg);
            tree->parent_ = this;
            children_.push_back(tree);
        }
    }
}

RegisterTree::RegisterTree(const std::string& name, RegisterTree* tree)
    : name_(name) {
    children_.push_back(tree);
}

void RegisterTree::add(RegisterTree* tree) {
    children_.push_back(tree);
    tree->parent_ = this;
}

std::string RegisterTree::getParentRegisterPath() const {
    auto* parentTree = getParent();
    if (!parentTree || !parentTree->getRegister()) {
        return {};
    }
    return parentTree->getRegisterPath();
}

std::string RegisterTree::getRegisterPath() const {
    auto parentPath = getParentRegisterPath();
    if (!parentPath.empty()) {
        return parentPath + SEPARATOR + getRegister()->getName();
    }
    return getRegister()->getName();
}

RegisterTree* RegisterTree::getRegisterTree(Register* reg) {
    if (register_ == reg) return this;
    for (auto* child : children_) {
        auto* result = child->getRegisterTree(reg);
        if (result) return result;
    }
    return nullptr;
}

void RegisterTree::remove(Register* reg) {
    auto* tree = getRegisterTree(reg);
    if (!tree || !tree->getParent()) return;
    auto& siblings = tree->getParent()->children_;
    auto it = std::find(siblings.begin(), siblings.end(), tree);
    if (it != siblings.end()) siblings.erase(it);
}

std::string RegisterTree::toString() const {
    std::string buffer = name_;
    buffer += '[';
    for (auto* child : children_) {
        buffer += child->toString();
        buffer += ',';
    }
    buffer += ']';
    return buffer;
}

} // namespace ghidra
