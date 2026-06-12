#include <ghidra/CodeBlockImpl.h>
#include <ghidra/CodeBlockModel.h>
#include <ghidra/CodeBlockReferenceIterator.h>
#include <ghidra/CodeBlockReference.h>
#include <ghidra/TaskMonitor.h>
#include <algorithm>

namespace ghidra {

CodeBlockImpl::CodeBlockImpl(CodeBlockModel* model, const std::vector<Address>& starts,
                             AddressSetView* body)
    : model_(model), starts_(starts), set_(body) {
    std::sort(starts_.begin(), starts_.end());
}

CodeBlockImpl::CodeBlockImpl(CodeBlockModel* model, Address start, AddressSetView* body)
    : model_(model), set_(body) {
    starts_.push_back(start);
}

Address CodeBlockImpl::getFirstStartAddress() const {
    return starts_[0];
}

std::string CodeBlockImpl::getName() const {
    return model_->getName(const_cast<CodeBlockImpl*>(this));
}

FlowType CodeBlockImpl::getFlowType() const {
    return model_->getFlowType(const_cast<CodeBlockImpl*>(this));
}

int CodeBlockImpl::getNumSources(TaskMonitor* monitor) {
    return model_->getNumSources(this, monitor);
}

CodeBlockReferenceIterator* CodeBlockImpl::getSources(TaskMonitor* monitor) {
    return model_->getSources(this, monitor);
}

int CodeBlockImpl::getNumDestinations(TaskMonitor* monitor) {
    return model_->getNumDestinations(this, monitor);
}

CodeBlockReferenceIterator* CodeBlockImpl::getDestinations(TaskMonitor* monitor) {
    return model_->getDestinations(this, monitor);
}

// AddressSetView delegation

bool CodeBlockImpl::contains(const Address& addr) const { return set_->contains(addr); }
bool CodeBlockImpl::contains(const Address& start, const Address& end) const { return set_->contains(start, end); }
bool CodeBlockImpl::contains(const AddressSetView& rangeSet) const { return set_->contains(rangeSet); }
bool CodeBlockImpl::isEmpty() const { return set_->isEmpty(); }
Address CodeBlockImpl::getMinAddress() const { return set_->getMinAddress(); }
Address CodeBlockImpl::getMaxAddress() const { return set_->getMaxAddress(); }
int CodeBlockImpl::getNumAddressRanges() const { return set_->getNumAddressRanges(); }
int64_t CodeBlockImpl::getNumAddresses() const { return set_->getNumAddresses(); }
AddressRangeIterator* CodeBlockImpl::getAddressRanges() const { return set_->getAddressRanges(); }
AddressRangeIterator* CodeBlockImpl::getAddressRanges(bool forward) const { return set_->getAddressRanges(forward); }
AddressRangeIterator* CodeBlockImpl::getAddressRanges(const Address& start, bool forward) const {
    return set_->getAddressRanges(start, forward);
}
bool CodeBlockImpl::intersects(const AddressSetView& other) const { return set_->intersects(other); }
bool CodeBlockImpl::intersects(const Address& start, const Address& end) const { return set_->intersects(start, end); }
AddressSet CodeBlockImpl::intersect(const AddressSetView& view) const { return set_->intersect(view); }
AddressSet CodeBlockImpl::intersectRange(const Address& start, const Address& end) const { return set_->intersectRange(start, end); }
AddressSet CodeBlockImpl::unionSet(const AddressSetView& addrSet) const { return set_->unionSet(addrSet); }
AddressSet CodeBlockImpl::subtract(const AddressSetView& addrSet) const { return set_->subtract(addrSet); }
AddressSet CodeBlockImpl::xorSet(const AddressSetView& addrSet) const { return set_->xorSet(addrSet); }
bool CodeBlockImpl::hasSameAddresses(const AddressSetView& addrSet) const { return set_->hasSameAddresses(addrSet); }
AddressRange CodeBlockImpl::getFirstRange() const { return set_->getFirstRange(); }
AddressRange CodeBlockImpl::getLastRange() const { return set_->getLastRange(); }
AddressRange CodeBlockImpl::getRangeContaining(const Address& address) const { return set_->getRangeContaining(address); }
Address CodeBlockImpl::findFirstAddressInCommon(const AddressSetView& other) const { return set_->findFirstAddressInCommon(other); }

std::string CodeBlockImpl::toString() const {
    return getName();
}

bool CodeBlockImpl::operator==(const CodeBlockImpl& other) const {
    if (model_->getName() != other.model_->getName()) return false;
    if (starts_.size() != other.starts_.size()) return false;
    for (size_t i = 0; i < starts_.size(); ++i) {
        if (starts_[i] != other.starts_[i]) return false;
    }
    return true;
}

} // namespace ghidra
