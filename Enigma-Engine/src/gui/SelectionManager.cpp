#include "SelectionManager.h"

SelectionManager::SelectionManager(QObject* parent)
    : QObject(parent)
{
}

void SelectionManager::setRangeResolver(RangeResolver resolver) {
    resolver_ = std::move(resolver);
}

void SelectionManager::select(const SelectionState& sel, QObject* sender) {
    Q_UNUSED(sender)
    SelectionState resolved = sel;
    if (resolved.valid && resolver_) {
        uint64_t start = resolved.address;
        uint64_t end = resolved.endAddress;
        if (resolver_(resolved.address, start, end)) {
            resolved.address = start;
            resolved.endAddress = end;
        }
    }
    if (state_ == resolved)
        return;
    state_ = resolved;
    emit selectionChanged(state_);
}
