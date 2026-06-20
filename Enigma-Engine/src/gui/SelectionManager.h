#pragma once

#include <QObject>
#include <functional>
#include "SelectionState.h"

class SelectionManager : public QObject {
    Q_OBJECT
public:
    using RangeResolver = std::function<bool(uint64_t addr, uint64_t& start, uint64_t& end)>;

    explicit SelectionManager(QObject* parent = nullptr);

    void setRangeResolver(RangeResolver resolver);
    void select(const SelectionState& sel, QObject* sender = nullptr);
    const SelectionState& current() const { return state_; }

signals:
    void selectionChanged(const SelectionState& sel);

private:
    SelectionState state_;
    RangeResolver resolver_;
};
