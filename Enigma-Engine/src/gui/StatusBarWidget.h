#pragma once

#include <QStatusBar>
#include <QLabel>

class StatusBarWidget : public QStatusBar {
    Q_OBJECT
public:
    explicit StatusBarWidget(QWidget* parent = nullptr);

    void setFunction(const QString& name);
    void setAddress(uint64_t addr);
    void setFunctionCount(int count);
    void clear();

private:
    QLabel* funcLabel_;
    QLabel* addrLabel_;
    QLabel* countLabel_;
};
