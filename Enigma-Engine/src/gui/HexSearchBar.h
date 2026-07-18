#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QVector>
#include <QRegularExpression>
#include <cstdint>
#include "HexView.h"

class HexSearchBar : public QWidget {
    Q_OBJECT
public:
    explicit HexSearchBar(HexView* hexView, QWidget* parent = nullptr);

    void activate();
    void deactivate();
    bool isActive() const { return visible_; }
    void activateReplace();

signals:
    void closeRequested();

protected:
    void keyPressEvent(QKeyEvent* event) override;

private slots:
    void searchPrev();
    void searchNext();
    void onPatternChanged(const QString& text);
    void replaceCurrent();
    void replaceAll();

private:
    void performSearch();
    void updateMatchLabel();
    void navigateToMatch(int index);
    void highlightMatches();

    HexView* hexView_;
    QLineEdit* patternEdit_;
    QLineEdit* replaceEdit_;
    QComboBox* modeCombo_;
    QPushButton* prevBtn_;
    QPushButton* nextBtn_;
    QPushButton* replaceBtn_;
    QPushButton* replaceAllBtn_;
    QPushButton* closeBtn_;
    QLabel* matchLabel_;
    QWidget* replaceRow_;
    bool visible_ = false;
    bool replaceVisible_ = false;

    QVector<HexSearchMatch> matches_;
    int currentMatchIndex_ = -1;
};
