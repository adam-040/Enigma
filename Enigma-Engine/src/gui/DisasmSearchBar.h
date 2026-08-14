#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QCheckBox>
#include <QToolButton>
#include <QLabel>
#include <QVector>

class DisassemblyFieldView;

class DisasmSearchBar : public QWidget {
    Q_OBJECT
public:
    explicit DisasmSearchBar(DisassemblyFieldView* disasmView, QWidget* parent = nullptr);

    void openSearch(const QString& initialText = QString());
    void closeSearch();
    bool isSearchActive() const { return isVisible(); }

public slots:
    void findNext();
    void findPrev();

signals:
    void searchClosed();

protected:
    void keyPressEvent(QKeyEvent* event) override;

private slots:
    void onTextChanged(const QString& text);
    void onMatchCaseToggled(bool checked);

private:
    void performSearch();
    void updateMatchLabel();
    void goToCurrentMatch();

    DisassemblyFieldView* disasmView_ = nullptr;
    QLineEdit* searchInput_ = nullptr;
    QCheckBox* matchCaseCheck_ = nullptr;
    QToolButton* prevBtn_ = nullptr;
    QToolButton* nextBtn_ = nullptr;
    QLabel* countLabel_ = nullptr;
    QToolButton* closeBtn_ = nullptr;

    QVector<int> matchingRows_;
    int currentMatchIdx_ = -1;
};
