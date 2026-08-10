#pragma once

#include <QTableWidget>
#include <cstdint>
#include <memory>
#include <QString>

namespace ghidra {
class Disassembler;
namespace patch { class PatchManager; }
}

class PatchListWidget : public QTableWidget {
    Q_OBJECT
public:
    enum Column {
        ColAddress = 0,
        ColFrom,
        ColTo,
        ColName,
        ColStatus,
        ColCount,
    };

    explicit PatchListWidget(QWidget* parent = nullptr);
    ~PatchListWidget() override;

    void setPatchManager(ghidra::patch::PatchManager* pm);
    void setDisassembler(std::unique_ptr<ghidra::Disassembler> disasm);
    void refresh();

signals:
    void navigateRequested(uint64_t addr);
    void patchDeleted(const QString& id);
    void patchToggled(const QString& id);

protected:
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;

private:
    QString idAtRow(int row) const;
    QString instructionText(const std::vector<uint8_t>& bytes, uint64_t addr) const;

    ghidra::patch::PatchManager* patchMgr_ = nullptr;
    std::unique_ptr<ghidra::Disassembler> disasm_;
};
