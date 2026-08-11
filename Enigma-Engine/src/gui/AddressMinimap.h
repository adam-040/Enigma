#pragma once

#include <QWidget>
#include <cstdint>
#include <vector>

namespace ghidra {
class Memory;
class FunctionManager;
namespace patch { class PatchManager; }
}

/// Horizontal address-range minimap (IDA/Ghidra style overview bar).
/// Shows the full binary address space with colored regions (code, data,
/// gaps) and red markers for active patches. A blue box marks the address
/// range currently visible in the disassembly view. Clicking or dragging
/// navigates the disassembly to that address.
class AddressMinimap : public QWidget {
    Q_OBJECT
public:
    explicit AddressMinimap(QWidget* parent = nullptr);

    void setData(ghidra::Memory* memory, ghidra::FunctionManager* fm,
                 ghidra::patch::PatchManager* pm);
    void setViewport(uint64_t start, uint64_t end);
    void refresh();
    static constexpr int kHeight = 22;

signals:
    void navigateRequested(uint64_t addr);
    void hexNavigateRequested(uint64_t addr);

protected:
    void paintEvent(QPaintEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void leaveEvent(QEvent* event) override;

private:
    struct Block {
        uint64_t start = 0;
        uint64_t end = 0;
        bool executable = false;
    };
    struct Range {
        uint64_t start = 0;
        uint64_t end = 0;
    };

    uint64_t addressAtX(int x) const;
    bool isCodeAddress(uint64_t addr) const;
    void navigateTo(const QPoint& pos);

    std::vector<Block> blocks_;
    std::vector<Range> funcRanges_;
    std::vector<Range> patches_;
    uint64_t minAddr_ = 0;
    uint64_t maxAddr_ = 0;
    uint64_t viewStart_ = 0;
    uint64_t viewEnd_ = 0;
    bool dragging_ = false;

    ghidra::patch::PatchManager* patchMgr_ = nullptr;
};
