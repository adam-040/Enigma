#include "AddressMinimap.h"
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/patch/PatchManager.h>
#include <ghidra/patch/Patch.h>
#include <QPainter>
#include <QMouseEvent>
#include <QToolTip>

namespace {

constexpr int kPad = 2; // px margin on each side
constexpr int kBarH = 14; // height of the colored band
constexpr int kTop = 4; // y offset of the band within the widget

// Light theme
const QColor kBgColor(0xf5, 0xf5, 0xf5);
const QColor kGapColor(0xdf, 0xdf, 0xdf);
const QColor kCodeColor(0x9a, 0xa8, 0xcc);
const QColor kFuncColor(0x6b, 0x82, 0xc9);
const QColor kDataColor(0xd0, 0xb0, 0x6a);
const QColor kPatchColor(0xe0, 0x4f, 0x4f);
const QColor kViewColor(0xd4, 0x3a, 0x3a);
const QColor kViewFill(0xd4, 0x3a, 0x3a, 45);

} // namespace

AddressMinimap::AddressMinimap(QWidget* parent)
    : QWidget(parent)
{
    setFixedHeight(kHeight);
    setMouseTracking(true);
}

void AddressMinimap::setData(ghidra::Memory* memory, ghidra::FunctionManager* fm,
                             ghidra::patch::PatchManager* pm) {
    blocks_.clear();
    funcRanges_.clear();
    patches_.clear();
    patchMgr_ = pm;
    minAddr_ = 0;
    maxAddr_ = 0;
    viewStart_ = 0;
    viewEnd_ = 0;

    if (memory) {
        auto memBlocks = memory->getBlocks();
        for (const auto* b : memBlocks) {
            if (!b) continue;
            Block blk;
            blk.start = b->getStart().getOffset();
            blk.end = b->getEnd().getOffset();
            blk.executable = b->isExecute();
            if (blk.start <= blk.end) {
                blocks_.push_back(blk);
                if (!minAddr_ || blk.start < minAddr_) minAddr_ = blk.start;
                if (blk.end > maxAddr_) maxAddr_ = blk.end;
            }
        }
    }

    if (fm) {
        ghidra::FunctionIterator fit = fm->getFunctions(true);
        while (fit.hasNext()) {
            auto* f = fit.next();
            if (!f) continue;
            Range body;
            body.start = f->getEntryPoint().getOffset();
            body.end = body.start;
            const auto& aset = f->getBody();
            auto* it = aset.getAddressRanges(true);
            if (it) {
                while (it->hasNext()) {
                    const ghidra::AddressRange& r = it->next();
                    uint64_t s = r.getMinAddress().getOffset();
                    uint64_t e = r.getMaxAddress().getOffset();
                    body.start = std::min(body.start, s);
                    body.end = std::max(body.end, e);
                }
                delete it;
            }
            funcRanges_.push_back(body);
        }
    }

    refresh();
}

void AddressMinimap::refresh() {
    patches_.clear();
    if (patchMgr_) {
        auto all = patchMgr_->getAllPatches();
        for (const auto* p : all) {
            if (!p) continue;
            Range r;
            r.start = p->baseAddress();
            r.end = r.start + std::max<size_t>(p->patchedBytes().size(), 1) - 1;
            patches_.push_back(r);
        }
    }
    update();
}

void AddressMinimap::setViewport(uint64_t start, uint64_t end) {
    viewStart_ = start;
    viewEnd_ = end;
    update();
}

uint64_t AddressMinimap::addressAtX(int x) const {
    if (maxAddr_ <= minAddr_) return 0;
    int w = width() - 2 * kPad;
    if (w <= 0) return 0;
    double frac = static_cast<double>(x - kPad) / w;
    frac = std::max(0.0, std::min(1.0, frac));
    return minAddr_ + static_cast<uint64_t>(frac * (maxAddr_ - minAddr_));
}

bool AddressMinimap::isCodeAddress(uint64_t addr) const {
    for (const auto& blk : blocks_) {
        if (addr >= blk.start && addr < blk.end)
            return blk.executable;
    }
    return false;
}

void AddressMinimap::navigateTo(const QPoint& pos) {
    uint64_t addr = addressAtX(pos.x());
    if (addr != 0) {
        if (isCodeAddress(addr))
            emit navigateRequested(addr);
        else
            emit hexNavigateRequested(addr);
    }
}

void AddressMinimap::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.fillRect(rect(), kBgColor);

    QRect band(kPad, kTop, width() - 2 * kPad, kBarH);
    p.fillRect(band, kGapColor);

    if (maxAddr_ <= minAddr_ || blocks_.empty()) {
        p.setPen(QColor(0x99, 0x99, 0x99));
        p.drawText(band, Qt::AlignCenter, tr("No binary loaded"));
        return;
    }

    double span = static_cast<double>(maxAddr_ - minAddr_);
    double w = static_cast<double>(band.width());

    auto xFor = [&](uint64_t addr) {
        return band.left() + static_cast<int>((addr - minAddr_) * w / span);
    };

    for (const auto& blk : blocks_) {
        int x0 = xFor(blk.start);
        int x1 = xFor(blk.end);
        if (x1 < x0) std::swap(x0, x1);
        p.fillRect(x0, band.top(), std::max(1, x1 - x0), band.height(),
                   blk.executable ? kCodeColor : kDataColor);
    }

    for (const auto& r : funcRanges_) {
        int x0 = xFor(r.start);
        int x1 = xFor(r.end);
        if (x1 < x0) std::swap(x0, x1);
        p.fillRect(x0, band.top(), std::max(1, x1 - x0), band.height(), kFuncColor);
    }

    for (const auto& r : patches_) {
        int x0 = xFor(r.start);
        int x1 = xFor(r.end);
        if (x1 < x0) std::swap(x0, x1);
        p.fillRect(x0, band.top(), std::max(1, x1 - x0), band.height(), kPatchColor);
    }

    if (viewStart_ != 0 && viewEnd_ >= viewStart_) {
        int x0 = xFor(viewStart_);
        int x1 = xFor(viewEnd_);
        if (x1 < x0) std::swap(x0, x1);
        QRect vp(x0, band.top() - 1, std::max(3, x1 - x0), band.height() + 2);
        p.fillRect(vp, kViewFill);
        p.setPen(QPen(kViewColor, 1));
        p.drawRect(vp);
    }
}

void AddressMinimap::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        dragging_ = true;
        navigateTo(event->pos());
    }
}

void AddressMinimap::mouseMoveEvent(QMouseEvent* event) {
    if (dragging_) {
        navigateTo(event->pos());
    } else {
        uint64_t addr = addressAtX(event->pos().x());
        if (addr != 0)
            QToolTip::showText(event->globalPos(),
                               tr("0x%1").arg(addr, 0, 16), this);
    }
}

void AddressMinimap::mouseReleaseEvent(QMouseEvent*) {
    dragging_ = false;
}

void AddressMinimap::leaveEvent(QEvent*) {
    QToolTip::hideText();
}
