#include <ghidra/EmbeddedMediaAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/StringDataType.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/AddressRange.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Options.h>
#include <cstring>
#include <vector>
#include <algorithm>
#include <memory>

namespace ghidra {

static const char* OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
static const char* OPTION_DESCRIPTION_CREATE_BOOKMARKS =
    "If checked, an analysis bookmark will be created at each location where embedded media data is identified.";

static const uint8_t MAGIC_GIF[] = {0x47, 0x49, 0x46};
static const uint8_t MAGIC_PNG[] = {0x89, 0x50, 0x4E, 0x47};
static const uint8_t MAGIC_JPEG[] = {0xFF, 0xD8, 0xFF};
static const uint8_t MAGIC_RIFF[] = {0x52, 0x49, 0x46, 0x46};
static const uint8_t MAGIC_WAVE_SUB[] = {0x57, 0x41, 0x56, 0x45};
static const uint8_t MAGIC_MIDI[] = {0x4D, 0x54, 0x68, 0x64};
static const uint8_t MAGIC_AU[] = {0x2E, 0x73, 0x6E, 0x64};
static const uint8_t MAGIC_FORM[] = {0x46, 0x4F, 0x52, 0x4D};
static const uint8_t MAGIC_AIFF_SUB[] = {0x41, 0x49, 0x46, 0x46};

struct MediaSig {
    const char* name;
    const uint8_t* magic;
    int magicLen;
    const uint8_t* subMagic;
    int subMagicLen;
    int subOffset;
};

static const MediaSig FORMATS[] = {
    {"GIF",  MAGIC_GIF,  sizeof(MAGIC_GIF),  nullptr, 0, 0},
    {"PNG",  MAGIC_PNG,  sizeof(MAGIC_PNG),  nullptr, 0, 0},
    {"JPEG", MAGIC_JPEG, sizeof(MAGIC_JPEG), nullptr, 0, 0},
    {"WAVE", MAGIC_RIFF, sizeof(MAGIC_RIFF), MAGIC_WAVE_SUB, sizeof(MAGIC_WAVE_SUB), 8},
    {"MIDI", MAGIC_MIDI, sizeof(MAGIC_MIDI), nullptr, 0, 0},
    {"AU",   MAGIC_AU,   sizeof(MAGIC_AU),   nullptr, 0, 0},
    {"AIFF", MAGIC_FORM, sizeof(MAGIC_FORM), MAGIC_AIFF_SUB, sizeof(MAGIC_AIFF_SUB), 8},
};

EmbeddedMediaAnalyzer::EmbeddedMediaAnalyzer()
    : AbstractAnalyzer("Embedded Media",
                       "Finds embedded media (PNG, JPEG, GIF, etc) in programs.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::BLOCK_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

void EmbeddedMediaAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled_,
                         OPTION_DESCRIPTION_CREATE_BOOKMARKS);
}

void EmbeddedMediaAnalyzer::optionsChanged(Options& options, Program* program) {
    createBookmarksEnabled_ = options.getBool(OPTION_NAME_CREATE_BOOKMARKS);
}

static int maxMagicLen() {
    int maxLen = 0;
    for (const auto& fmt : FORMATS) {
        int need = fmt.magicLen;
        if (fmt.subMagic) {
            need = (std::max)(need, fmt.subOffset + fmt.subMagicLen);
        }
        if (need > maxLen) maxLen = need;
    }
    return maxLen;
}

bool EmbeddedMediaAnalyzer::added(Program* program, const AddressSetView& set,
                                   TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    BookmarkManager* bm = program->getBookmarkManager();

    auto blocks = memory->getBlocks();
    int totalFound = 0;

    const int maxNeed = maxMagicLen();
    uint8_t buf[32];

    auto* rangeIter = set.getAddressRanges();
    if (!rangeIter) return false;

    while (rangeIter->hasNext()) {
        if (monitor && monitor->isCancelled()) break;

        const AddressRange& range = rangeIter->next();
        Address rangeStart = range.getMinAddress();
        Address rangeEnd = range.getMaxAddress();

        for (auto* block : blocks) {
            if (!block->isInitialized() || !block->isLoaded()) continue;
            if (monitor && monitor->isCancelled()) break;

            Address blockStart = block->getStart();
            Address blockEnd = block->getEnd();

            if (rangeEnd < blockStart || rangeStart > blockEnd) continue;

            Address scanStart = (rangeStart < blockStart) ? blockStart : rangeStart;
            Address scanEnd = (rangeEnd > blockEnd) ? blockEnd : rangeEnd;

            Address addr = scanStart;
            while (addr <= scanEnd) {
                if (monitor && monitor->isCancelled()) break;

                int64_t remaining = scanEnd.getOffset() - addr.getOffset() + 1;
                if (remaining < maxNeed) break;

                int n = block->getBytes(addr, buf, (std::min)(static_cast<int64_t>(sizeof(buf)), remaining));
                if (n < maxNeed) {
                    addr = addr.next();
                    continue;
                }

                bool matched = false;
                for (const auto& fmt : FORMATS) {
                    if (memcmp(buf, fmt.magic, fmt.magicLen) != 0) continue;

                    if (fmt.subMagic) {
                        if (fmt.subOffset + fmt.subMagicLen > n) continue;
                        if (memcmp(buf + fmt.subOffset, fmt.subMagic, fmt.subMagicLen) != 0) continue;
                    }

                    if (listing->isUndefined(addr)) {
                        listing->createData(addr, &StringDataType::dataType());
                        if (createBookmarksEnabled_ && bm) {
                            std::string comment = std::string("Found ") + fmt.name + " Embedded Media";
                            bm->setBookmark(addr, "Analysis", comment);
                        }
                        ++totalFound;
                    }
                    matched = true;
                    break;
                }

                addr = addr.next();
            }
        }
    }

    delete rangeIter;

    if (totalFound > 0) {
        log.append(getName(), "Found " + std::to_string(totalFound) + " embedded media signatures");
    }
    return totalFound > 0;
}

} // namespace ghidra
