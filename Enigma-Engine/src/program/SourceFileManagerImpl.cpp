/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourceFileManagerImpl.cpp
/// \brief Implementation of source file manager
/// Translated from: ghidra.program.database.sourcemap.SourceFileManagerDB

#include <ghidra/SourceFileManagerImpl.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/AddressOutOfBoundsException.h>
#include <stdexcept>
#include <algorithm>

namespace ghidra {

// Implement SourceMapEntry compareTo here where SourceFile is fully defined
int SourceMapEntry::compareTo(const SourceMapEntry& other) const {
    if (!sourceFile_ && other.sourceFile_) return -1;
    if (sourceFile_ && !other.sourceFile_) return 1;
    if (sourceFile_ && other.sourceFile_) {
        int comp = sourceFile_->compareTo(*other.sourceFile_);
        if (comp != 0) return comp;
    }
    if (lineNumber_ < other.lineNumber_) return -1;
    if (lineNumber_ > other.lineNumber_) return 1;
    if (baseAddress_ < other.baseAddress_) return -1;
    if (baseAddress_ > other.baseAddress_) return 1;
    if (length_ < other.length_) return -1;
    if (length_ > other.length_) return 1;
    return 0;
}

// SourceFileManagerImpl implementations
SourceFile* SourceFileManagerImpl::addSourceFile(const std::string& path, const std::string& compilerSpec) {
    auto it = filesByPath_.find(path);
    if (it != filesByPath_.end() && it->second->getCompilerSpec() == compilerSpec) {
        return it->second;
    }
    auto sf = std::make_unique<SourceFile>(path, compilerSpec);
    SourceFile* raw = sf.get();
    filesByPath_[path] = raw;
    files_.push_back(std::move(sf));
    return raw;
}

SourceFile* SourceFileManagerImpl::getSourceFile(const std::string& path) {
    auto it = filesByPath_.find(path);
    return (it != filesByPath_.end()) ? it->second : nullptr;
}

std::vector<SourceFile*> SourceFileManagerImpl::getSourceFiles() {
    std::vector<SourceFile*> result;
    for (const auto& f : files_) {
        result.push_back(f.get());
    }
    return result;
}

std::vector<SourceMapEntry> SourceFileManagerImpl::getSourceMapEntries(const Address& addr) {
    std::vector<SourceMapEntry> matched;
    for (const auto& entry : entries_) {
        if (entry.getLength() > 0) {
            Address estart = entry.getBaseAddress();
            Address eend = estart.add(entry.getLength() - 1);
            if (estart <= addr && addr <= eend) {
                matched.push_back(entry);
            }
        } else {
            if (entry.getBaseAddress() == addr) {
                matched.push_back(entry);
            }
        }
    }
    return matched;
}

bool SourceFileManagerImpl::addSourceFile(SourceFile* sourceFile) {
    if (!sourceFile) return false;
    for (const auto& f : files_) {
        if (*f == *sourceFile) {
            return false;
        }
    }
    auto sf = std::make_unique<SourceFile>(*sourceFile);
    filesByPath_[sf->getPath()] = sf.get();
    files_.push_back(std::move(sf));
    return true;
}

bool SourceFileManagerImpl::removeSourceFile(SourceFile* sourceFile) {
    if (!sourceFile) return false;
    auto it = std::find_if(files_.begin(), files_.end(), [&](const std::unique_ptr<SourceFile>& f) {
        return *f == *sourceFile;
    });
    if (it == files_.end()) return false;

    // Remove associated entries
    auto sfPtr = it->get();
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const SourceMapEntry& entry) {
        return entry.getSourceFile() == sfPtr || (entry.getSourceFile() && *entry.getSourceFile() == *sfPtr);
    }), entries_.end());

    filesByPath_.erase(sfPtr->getPath());
    files_.erase(it);
    return true;
}

bool SourceFileManagerImpl::containsSourceFile(SourceFile* sourceFile) {
    if (!sourceFile) return false;
    for (const auto& f : files_) {
        if (*f == *sourceFile) return true;
    }
    return false;
}

std::vector<SourceFile*> SourceFileManagerImpl::getAllSourceFiles() {
    return getSourceFiles();
}

std::vector<SourceFile*> SourceFileManagerImpl::getMappedSourceFiles() {
    std::vector<SourceFile*> mapped;
    for (const auto& entry : entries_) {
        SourceFile* sf = entry.getSourceFile();
        if (sf && std::find(mapped.begin(), mapped.end(), sf) == mapped.end()) {
            mapped.push_back(sf);
        }
    }
    std::sort(mapped.begin(), mapped.end(), [](SourceFile* a, SourceFile* b) {
        return a->compareTo(*b) < 0;
    });
    return mapped;
}

SourceMapEntry SourceFileManagerImpl::addSourceMapEntry(SourceFile* sourceFile, int lineNumber, const Address& baseAddr, uint64_t length) {
    if (lineNumber < 0) {
        throw std::invalid_argument("lineNumber cannot be negative");
    }
    if (!sourceFile) {
        throw std::invalid_argument("sourceFile cannot be null");
    }
    if (!containsSourceFile(sourceFile)) {
        throw std::invalid_argument("sourceFile not associated with program");
    }

    Memory* mem = program_ ? program_->getMemory() : nullptr;
    if (mem) {
        MemoryBlock* block = mem->getBlock(baseAddr);
        if (!block) {
            throw AddressOutOfBoundsException(baseAddr.toString() + " is not in a defined memory block");
        }
        if (length > 0) {
            Address endAddr = baseAddr.add(length - 1);
            bool rangeContained = false;
            MemoryBlock* currBlock = block;
            Address currStart = baseAddr;
            while (currBlock) {
                if (currBlock->contains(endAddr)) {
                    rangeContained = true;
                    break;
                }
                Address nextAddr = currBlock->getEnd().add(1);
                if (nextAddr < currStart || nextAddr > endAddr) {
                    break;
                }
                currBlock = mem->getBlock(nextAddr);
                currStart = nextAddr;
            }
            if (!rangeContained) {
                throw AddressOutOfBoundsException(baseAddr.toString() + "," + endAddr.toString() + " spans undefined memory");
            }
        }
    }

    if (length > 0) {
        Address newStart = baseAddr;
        Address newEnd = baseAddr.add(length - 1);

        for (const auto& entry : entries_) {
            if (entry.getLength() > 0) {
                Address estart = entry.getBaseAddress();
                Address eend = estart.add(entry.getLength() - 1);
                if (eend >= newStart && newEnd >= estart) { // intersects
                    if (estart != newStart || eend != newEnd) {
                        throw std::invalid_argument("new entry would overlap but not equal an existing entry");
                    }
                }
            }
        }
    }

    // Check if duplicate exists
    for (const auto& entry : entries_) {
        if (entry.getSourceFile() == sourceFile && entry.getLineNumber() == lineNumber &&
            entry.getBaseAddress() == baseAddr && entry.getLength() == length) {
            return entry;
        }
    }

    SourceMapEntry newEntry(sourceFile, lineNumber, baseAddr, length);
    entries_.push_back(newEntry);
    return newEntry;
}

bool SourceFileManagerImpl::intersectsSourceMapEntry(const AddressSetView& addrs) {
    if (addrs.isEmpty()) return false;
    auto rangeIter = addrs.getAddressRanges();
    if (!rangeIter) return false;
    bool found = false;
    while (rangeIter->hasNext()) {
        AddressRange r = rangeIter->next();
        for (const auto& entry : entries_) {
            if (entry.getLength() > 0) {
                Address estart = entry.getBaseAddress();
                Address eend = estart.add(entry.getLength() - 1);
                if (r.intersects(estart, eend)) {
                    found = true;
                    break;
                }
            } else {
                if (r.contains(entry.getBaseAddress())) {
                    found = true;
                    break;
                }
            }
        }
        if (found) break;
    }
    delete rangeIter;
    return found;
}

void SourceFileManagerImpl::transferSourceMapEntries(SourceFile* source, SourceFile* target) {
    if (!containsSourceFile(source) || !containsSourceFile(target)) {
        throw std::invalid_argument("source or target has not been added previously");
    }
    if (*source == *target) return;

    for (auto& entry : entries_) {
        if (entry.getSourceFile() == source || (entry.getSourceFile() && *entry.getSourceFile() == *source)) {
            entry = SourceMapEntry(target, entry.getLineNumber(), entry.getBaseAddress(), entry.getLength());
        }
    }
}

SourceMapEntryIterator SourceFileManagerImpl::getSourceMapEntryIterator(const Address& address, bool forward) {
    std::vector<SourceMapEntry> matched;
    for (const auto& entry : entries_) {
        if (forward) {
            if (entry.getBaseAddress() >= address) {
                matched.push_back(entry);
            }
        } else {
            if (entry.getBaseAddress() <= address) {
                matched.push_back(entry);
            }
        }
    }
    
    std::sort(matched.begin(), matched.end(), [forward](const SourceMapEntry& a, const SourceMapEntry& b) {
        if (forward) {
            return a.getBaseAddress() < b.getBaseAddress();
        } else {
            return b.getBaseAddress() < a.getBaseAddress(); // descending
        }
    });

    return SourceMapEntryIterator(matched);
}

std::vector<SourceMapEntry> SourceFileManagerImpl::getSourceMapEntries(SourceFile* sourceFile, int minLine, int maxLine) {
    std::vector<SourceMapEntry> matched;
    for (const auto& entry : entries_) {
        if (entry.getSourceFile() == sourceFile || (entry.getSourceFile() && *entry.getSourceFile() == *sourceFile)) {
            if (entry.getLineNumber() >= minLine && entry.getLineNumber() <= maxLine) {
                matched.push_back(entry);
            }
        }
    }
    std::sort(matched.begin(), matched.end());
    return matched;
}

bool SourceFileManagerImpl::removeSourceMapEntry(const SourceMapEntry& entry) {
    auto it = std::find(entries_.begin(), entries_.end(), entry);
    if (it != entries_.end()) {
        entries_.erase(it);
        return true;
    }
    return false;
}

void SourceFileManagerImpl::deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) {
    std::vector<SourceMapEntry> nextEntries;
    for (const auto& entry : entries_) {
        if (entry.getLength() == 0) {
            if (startAddr <= entry.getBaseAddress() && entry.getBaseAddress() <= endAddr) {
                // delete zero-length entry inside delete range
            } else {
                nextEntries.push_back(entry);
            }
            continue;
        }
        Address recStart = entry.getBaseAddress();
        Address recEnd = recStart.add(entry.getLength() - 1);
        if (recEnd < startAddr || endAddr < recStart) {
            nextEntries.push_back(entry);
            continue;
        }
        // overlap - split left and right
        if (recStart < startAddr) {
            uint64_t leftLen = startAddr.getOffset() - recStart.getOffset();
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), recStart, leftLen));
        }
        if (endAddr < recEnd) {
            uint64_t rightLen = recEnd.getOffset() - endAddr.getOffset();
            Address rightStart = endAddr.add(1);
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), rightStart, rightLen));
        }
    }
    entries_ = std::move(nextEntries);
}

void SourceFileManagerImpl::moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) {
    if (length == 0) return;
    Address rangeToMoveEnd = fromAddr.add(length - 1);
    std::vector<SourceMapEntry> nextEntries;
    for (const auto& entry : entries_) {
        if (entry.getLength() == 0) {
            if (fromAddr <= entry.getBaseAddress() && entry.getBaseAddress() <= rangeToMoveEnd) {
                Address newBase = toAddr.add(entry.getBaseAddress().getOffset() - fromAddr.getOffset());
                nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), newBase, 0));
            } else {
                nextEntries.push_back(entry);
            }
            continue;
        }
        Address recStart = entry.getBaseAddress();
        Address recEnd = recStart.add(entry.getLength() - 1);
        if (recEnd < fromAddr || rangeToMoveEnd < recStart) {
            nextEntries.push_back(entry);
            continue;
        }
        
        if (recStart < fromAddr && rangeToMoveEnd < recEnd) {
            uint64_t leftLen = fromAddr.getOffset() - recStart.getOffset();
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), recStart, leftLen));
            
            Address midStart = toAddr;
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), midStart, length));
            
            uint64_t rightLen = recEnd.getOffset() - rangeToMoveEnd.getOffset();
            Address rightStart = rangeToMoveEnd.add(1);
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), rightStart, rightLen));
        }
        else if (recStart < fromAddr) {
            uint64_t leftLen = fromAddr.getOffset() - recStart.getOffset();
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), recStart, leftLen));
            
            uint64_t midLen = recEnd.getOffset() - fromAddr.getOffset() + 1;
            Address midStart = toAddr;
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), midStart, midLen));
        }
        else if (rangeToMoveEnd < recEnd) {
            uint64_t midLen = rangeToMoveEnd.getOffset() - recStart.getOffset() + 1;
            Address midStart = toAddr.add(recStart.getOffset() - fromAddr.getOffset());
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), midStart, midLen));
            
            uint64_t rightLen = recEnd.getOffset() - rangeToMoveEnd.getOffset();
            Address rightStart = rangeToMoveEnd.add(1);
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), rightStart, rightLen));
        }
        else {
            Address midStart = toAddr.add(recStart.getOffset() - fromAddr.getOffset());
            nextEntries.push_back(SourceMapEntry(entry.getSourceFile(), entry.getLineNumber(), midStart, entry.getLength()));
        }
    }
    entries_ = std::move(nextEntries);
}

} // namespace ghidra
