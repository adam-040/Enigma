/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LinkedByteBuffer.cpp
/// \brief A byte buffer stored as a linked list of pages with a Position iterator.
#include "ghidra/LinkedByteBuffer.h"
#include "ghidra/Decoder.h"
#include "ghidra/DecoderException.h"
#include <stdexcept>

namespace ghidra {

void LinkedByteBuffer::Position::copy(const Position& pos) {
    seqIter = pos.seqIter;
    current = pos.current;
}

uint8_t LinkedByteBuffer::Position::getByte() const {
    return seqIter->array[current];
}

uint8_t LinkedByteBuffer::Position::getBytePlus1() {
    int plus1 = current + 1;
    if (plus1 == static_cast<int>(seqIter->array.size())) {
        ArrayIter* iter = seqIter->next;
        if (iter == nullptr) {
            iter = buffer->readNextPage(seqIter);
        }
        return iter->array[0];
    }
    return seqIter->array[plus1];
}

uint8_t LinkedByteBuffer::Position::getNextByte() {
    uint8_t res = seqIter->array[current];
    current += 1;
    if (current != static_cast<int>(seqIter->array.size())) {
        return res;
    }
    if (seqIter->next == nullptr) {
        seqIter = buffer->readNextPage(seqIter);
    } else {
        seqIter = seqIter->next;
    }
    current = 0;
    return res;
}

void LinkedByteBuffer::Position::advancePosition(int skip) {
    while (skip > 0) {
        int avail = static_cast<int>(seqIter->array.size()) - current;
        if (skip < avail) {
            current += skip;
            return;
        }
        skip -= avail;
        if (seqIter->next == nullptr) {
            seqIter = buffer->readNextPage(seqIter);
        } else {
            seqIter = seqIter->next;
        }
        current = 0;
    }
}

bool LinkedByteBuffer::Position::isEnd() const {
    return current >= static_cast<int>(seqIter->array.size());
}

LinkedByteBuffer::LinkedByteBuffer() {
    initialBuffer_ = new ArrayIter(BUFFER_SIZE);
    currentBuffer_ = initialBuffer_;
    currentPos_ = 0;
    byteCount_ = 0;
}

LinkedByteBuffer::~LinkedByteBuffer() {
    ArrayIter* cur = initialBuffer_;
    while (cur != nullptr) {
        ArrayIter* nxt = cur->next;
        delete cur;
        cur = nxt;
    }
}

void LinkedByteBuffer::open(int maxCount, const std::string& desc) {
    maxCount_ = maxCount;
    description_ = desc;
    currentPos_ = 0;
    byteCount_ = 0;
    currentBuffer_ = initialBuffer_;
}

void LinkedByteBuffer::ingestStreamToNextTerminator(std::istream& stream) {
    int tok = stream.get();
    if (tok <= 0) return;
    for (;;) {
        if (byteCount_ > maxCount_) {
            throw std::runtime_error("Response buffer size exceeded for: " + description_);
        }
        do {
            if (currentPos_ == BUFFER_SIZE) break;
            currentBuffer_->array[currentPos_++] = static_cast<uint8_t>(tok);
            tok = stream.get();
        } while (tok > 0);
        byteCount_ += currentPos_;
        if (tok <= 0) return;
        currentBuffer_->next = new ArrayIter(BUFFER_SIZE);
        currentBuffer_ = currentBuffer_->next;
        currentPos_ = 0;
    }
}

void LinkedByteBuffer::ingestStream(std::istream& stream) {
    while (byteCount_ < maxCount_) {
        int len = maxCount_ - byteCount_;
        if (len > BUFFER_SIZE) len = BUFFER_SIZE;
        int pos = 0;
        do {
            stream.read(reinterpret_cast<char*>(currentBuffer_->array.data()) + pos, len - pos);
            int readLen = static_cast<int>(stream.gcount());
            if (readLen <= 0) break;
            pos += readLen;
        } while (pos < len);
        byteCount_ += pos;
        if (pos < BUFFER_SIZE) {
            currentPos_ += pos;
            break;
        }
        currentBuffer_->next = new ArrayIter(BUFFER_SIZE);
        currentBuffer_ = currentBuffer_->next;
        currentPos_ = 0;
    }
}

void LinkedByteBuffer::ingestBytes(const uint8_t* byteArray, int off, int sz) {
    for (int i = 0; i < sz; ++i) {
        uint8_t tok = byteArray[off + i];
        if (currentPos_ == BUFFER_SIZE) {
            currentBuffer_->next = new ArrayIter(BUFFER_SIZE);
            currentBuffer_ = currentBuffer_->next;
            currentPos_ = 0;
        }
        currentBuffer_->array[currentPos_++] = tok;
        byteCount_ += 1;
        if (byteCount_ > maxCount_) {
            throw std::runtime_error("Response buffer size exceeded for: " + description_);
        }
    }
}

void LinkedByteBuffer::pad(uint8_t padValue) {
    if (currentPos_ == BUFFER_SIZE) {
        byteCount_ += currentPos_;
        currentBuffer_->next = new ArrayIter(1);
        currentBuffer_ = currentBuffer_->next;
        currentPos_ = 0;
    }
    currentBuffer_->array[currentPos_++] = padValue;
    byteCount_ += 1;
}

void LinkedByteBuffer::getStartPosition(Position& position) {
    position.buffer = this;
    position.seqIter = initialBuffer_;
    position.current = 0;
}

LinkedByteBuffer::ArrayIter* LinkedByteBuffer::readNextPage(ArrayIter* buffer) {
    if (asNeededStream_ == nullptr) {
        throw DecoderException("Unexpected end of stream");
    }
    currentBuffer_ = new ArrayIter(BUFFER_SIZE);
    buffer->next = currentBuffer_;
    int len = maxCount_ - byteCount_;
    if (len > BUFFER_SIZE) len = BUFFER_SIZE;
    int pos = 0;
    while (pos < len) {
        asNeededStream_->read(reinterpret_cast<char*>(currentBuffer_->array.data()) + pos, len - pos);
        int rl = static_cast<int>(asNeededStream_->gcount());
        if (rl <= 0) break;
        pos += rl;
    }
    byteCount_ += pos;
    if (pos < BUFFER_SIZE) {
        currentPos_ = pos;
    } else {
        currentPos_ = 0;
    }
    return currentBuffer_;
}

} // namespace ghidra
