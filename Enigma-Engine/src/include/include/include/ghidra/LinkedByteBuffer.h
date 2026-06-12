/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LinkedByteBuffer.h
/// \brief A byte buffer stored as a linked list of pages with a Position iterator.
#pragma once

#include "ghidra/Decoder.h"
#include <cstdint>
#include <istream>
#include <stdexcept>
#include <vector>

namespace ghidra {

/**
 * A byte buffer that is stored as a linked list of pages, each holding BUFFER_SIZE bytes.
 * A Position object acts as an iterator over the whole buffer. The buffer can be populated
 * from a stream, either all at once or lazily as Position advances.
 * Translated from: ghidra.program.model.pcode.LinkedByteBuffer
 */
class LinkedByteBuffer {
public:
    static constexpr int BUFFER_SIZE = 4096;

    class ArrayIter {
    public:
        std::vector<uint8_t> array;
        ArrayIter* next = nullptr;

        ArrayIter() : array() {}
        explicit ArrayIter(int sz) : array(sz) {}
    };

    /**
     * An iterator into the byte buffer.
     */
    class Position {
    public:
        LinkedByteBuffer* buffer = nullptr;
        ArrayIter* seqIter = nullptr;
        int current = 0;

        void copy(const Position& pos);
        uint8_t getByte() const;
        uint8_t getBytePlus1();
        uint8_t getNextByte();
        void advancePosition(int skip);
        bool isEnd() const;
    };

    LinkedByteBuffer();
    ~LinkedByteBuffer();

    void open(int maxCount, const std::string& desc);
    void ingestStreamToNextTerminator(std::istream& stream);
    void ingestStream(std::istream& stream);
    void ingestBytes(const uint8_t* byteArray, int off, int sz);
    void pad(uint8_t padValue);
    void getStartPosition(Position& position);
    void setAsNeededStream(std::istream* stream) { asNeededStream_ = stream; }
    int getByteCount() const { return byteCount_; }

private:
    ArrayIter* readNextPage(ArrayIter* buffer);

    ArrayIter* initialBuffer_ = nullptr;
    ArrayIter* currentBuffer_ = nullptr;
    int currentPos_ = 0;
    int maxCount_ = 0;
    int byteCount_ = 0;
    std::string description_;
    std::istream* asNeededStream_ = nullptr;
};

} // namespace ghidra
