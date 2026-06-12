/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "ghidra/ByteMemBufferImpl.h"

namespace ghidra {

ByteMemBufferImpl::ByteMemBufferImpl(const Address& addr, const std::vector<uint8_t>& bytes, bool isBigEndian)
    : converter_(GhidraDataConverter::getConverter(isBigEndian)),
      bytes_(bytes), addr_(addr), mem_(nullptr) {}

ByteMemBufferImpl::ByteMemBufferImpl(Memory* memory, const Address& addr, const std::vector<uint8_t>& bytes, bool isBigEndian)
    : converter_(GhidraDataConverter::getConverter(isBigEndian)),
      bytes_(bytes), addr_(addr), mem_(memory) {}

ByteMemBufferImpl::ByteMemBufferImpl(const Address& addr, const uint8_t* bytes, int length, bool isBigEndian)
    : converter_(GhidraDataConverter::getConverter(isBigEndian)),
      bytes_(bytes, bytes + length), addr_(addr), mem_(nullptr) {}

int ByteMemBufferImpl::getLength() const {
    return static_cast<int>(bytes_.size());
}

Address ByteMemBufferImpl::getAddress() const {
    return addr_;
}

Memory* ByteMemBufferImpl::getMemory() const {
    return mem_;
}

int8_t ByteMemBufferImpl::getByte(int offset) const {
    if (offset < 0 || offset >= static_cast<int>(bytes_.size())) {
        throw MemoryAccessException("Offset " + std::to_string(offset) + " is not in range");
    }
    return static_cast<int8_t>(bytes_[offset]);
}

int ByteMemBufferImpl::getBytes(std::vector<uint8_t>& b, int offset) const {
    if (offset < 0 || offset >= static_cast<int>(bytes_.size())) {
        return 0;
    }
    int len = std::min(static_cast<int>(b.size()), static_cast<int>(bytes_.size()) - offset);
    std::copy(bytes_.begin() + offset, bytes_.begin() + offset + len, b.begin());
    return len;
}

int ByteMemBufferImpl::getBytes(uint8_t* b, int length, int offset) const {
    if (offset < 0 || offset >= static_cast<int>(bytes_.size())) {
        return 0;
    }
    int len = std::min(length, static_cast<int>(bytes_.size()) - offset);
    std::copy(bytes_.begin() + offset, bytes_.begin() + offset + len, b);
    return len;
}

bool ByteMemBufferImpl::isBigEndian() const {
    return converter_->isBigEndian();
}

int16_t ByteMemBufferImpl::getShort(int offset) const {
    return converter_->getShort(this, offset);
}

int32_t ByteMemBufferImpl::getInt(int offset) const {
    return converter_->getInt(this, offset);
}

int64_t ByteMemBufferImpl::getLong(int offset) const {
    return converter_->getLong(this, offset);
}

std::vector<uint8_t> ByteMemBufferImpl::getBigInteger(int offset, int size, bool signed_val) const {
    return converter_->getBigInteger(this, offset, size, signed_val);
}

std::unique_ptr<std::istream> ByteMemBufferImpl::getInputStream() const {
    auto buf = new std::stringbuf;
    buf->sputn(reinterpret_cast<const char*>(bytes_.data()), static_cast<std::streamsize>(bytes_.size()));
    return std::unique_ptr<std::istream>(new std::istream(buf));
}

std::unique_ptr<std::istream> ByteMemBufferImpl::getInputStream(int initialPosition, int length) const {
    if (initialPosition < 0 || initialPosition >= static_cast<int>(bytes_.size())) {
        auto buf = new std::stringbuf;
        return std::unique_ptr<std::istream>(new std::istream(buf));
    }
    int len = std::min(length, static_cast<int>(bytes_.size()) - initialPosition);
    auto buf = new std::stringbuf;
    buf->sputn(reinterpret_cast<const char*>(bytes_.data() + initialPosition), static_cast<std::streamsize>(len));
    return std::unique_ptr<std::istream>(new std::istream(buf));
}

} // namespace ghidra
