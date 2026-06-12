#include <ghidra/LocalVariableImpl.h>
#include <stdexcept>

namespace ghidra {

LocalVariableImpl::LocalVariableImpl(const std::string& name, DataType* dataType, Address address, Program* program)
    : VariableImpl(name, dataType, address, program, SourceType::DEFAULT), firstUseOffset_(0) {
    if (hasStackStorage() && firstUseOffset_ != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
}

LocalVariableImpl::LocalVariableImpl(const std::string& name, DataType* dataType, Address address, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, address, program, sourceType), firstUseOffset_(0) {
    if (hasStackStorage() && firstUseOffset_ != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
}

LocalVariableImpl::LocalVariableImpl(const std::string& name, int firstUseOffset, DataType* dataType, Address address, Program* program)
    : VariableImpl(name, dataType, address, program, SourceType::DEFAULT), firstUseOffset_(firstUseOffset) {
    if (hasStackStorage() && firstUseOffset_ != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
}

LocalVariableImpl::LocalVariableImpl(const std::string& name, int firstUseOffset, DataType* dataType, Address address, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, address, program, sourceType), firstUseOffset_(firstUseOffset) {
    if (hasStackStorage() && firstUseOffset_ != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
}

LocalVariableImpl::LocalVariableImpl(const std::string& name, DataType* dataType, VariableStorage storage, Program* program)
    : VariableImpl(name, dataType, storage, false, program, SourceType::DEFAULT), firstUseOffset_(0) {
    if (hasStackStorage() && firstUseOffset_ != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
}

LocalVariableImpl::LocalVariableImpl(const std::string& name, DataType* dataType, VariableStorage storage, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, storage, false, program, sourceType), firstUseOffset_(0) {
    if (hasStackStorage() && firstUseOffset_ != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
}

LocalVariableImpl::LocalVariableImpl(const std::string& name, int firstUseOffset, DataType* dataType, VariableStorage storage, Program* program)
    : VariableImpl(name, dataType, storage, false, program, SourceType::DEFAULT), firstUseOffset_(firstUseOffset) {
    if (hasStackStorage() && firstUseOffset_ != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
}

LocalVariableImpl::LocalVariableImpl(const std::string& name, int firstUseOffset, DataType* dataType, VariableStorage storage, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, storage, false, program, sourceType), firstUseOffset_(firstUseOffset) {
    if (hasStackStorage() && firstUseOffset_ != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
}

int LocalVariableImpl::getFirstUseOffset() const {
    return firstUseOffset_;
}

bool LocalVariableImpl::setFirstUseOffset(int firstUseOffset) {
    if (hasStackStorage() && firstUseOffset != 0) {
        throw std::invalid_argument("Stack variable must have first use offset of 0");
    }
    if (firstUseOffset_ == firstUseOffset) {
        return false;
    }
    firstUseOffset_ = firstUseOffset;
    return true;
}

} // namespace ghidra
