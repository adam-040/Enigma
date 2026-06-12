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
/// \file DataTypePath.cpp
/// \brief Holds a category path and a datatype name separately
#include "ghidra/DataTypePath.h"

namespace ghidra {

DataTypePath::DataTypePath(const std::string& categoryPath, const std::string& dataTypeName)
    : categoryPath_(categoryPath), dataTypeName_(dataTypeName)
{
    if (dataTypeName_.empty()) {
        throw std::invalid_argument("Data type name cannot be null or empty");
    }
}

DataTypePath::DataTypePath(const CategoryPath& categoryPath, const std::string& dataTypeName)
    : categoryPath_(categoryPath), dataTypeName_(dataTypeName)
{
    if (dataTypeName_.empty()) {
        throw std::invalid_argument("Data type name cannot be null or empty");
    }
}

const CategoryPath& DataTypePath::getCategoryPath() const {
    return categoryPath_;
}

bool DataTypePath::isAncestor(const CategoryPath& otherCategoryPath) const {
    return categoryPath_.isAncestorOrSelf(otherCategoryPath);
}

const std::string& DataTypePath::getDataTypeName() const {
    return dataTypeName_;
}

std::string DataTypePath::getPath() const {
    std::string path = categoryPath_.getPath();
    if (!path.empty() && path.back() != CategoryPath::DELIMITER_CHAR) {
        path += CategoryPath::DELIMITER_CHAR;
    }
    path += dataTypeName_;
    return path;
}

bool DataTypePath::operator==(const DataTypePath& other) const {
    return categoryPath_ == other.categoryPath_ && dataTypeName_ == other.dataTypeName_;
}

bool DataTypePath::operator!=(const DataTypePath& other) const {
    return !(*this == other);
}

int DataTypePath::compareTo(const DataTypePath& other) const {
    if (categoryPath_ < other.categoryPath_) return -1;
    if (other.categoryPath_ < categoryPath_) return 1;
    return dataTypeName_.compare(other.dataTypeName_);
}

bool DataTypePath::operator<(const DataTypePath& other) const {
    return compareTo(other) < 0;
}

bool DataTypePath::operator>(const DataTypePath& other) const {
    return compareTo(other) > 0;
}

std::string DataTypePath::toString() const {
    return getPath();
}

} // namespace ghidra

namespace std {
    size_t hash<ghidra::DataTypePath>::operator()(const ghidra::DataTypePath& p) const {
        return hash<ghidra::CategoryPath>{}(p.getCategoryPath()) ^
               (hash<string>{}(p.getDataTypeName()) << 1);
    }
}
