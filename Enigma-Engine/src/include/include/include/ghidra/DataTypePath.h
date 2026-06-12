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
/// \file DataTypePath.h
/// \brief Holds a category path and a datatype name separately
/// Translated from: ghidra.program.model.data.DataTypePath
#pragma once

#include <string>
#include <functional>
#include "ghidra/CategoryPath.h"

namespace ghidra {

/**
 * Object to hold a category path and a datatype name. They are held separately so that
 * the datatype name can contain a categoryPath delimiter ("/") character.
 */
class DataTypePath {
private:
    CategoryPath categoryPath_;
    std::string dataTypeName_;

public:
    /// Create DataTypePath from string path and name
    DataTypePath(const std::string& categoryPath, const std::string& dataTypeName);

    /// Create DataTypePath from CategoryPath and name
    DataTypePath(const CategoryPath& categoryPath, const std::string& dataTypeName);

    /// Returns the category path for the datatype
    const CategoryPath& getCategoryPath() const;

    /// Determine if the specified category path is an ancestor of this data type path
    bool isAncestor(const CategoryPath& otherCategoryPath) const;

    /// Returns the name of the datatype
    const std::string& getDataTypeName() const;

    /// Returns the full path of this datatype
    std::string getPath() const;

    bool operator==(const DataTypePath& other) const;
    bool operator!=(const DataTypePath& other) const;
    int compareTo(const DataTypePath& other) const;
    bool operator<(const DataTypePath& other) const;
    bool operator>(const DataTypePath& other) const;
    std::string toString() const;
};

} // namespace ghidra

namespace std {
    template<>
    struct hash<ghidra::DataTypePath> {
        size_t operator()(const ghidra::DataTypePath& p) const;
    };
}
