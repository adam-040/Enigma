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
/// \file UnionAddressSetView.h
/// \brief Lazy address set view representing the union of multiple AddressSetViews
/// Translated from: ghidra.util.UnionAddressSetView
#pragma once

#include <ghidra/AbstractAddressSetView.h>
#include <vector>

namespace ghidra {

/// \brief A lazy, read-only view representing the union of one or more AddressSetViews.
///
/// No data is copied; the union is computed on-the-fly when iterated or queried.
/// The underlying AddressSetViews must remain valid for the lifetime of this object.
class UnionAddressSetView : public AbstractAddressSetView {
private:
    std::vector<const AddressSetView*> sets_;

public:
    /// Construct from two address set views
    UnionAddressSetView(const AddressSetView& a, const AddressSetView& b);

    /// Construct from a collection of address set views
    explicit UnionAddressSetView(const std::vector<const AddressSetView*>& sets);

    ~UnionAddressSetView() override = default;

    bool contains(const Address& addr) const override;

protected:
    std::vector<AddressRange> getRanges() const override;
};

} // namespace ghidra
