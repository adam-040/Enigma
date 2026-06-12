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
/// \file SymmetricDifferenceAddressSetView.h
/// \brief Lazy address set view representing the symmetric difference (A ⊕ B)
/// Translated from: ghidra.util.SymmetricDifferenceAddressSetView
#pragma once

#include <ghidra/AbstractAddressSetView.h>

namespace ghidra {

/// \brief A lazy, read-only view representing A ⊕ B (addresses in either A or B, but not both).
///
/// No data is copied; the symmetric difference is computed on-the-fly.
/// Both underlying AddressSetViews must remain valid for the lifetime of this object.
class SymmetricDifferenceAddressSetView : public AbstractAddressSetView {
private:
    const AddressSetView& setA_;
    const AddressSetView& setB_;

public:
    /// \param a The first address set
    /// \param b The second address set
    SymmetricDifferenceAddressSetView(const AddressSetView& a, const AddressSetView& b);
    ~SymmetricDifferenceAddressSetView() override = default;

    bool contains(const Address& addr) const override;

protected:
    std::vector<AddressRange> getRanges() const override;
};

} // namespace ghidra
