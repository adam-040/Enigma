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
/// \file TriConsumer.h
/// \brief Three-argument functional interface patterned after std::function
/// Translated from: ghidra.util.TriConsumer
#pragma once

#include <functional>

namespace ghidra {

/// \brief A three-argument consumer modeled after std::function<void(T,U,V)>.
/// Patterned after Java's TriConsumer (analogous to BiConsumer but with 3 args).
template<typename T, typename U, typename V>
using TriConsumer = std::function<void(T, U, V)>;

} // namespace ghidra
