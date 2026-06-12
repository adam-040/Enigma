/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <string>

namespace ghidra {

class ConstructTpl;
class Location;
class SleighLanguage;
class PcodeEmit;

class PcodeParser {
public:
    PcodeParser(SleighLanguage* lang, long uniqueBase);

    void addOperand(const Location& loc, const std::string& name, int index);
    ConstructTpl* compilePcode(const std::string& pcodeText,
                               const std::string& sourceName, int lineNum);
    long getNextTempOffset() const { return nextUnique_; }

private:
    SleighLanguage* language_;
    long uniqueBase_;
    long nextUnique_ = 0;
};

} // namespace ghidra
