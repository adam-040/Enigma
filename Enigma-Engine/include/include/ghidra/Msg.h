/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Msg.h
/// \brief Logging and message reporting utility
#pragma once

#include <string>
#include <exception>

namespace ghidra {

class Msg {
public:
    static void out(const std::string& message);

    static void trace(const std::string& originator, const std::string& message);
    static void trace(const std::string& originator, const std::string& message, const std::exception& e);

    static void debug(const std::string& originator, const std::string& message);
    static void debug(const std::string& originator, const std::string& message, const std::exception& e);

    static void info(const std::string& originator, const std::string& message);
    static void info(const std::string& originator, const std::string& message, const std::exception& e);

    static void showInfo(const std::string& originator, void* parent, const std::string& title, const std::string& message);

    static void warn(const std::string& originator, const std::string& message);
    static void warn(const std::string& originator, const std::string& message, const std::exception& e);

    static void showWarn(const std::string& originator, void* parent, const std::string& title, const std::string& message);

    static void error(const std::string& originator, const std::string& message);
    static void error(const std::string& originator, const std::string& message, const std::exception& e);

    static void showError(const std::string& originator, void* parent, const std::string& title, const std::string& message);
    static void showError(const std::string& originator, void* parent, const std::string& title, const std::string& message, const std::exception& e);
};

} // namespace ghidra
