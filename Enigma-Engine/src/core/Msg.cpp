/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Msg.cpp
/// \brief Logging and message reporting utility implementation
#include "ghidra/Msg.h"
#include <iostream>

namespace ghidra {

void Msg::out(const std::string& message) {
    std::cerr << message << std::endl;
}

void Msg::trace(const std::string& originator, const std::string& message) {
    std::cout << "[TRACE] " << originator << ": " << message << std::endl;
}

void Msg::trace(const std::string& originator, const std::string& message, const std::exception& e) {
    std::cout << "[TRACE] " << originator << ": " << message << " - " << e.what() << std::endl;
}

void Msg::debug(const std::string& originator, const std::string& message) {
    std::cout << "[DEBUG] " << originator << ": " << message << std::endl;
}

void Msg::debug(const std::string& originator, const std::string& message, const std::exception& e) {
    std::cout << "[DEBUG] " << originator << ": " << message << " - " << e.what() << std::endl;
}

void Msg::info(const std::string& originator, const std::string& message) {
    std::cerr << "[INFO] " << originator << ": " << message << std::endl;
}

void Msg::info(const std::string& originator, const std::string& message, const std::exception& e) {
    std::cerr << "[INFO] " << originator << ": " << message << " - " << e.what() << std::endl;
}

void Msg::showInfo(const std::string& originator, void* parent, const std::string& title, const std::string& message) {
    std::cerr << "[SHOW_INFO] " << title << " (" << originator << "): " << message << std::endl;
}

void Msg::warn(const std::string& originator, const std::string& message) {
    std::cerr << "[WARN] " << originator << ": " << message << std::endl;
}

void Msg::warn(const std::string& originator, const std::string& message, const std::exception& e) {
    std::cerr << "[WARN] " << originator << ": " << message << " - " << e.what() << std::endl;
}

void Msg::showWarn(const std::string& originator, void* parent, const std::string& title, const std::string& message) {
    std::cerr << "[SHOW_WARN] " << title << " (" << originator << "): " << message << std::endl;
}

void Msg::error(const std::string& originator, const std::string& message) {
    std::cerr << "[ERROR] " << originator << ": " << message << std::endl;
}

void Msg::error(const std::string& originator, const std::string& message, const std::exception& e) {
    std::cerr << "[ERROR] " << originator << ": " << message << " - " << e.what() << std::endl;
}

void Msg::showError(const std::string& originator, void* parent, const std::string& title, const std::string& message) {
    std::cerr << "[SHOW_ERROR] " << title << " (" << originator << "): " << message << std::endl;
}

void Msg::showError(const std::string& originator, void* parent, const std::string& title, const std::string& message, const std::exception& e) {
    std::cerr << "[SHOW_ERROR] " << title << " (" << originator << "): " << message << " - " << e.what() << std::endl;
}

} // namespace ghidra
