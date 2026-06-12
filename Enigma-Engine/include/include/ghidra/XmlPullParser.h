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
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace ghidra {

class XmlElement {
public:
    XmlElement() = default;
    explicit XmlElement(const std::string& name) : name_(name), isEnd_(false), isText_(false) {}

    const std::string& getName() const { return name_; }
    std::string getAttribute(const std::string& key) const {
        auto it = attributes_.find(key);
        return (it != attributes_.end()) ? it->second : "";
    }
    void setAttribute(const std::string& key, const std::string& value) {
        attributes_[key] = value;
    }
    const std::map<std::string, std::string>& getAttributes() const { return attributes_; }

    bool isEnd() const { return isEnd_; }
    void setIsEnd(bool val) { isEnd_ = val; }

    bool isText() const { return isText_; }
    void setIsText(bool val) { isText_ = val; }

    const std::string& getText() const { return text_; }
    void setText(const std::string& text) {
        text_ = text;
        isText_ = true;
    }

private:
    std::string name_;
    std::map<std::string, std::string> attributes_;
    bool isEnd_ = false;
    bool isText_ = false;
    std::string text_;
};

class XmlPullParser {
public:
    XmlPullParser() = default;
    explicit XmlPullParser(const std::string& source) : source_(source), index_(0) {
        parse();
    }

    bool hasNext() const {
        return index_ < elements_.size();
    }

    XmlElement nextElement() {
        if (!hasNext()) {
            return XmlElement("");
        }
        return elements_[index_++];
    }

    const XmlElement& peek() const {
        if (!hasNext()) {
            static const XmlElement empty("");
            return empty;
        }
        return elements_[index_];
    }

    const std::string& getSource() const { return source_; }

private:
    std::string source_;
    std::vector<XmlElement> elements_;
    size_t index_ = 0;

    static std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

    static std::string unescapeXml(const std::string& str) {
        std::string result;
        result.reserve(str.size());
        for (size_t i = 0; i < str.size(); ) {
            if (str[i] == '&') {
                if (str.compare(i, 5, "&amp;") == 0) {
                    result += '&';
                    i += 5;
                } else if (str.compare(i, 4, "&lt;") == 0) {
                    result += '<';
                    i += 4;
                } else if (str.compare(i, 4, "&gt;") == 0) {
                    result += '>';
                    i += 4;
                } else if (str.compare(i, 6, "&quot;") == 0) {
                    result += '"';
                    i += 6;
                } else if (str.compare(i, 6, "&apos;") == 0) {
                    result += '\'';
                    i += 6;
                } else {
                    result += str[i];
                    i++;
                }
            } else {
                result += str[i];
                i++;
            }
        }
        return result;
    }

    XmlElement parseTagContent(const std::string& content) {
        size_t i = 0;
        while (i < content.size() && std::isspace((unsigned char)content[i])) i++;
        size_t start = i;
        while (i < content.size() && !std::isspace((unsigned char)content[i])) i++;
        std::string name = content.substr(start, i - start);

        XmlElement elem(name);

        while (i < content.size()) {
            while (i < content.size() && std::isspace((unsigned char)content[i])) i++;
            if (i >= content.size()) break;

            size_t keyStart = i;
            while (i < content.size() && content[i] != '=' && !std::isspace((unsigned char)content[i])) i++;
            std::string key = content.substr(keyStart, i - keyStart);

            while (i < content.size() && std::isspace((unsigned char)content[i])) i++;
            if (i < content.size() && content[i] == '=') {
                i++; // skip '='
                while (i < content.size() && std::isspace((unsigned char)content[i])) i++;
                if (i < content.size() && (content[i] == '"' || content[i] == '\'')) {
                    char quote = content[i];
                    i++; // skip quote
                    size_t valStart = i;
                    while (i < content.size() && content[i] != quote) i++;
                    std::string val = content.substr(valStart, i - valStart);
                    if (i < content.size()) i++; // skip quote
                    elem.setAttribute(key, unescapeXml(val));
                } else {
                    size_t valStart = i;
                    while (i < content.size() && !std::isspace((unsigned char)content[i])) i++;
                    std::string val = content.substr(valStart, i - valStart);
                    elem.setAttribute(key, unescapeXml(val));
                }
            }
        }
        return elem;
    }

    void parse() {
        size_t i = 0;
        std::vector<size_t> parseStack;
        while (i < source_.size()) {
            if (source_[i] == '<') {
                if (i + 1 < source_.size() && source_[i+1] == '?') {
                    size_t end = source_.find("?>", i);
                    if (end == std::string::npos) break;
                    i = end + 2;
                } else if (i + 4 < source_.size() && source_.compare(i, 4, "<!--") == 0) {
                    size_t end = source_.find("-->", i);
                    if (end == std::string::npos) break;
                    i = end + 3;
                } else if (i + 1 < source_.size() && source_[i+1] == '/') {
                    size_t end = source_.find('>', i);
                    if (end == std::string::npos) break;
                    std::string name = source_.substr(i + 2, end - (i + 2));
                    name = trim(name);
                    XmlElement elem(name);
                    elem.setIsEnd(true);
                    elements_.push_back(elem);
                    if (!parseStack.empty()) {
                        parseStack.pop_back();
                    }
                    i = end + 1;
                } else {
                    size_t end = source_.find('>', i);
                    if (end == std::string::npos) break;
                    bool selfClosing = false;
                    size_t len = end - i - 1;
                    if (source_[end - 1] == '/') {
                        selfClosing = true;
                        len--;
                    }
                    std::string content = source_.substr(i + 1, len);
                    XmlElement elem = parseTagContent(content);
                    size_t elemIdx = elements_.size();
                    elements_.push_back(elem);
                    if (selfClosing) {
                        XmlElement endElem(elem.getName());
                        endElem.setIsEnd(true);
                        elements_.push_back(endElem);
                    } else {
                        parseStack.push_back(elemIdx);
                    }
                    i = end + 1;
                }
            } else {
                size_t end = source_.find('<', i);
                std::string text;
                if (end == std::string::npos) {
                    text = source_.substr(i);
                    i = source_.size();
                } else {
                    text = source_.substr(i, end - i);
                    i = end;
                }
                text = trim(text);
                if (!text.empty() && !parseStack.empty()) {
                    std::string currentText = elements_[parseStack.back()].getText();
                    if (!currentText.empty()) currentText += " ";
                    elements_[parseStack.back()].setText(currentText + unescapeXml(text));
                }
            }
        }
    }
};

} // namespace ghidra
