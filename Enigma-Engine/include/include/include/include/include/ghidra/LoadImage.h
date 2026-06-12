#pragma once

#include <ghidra/Address.h>
#include <vector>
#include <cstdint>
#include <string>

namespace ghidra {

typedef uint8_t uint1;
typedef int32_t int4;

class LoadImage {
public:
    virtual ~LoadImage() = default;
    virtual void loadFill(uint1* ptr, int4 size, const Address& addr) = 0;
    virtual std::string getArchType() const = 0;
    virtual void adjustVma(long adjust) = 0;
    virtual void applyRelocations(uint1* img, int4 size, const Address& baseAddr) = 0;
};

class LoadImageBindArray : public LoadImage {
private:
    struct Section {
        std::vector<uint1> data;
        Address baseAddr;
        int4 size;
    };
    std::vector<Section> sections;

public:
    LoadImageBindArray() = default;
    ~LoadImageBindArray() override = default;

    void addSection(const Address& baseAddr, const uint1* data, int4 size);
    void loadFill(uint1* ptr, int4 size, const Address& addr) override;
    std::string getArchType() const override { return "bindarray"; }
    void adjustVma(long adjust) override;
    void applyRelocations(uint1* img, int4 size, const Address& baseAddr) override;
};

class LoadImageRawFile : public LoadImage {
private:
    std::vector<uint1> fileData;
    Address baseAddr;
    std::string archType;

public:
    LoadImageRawFile(const std::string& filename, const Address& base, const std::string& arch);
    ~LoadImageRawFile() override = default;

    void loadFill(uint1* ptr, int4 size, const Address& addr) override;
    std::string getArchType() const override { return archType; }
    void adjustVma(long adjust) override;
    void applyRelocations(uint1* img, int4 size, const Address& baseAddr) override;
    const std::vector<uint1>& getData() const { return fileData; }
    int4 getSize() const { return static_cast<int4>(fileData.size()); }
};

} // namespace ghidra
