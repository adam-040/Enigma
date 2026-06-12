#include <ghidra/Translate.h>

namespace ghidra {

Translate::Translate(LoadImage* ld, int4 ptrSize, bool endian)
    : loader(ld), pointerSize(ptrSize), bigEndian(endian), codeAlign(1) {
    stats = TranslateStats();
}

void Translate::setDefaultFloatFormats() {
  if (floatformats.empty()) {
    floatformats.push_back(FloatFormat(4));
    floatformats.push_back(FloatFormat(8));
  }
}

const FloatFormat* Translate::getFloatFormat(int4 size) const {
  for (const auto& ff : floatformats) {
    if (ff.getSize() == size)
      return &ff;
  }
  return nullptr;
}

} // namespace ghidra
