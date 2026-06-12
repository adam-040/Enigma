#include <ghidra/HighFunction.h>
#include <ghidra/Funcdata.h>

namespace ghidra {

HighFunction::HighFunction(Funcdata* f) : fd(f), name(f ? f->getName() : "") {}

} // namespace ghidra
