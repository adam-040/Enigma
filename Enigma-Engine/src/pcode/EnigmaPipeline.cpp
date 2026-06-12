#include <ghidra/EnigmaPipeline.h>
#include <ghidra/AddrSpace.h>
#include <ghidra/BlockGraph.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/FlowInfo.h>
#include <ghidra/Heritage.h>
#include <ghidra/ActionManager.h>
#include <ghidra/PrintLanguage.h>
#include <sstream>

namespace ghidra {

EnigmaPipeline::EnigmaPipeline()
    : bitness_(64), baseAddr_(0x1000), loaded_(false) {
}

EnigmaPipeline::~EnigmaPipeline() = default;

void EnigmaPipeline::setArchitecture(const std::string& arch, int bitness) {
    arch_ = arch;
    bitness_ = bitness;
}

void EnigmaPipeline::setBaseAddress(uint64_t base) {
    baseAddr_ = base;
}

bool EnigmaPipeline::loadBinary(const std::string& path) {
    GenericAddressSpace codeSpace("ram", bitness_, AddressSpace::TYPE_RAM, 0);
    Address baseAddr(&codeSpace, static_cast<int64_t>(baseAddr_));

    loader_ = std::make_unique<LoadImageRawFile>(path, baseAddr, arch_);
    if (loader_->getSize() == 0) {
        return false;
    }

    sleigh_ = std::make_unique<Sleigh>(loader_.get(), "");
    sleigh_->setArchitecture(arch_, bitness_);
    if (!sleigh_->initialize()) {
        return false;
    }

    loaded_ = true;
    return true;
}

bool EnigmaPipeline::decompile() {
    if (!loaded_ || !sleigh_) return false;

    GenericAddressSpace codeSpace("ram", bitness_, AddressSpace::TYPE_RAM, 0);
    Address entryAddr(&codeSpace, static_cast<int64_t>(baseAddr_));

    fd_ = std::make_unique<Funcdata>("decompiled_func", entryAddr);

    // Disassemble the entire binary range
    const auto& data = loader_->getData();
    int4 totalSize = loader_->getSize();
    uint64_t currentAddr = baseAddr_;

    int maxInstructions = 1000; // safety limit
    int count = 0;

    while (currentAddr < baseAddr_ + static_cast<uint64_t>(totalSize) && count < maxInstructions) {
        Address instAddr(&codeSpace, static_cast<int64_t>(currentAddr));
        int4 length = 0;
        try {
            length = sleigh_->oneInstruction(*fd_, instAddr);
        } catch (const std::exception& e) {
            std::string err = e.what();
            std::cerr << "Crash at addr 0x" << std::hex << currentAddr
                      << std::dec << " (offset " << (currentAddr - baseAddr_)
                      << "): " << err << "\n";
            break;
        }
        if (length <= 0) {
            break;
        }
        currentAddr += static_cast<uint64_t>(length);
        count++;
    }

    // Build CFG from pcode ops
    auto* bgraph = fd_->getBlockGraph();
    std::vector<FuncCallSpecs*> callList;
    FlowInfo flowInfo(*fd_, *bgraph, callList);
    flowInfo.setRange(entryAddr, entryAddr.add(totalSize > 0 ? totalSize : 0x100000));
    flowInfo.setMaximumInstructions(maxInstructions);
    flowInfo.generateOps();
    flowInfo.generateBlocks();

    // Compute forward dominators (required for SSA phi placement)
    if (bgraph) {
        bgraph->computeDominators();
    }

    // Build SSA form (phi insertion + variable renaming)
    // Must run BEFORE computePostDominators because Heritage reads domChildren_
    Heritage heritage(fd_.get());
    heritage.initialize();
    heritage.execute();

    // Post-dominators (after SSA — used for dead code elimination, etc.)
    if (bgraph) {
        bgraph->computePostDominators();
    }

    // Run analysis actions (constant folding, copy propagation, dead code elim, etc.)
    ActionManager actionMgr(nullptr);
    actionMgr.initialize();
    actionMgr.execute(*fd_);

    printer_ = std::make_unique<PrintC>();
    printer_->reset();
    printer_->printFuncdata(*fd_);
    output_ = printer_->getBuffer();

    return true;
}

std::string EnigmaPipeline::getOutput() const {
    return output_;
}

} // namespace ghidra
