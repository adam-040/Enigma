#include <ghidra/OperandReferenceAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/Scalar.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/Pointer.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/StackFrame.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefTypeFactory.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/AddressIterator.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>

namespace ghidra {

OperandReferenceAnalyzer::OperandReferenceAnalyzer()
    : AbstractAnalyzer("Reference",
                       "Analyzes data referenced by instructions.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS);
}

OperandReferenceAnalyzer::OperandReferenceAnalyzer(const std::string& name,
                                                     const std::string& description,
                                                     AnalyzerType type)
    : AbstractAnalyzer(name, description, type) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS);
}

bool OperandReferenceAnalyzer::canAnalyze(Program* program) const {
    AddressSpace* defaultSpace =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!defaultSpace) return false;

    // Disable pointer/address table for segmented or ARM
    bool isArm = false;
    auto* listing = program->getListing();
    if (listing) {
        auto* data = listing->getDataAt(program->getMinAddress());
        if (data) {
            // ARM check is processor-dependent
        }
    }

    int bitSize = defaultSpace->getSize();
    return bitSize > 16;
}

bool OperandReferenceAnalyzer::getDefaultEnablement(Program* program) const {
    // Default: enable for PE format, disable otherwise
    std::string format = program->getExecutableFormat();
    return format.find("PE") != std::string::npos;
}

void OperandReferenceAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPT_NAME_ASCII, asciiEnabled_, OPT_NAME_ASCII);
    options.registerBool(OPT_NAME_UNICODE, unicodeEnabled_, OPT_NAME_UNICODE);
    options.registerBool(OPT_NAME_ALIGN_STRINGS, alignStringsEnabled_, OPT_NAME_ALIGN_STRINGS);
    options.registerInt(OPT_NAME_MIN_STRING_LENGTH, minStringLength_, OPT_NAME_MIN_STRING_LENGTH);
    options.registerBool(OPT_NAME_POINTER, pointerEnabled_, OPT_NAME_POINTER);
    options.registerBool(OPT_NAME_RELOCATION_GUIDE, relocationGuideEnabled_, OPT_NAME_RELOCATION_GUIDE);
    options.registerBool(OPT_NAME_SUBROUTINE, subroutinesEnabled_, OPT_NAME_SUBROUTINE);
    options.registerBool(OPT_NAME_ADDRESS_TABLE, addressTablesEnabled_, OPT_NAME_ADDRESS_TABLE);
    options.registerBool(OPT_NAME_SWITCH, switchTableEnabled_, OPT_NAME_SWITCH);
    options.registerInt(OPT_NAME_SWITCH_ALIGNMENT, switchTableAlignment_, OPT_NAME_SWITCH_ALIGNMENT);
    options.registerInt(OPT_NAME_MINIMUM_TABLE_SIZE, minimumAddressTableSize_, OPT_NAME_MINIMUM_TABLE_SIZE);
    options.registerBool(OPT_NAME_RESPECT_EXECUTE, respectExecuteFlags_, OPT_NAME_RESPECT_EXECUTE);
}

void OperandReferenceAnalyzer::optionsChanged(Options& options, Program* program) {
    minStringLength_ = options.getInt(OPT_NAME_MIN_STRING_LENGTH);
    switchTableAlignment_ = options.getInt(OPT_NAME_SWITCH_ALIGNMENT);
    minimumAddressTableSize_ = options.getInt(OPT_NAME_MINIMUM_TABLE_SIZE);
    asciiEnabled_ = options.getBool(OPT_NAME_ASCII);
    unicodeEnabled_ = options.getBool(OPT_NAME_UNICODE);
    alignStringsEnabled_ = options.getBool(OPT_NAME_ALIGN_STRINGS);
    pointerEnabled_ = options.getBool(OPT_NAME_POINTER);
    relocationGuideEnabled_ = options.getBool(OPT_NAME_RELOCATION_GUIDE);
    subroutinesEnabled_ = options.getBool(OPT_NAME_SUBROUTINE);
    addressTablesEnabled_ = options.getBool(OPT_NAME_ADDRESS_TABLE);
    switchTableEnabled_ = options.getBool(OPT_NAME_SWITCH);
    respectExecuteFlags_ = options.getBool(OPT_NAME_RESPECT_EXECUTE);
}

//--------------------------------------------------------------------------
// String detection methods
//--------------------------------------------------------------------------

bool OperandReferenceAnalyzer::isValidRelocationAddress(Program* program, const Address& target) {
    return true; // simplified - relocation table not fully available
}

AddressSet OperandReferenceAnalyzer::getExecuteSet(Memory* memory) {
    AddressSet set;
    auto blocks = memory->getBlocks();
    for (MemoryBlock* block : blocks) {
        if (block->isExecute()) {
            set.addRange(block->getStart(), block->getEnd());
        }
    }
    if (set.isEmpty()) return {};
    return set;
}

bool OperandReferenceAnalyzer::isFunctionPointer(Listing* listing, const Address& fromAddr) {
    Data* fromData = listing->getDataContaining(fromAddr);
    if (!fromData) return false;
    int offset = static_cast<int>(fromAddr.subtract(fromData->getAddress()));
    Data* primitiveAt = fromData->getPrimitiveAt(offset);
    if (!primitiveAt) return false;
    DataType* dt = primitiveAt->getDataType();
    if (!dt) return false;
    auto* ptr = dynamic_cast<Pointer*>(dt);
    if (!ptr) return false;
    return true; // simplified function definition check
}

bool OperandReferenceAnalyzer::hasDataAccessReferences(Program* program, const Address& target) {
    auto refs = program->getReferenceManager()->getReferencesTo(target);
    for (Reference* ref : refs) {
        const RefType* rt = ref->getReferenceType();
        if (rt && (rt->isRead() || rt->isWrite())) {
            return true;
        }
    }
    return false;
}

bool OperandReferenceAnalyzer::shouldBeValidFunction(Program* program, Instruction* targetInstr) {
    Function* func = program->getFunctionManager()->getFunctionContaining(
        targetInstr->getAddress());
    if (func) return false;

    auto refs = program->getReferenceManager()->getReferencesTo(
        targetInstr->getAddress());
    for (Reference* ref : refs) {
        const RefType* rt = ref->getReferenceType();
        if (rt && rt->isFlow()) return false;
        if (rt && (rt->isRead() || rt->isWrite())) return false;
    }
    return true;
}

bool OperandReferenceAnalyzer::checkForExternalJump(Program* program, Reference* reference,
                                                      TaskMonitor* monitor) {
    Address toAddr = reference->getToAddress();
    MemoryBlock* block = program->getMemory()->getBlock(toAddr);
    if (!block || !block->isExternalBlock()) return false;

    Address fromAddr = reference->getFromAddress();
    Instruction* instr = program->getListing()->getInstructionAt(fromAddr);
    if (instr && instr->getFlowType() && instr->getFlowType()->isJump()) {
        instr->setFlowOverride(FlowOverride::CALL_RETURN);
    }

    Function* func = program->getFunctionManager()->getFunctionAt(toAddr);
    if (!func) {
        program->getFunctionManager()->createFunction("", toAddr,
            AddressSet(toAddr, toAddr), SourceType::ANALYSIS);
    }
    return true;
}

bool OperandReferenceAnalyzer::desiredDataMemoryContainsReference(Program* program,
                                                                   const Address& rangeStart,
                                                                   int rangeLength) {
    Address nextAddress = rangeStart.next();
    if (!nextAddress.isValid()) return false;

    auto refs = program->getReferenceManager()->getReferencesTo(nextAddress);
    if (refs.empty()) return false;

    AddressSpace* targetSpace = rangeStart.getAddressSpace();
    for (Reference* ref : refs) {
        Address refAddr = ref->getToAddress();
        if (refAddr.getAddressSpace() == targetSpace) {
            long distance = static_cast<long>(refAddr.subtract(rangeStart));
            if (distance >= 0 && distance < rangeLength) return true;
        }
    }
    return false;
}

int OperandReferenceAnalyzer::getStringLength(Memory* memory, const Address& startAddress,
                                               int stringAlignment) {
    uint8_t bytes[1000];
    int numBytes = memory->getBytes(startAddress, bytes, 1000);
    if (numBytes <= 0) return -1;

    int nullOffset = -1;
    for (int i = 0; i < numBytes; i++) {
        if (bytes[i] == 0) {
            nullOffset = i;
            break;
        }
        uint8_t b = bytes[i];
        if (b >= 0x7f) return -1;
        if (b < 0x20 && b != 0x09 && b != 0x0a && b != 0x0d) return -1;
    }
    if (nullOffset < 0 || nullOffset < minStringLength_) return -1;

    int length = nullOffset + 1;
    if (alignStringsEnabled_) {
        int modAlignment = length % stringAlignment;
        if (modAlignment != 0) {
            int numAlignBytes = stringAlignment - modAlignment;
            length += numAlignBytes;
            if (length > numBytes) return -1;
        }
    }
    return length;
}

int OperandReferenceAnalyzer::getWStrLen(Memory* memory, const Address& addr) {
    for (int i = 0; i < 1000; i++) {
        uint16_t value = memory->getShort(addr.add(2 * i));
        if (value == 0) return i;
        if (value != 0x09 && value != 0x0a && value != 0x0d &&
            (value < 0x20 || value >= 0x7f)) {
            return -1;
        }
    }
    return -1;
}

int OperandReferenceAnalyzer::checkAnsiString(Memory* memory, const Address& addr) {
    int len = getStringLength(memory, addr, processorAlignment_);
    if (len <= 0) return 0;
    return len;
}

int OperandReferenceAnalyzer::checkUnicodeString(Memory* memory, const Address& addr) {
    int len = getWStrLen(memory, addr);
    if (len <= 0) return 0;

    int len2 = getWStrLen(memory, addr.subtract(8));
    if (len2 > len + 2) return 0;

    return (len > 3) ? len : 0;
}

bool OperandReferenceAnalyzer::clearAllUndefined(Program* program, const Address& start,
                                                   int lenBytes) {
    if (lenBytes < 1) return false;

    Address end = start.add(lenBytes - 1);
    if (!end.isValid()) return false;

    // Check that every byte in range is undefined
    Address cur = start;
    while (cur <= end) {
        if (program->getListing()->getInstructionAt(cur)) return false;
        Data* d = program->getListing()->getDataAt(cur);
        if (d && d->isDefined()) return false;
        cur = cur.next();
    }

    // Remove undefined data in range
    cur = start;
    while (cur <= end) {
        Data* d = program->getListing()->getDataAt(cur);
        if (d) program->getListing()->removeData(d->getAddress());
        if (cur == end) break;
        cur = cur.next();
    }
    return true;
}

//--------------------------------------------------------------------------
// Main analysis entry point
//--------------------------------------------------------------------------

bool OperandReferenceAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!asciiEnabled_ && !unicodeEnabled_ && !subroutinesEnabled_) {
        log.append("ASCII, Unicode, and Subroutines are all disabled.");
        return true;
    }

    if (minimumAddressTableSize_ < 2) minimumAddressTableSize_ = 2;

    Listing* listing = program->getListing();
    Memory* memory = program->getMemory();
    ReferenceManager* refMgr = program->getReferenceManager();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!listing || !memory || !refMgr || !funcMgr) return false;

    AddressSet executeSet;
    if (respectExecuteFlags_) {
        executeSet = getExecuteSet(memory);
    }

    int count = 0;
    int nextLogCount = 50000;
    long initialCount = set.getNumAddresses();
    if (monitor) {
        monitor->initialize(initialCount);
        monitor->setMessage("Analyze Operand References " + set.getMinAddress().toString());
    }
    log.append("OperandReferenceAnalyzer: starting analysis of " + std::to_string(initialCount) + " addresses");

    AddressSet leftSet(set);
    AddressSet ignoreNewPointers;
    AddressSet checkedTargets;
    AddressSet disTargets;
    AddressSet foundCodeBookmarkLocations;
    AddressSet doneSubTest;

    // PHASE 6: safety counters
    int stackRefIterations_ = 0;
    int stackRefAnomalies_ = 0;
    int mainLoopIterations_ = 0;
    int disTargetsIterations_ = 0;
    int disTargetsAnomalies_ = 0;

    // Create stack references from scalar operands referencing function stack frames
    {
        auto instrs = listing->getInstructions(set);
        for (Instruction* instr : instrs) {
            if (monitor && monitor->isCancelled()) break;
            ++stackRefIterations_;

            Function* func = funcMgr->getFunctionContaining(instr->getMinAddress());
            if (!func) continue;

            StackFrame* frame = func->getStackFrame();
            if (!frame || frame->getFrameSize() <= 0) continue;

            int localSize = frame->getLocalSize();
            int stackSize = frame->getFrameSize();

            for (int opIdx = 0; opIdx < instr->getNumOperands(); ++opIdx) {
                auto scalars = instr->getOperandScalars(opIdx);
                for (Scalar* scalar : scalars) {
                    long val = static_cast<long>(scalar->getSignedValue());
                    if (val >= 0) continue;
                    int stackOff = static_cast<int>(val);
                    if (stackOff < -stackSize || stackOff >= 0) {
                        ++stackRefAnomalies_;
                        continue;
                    }
                    if (!instr->getOperandReferences(opIdx).empty()) continue;

                    refMgr->addStackReference(instr->getMinAddress(), opIdx, stackOff,
                                               &RefTypes::READ, SourceType::ANALYSIS);
                }
            }
        }
        if (stackRefAnomalies_ > 0) {
            std::cerr << "[WARN] OperandReferenceAnalyzer: stack ref anomalies=" << stackRefAnomalies_
                      << " iterations=" << stackRefIterations_ << std::endl;
        }
    }

    auto addrIter = refMgr->getReferenceSourceIterator(set, true);
    int mainLoopHardLimit_ = 50000;  // will test 100K/200K/300K/500K
    std::cerr << "[INFO] OperandReferenceAnalyzer: starting main loop" << std::endl;
    while (addrIter->hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        ++mainLoopIterations_;
        if (mainLoopIterations_ > mainLoopHardLimit_) {
            std::cerr << "[WARN] OperandReferenceAnalyzer: main loop exceeded "
                      << mainLoopHardLimit_ << " iterations, breaking" << std::endl;
            break;
        }
        if (mainLoopIterations_ % 1000 == 0) {
            std::cerr << "[INFO] OperandReferenceAnalyzer: main loop iter=" << mainLoopIterations_ << std::endl;
        }

        Address addr = addrIter->next();

        count++;
        if (count >= NOTIFICATION_INTERVAL) {
            leftSet.deleteRange(leftSet.getMinAddress(), addr);
            int processed = static_cast<int>(initialCount - leftSet.getNumAddresses());
            if (monitor) {
                monitor->setProgress(processed);
                monitor->setMessage("Analyze OpRefs : " + addr.toString());
            }
            if (processed >= nextLogCount) {
                std::cerr << "[INFO] OperandReferenceAnalyzer: processed " << processed << " addresses" << std::endl;
                nextLogCount += 50000;
            }
            count = 0;
        }

        if (ignoreNewPointers.contains(addr)) continue;

        CodeUnit* cu = listing->getCodeUnitContaining(addr);
        if (!cu) continue;

        // Get all references coming from this code unit
        auto memRefs = cu->getReferencesFrom();
        ignoreNewPointers.addRange(cu->getAddress(), cu->getMaxAddress());

        for (size_t m = 0; m < memRefs.size(); m++) {
            if (monitor && monitor->isCancelled()) break;

            Reference* reference = memRefs[m];
            if (!reference) continue;

            Address target = reference->getToAddress();

            const RefType* memRefType = reference->getReferenceType();

            // Handle flow references (jumps/calls)
            if (memRefType && memRefType->isFlow() && !memRefType->isIndirect() &&
                !dynamic_cast<Data*>(cu)) {

                if (memRefType->isCall() && memRefType->isComputed()) {
                    Function* func = funcMgr->getFunctionAt(target);
                    if (!func) {
                        // Schedule function analysis - simplified: just create function
                        funcMgr->createFunction("", target, AddressSet(target, target),
                                                 SourceType::ANALYSIS);
                    }
                }

                if (memRefType->isJump()) {
                    checkForExternalJump(program, reference, monitor);
                }

                // Check for thunks
                if (memRefType->isComputed() && memRefs.size() <= 2) {
                    if (memRefType->isCall()) {
                        auto* instr = dynamic_cast<Instruction*>(cu);
                        if (instr && instr->getFlowType() &&
                            instr->getFlowType()->isComputed() &&
                            !instr->getFlowType()->isTerminal()) {
                            continue; // not a CALL_TERMINATOR
                        }
                    }
                    Function* func = funcMgr->getFunctionContaining(
                        reference->getFromAddress());
                    if (func && !func->isThunk()) {
                        // Simplified thunk check - would need CreateThunkFunctionCmd
                        // Just mark as potential thunk via bookmark
                        program->getBookmarkManager()->setBookmark(
                            target, "ANALYSIS", "Potential Thunk");
                    }
                }
                continue;
            }

            // Skip already-checked targets
            if (checkedTargets.contains(target)) continue;
            checkedTargets.add(target);

            if (!reference->isMemoryReference()) continue;

            // Check if target is in memory
            MemoryBlock* block = memory->getBlock(target);
            if (!block) continue;

            if (ignoreNewPointers.contains(target)) continue;

            // Check if something is already defined at target
            bool stuffDefined = false;
            bool isUndefinedStuff = false;
            Data* data = listing->getDefinedDataContaining(target);
    if (data) {
        DataType* dt = data->getDataType();
        stuffDefined = true;
        if (data->isString() || data->isPointer()) {
            // keep processing
        } else if (dt && (dt->getName().find("undefined") != std::string::npos ||
                          dt->getName().find("Undefined") != std::string::npos)) {
            isUndefinedStuff = true;
        } else {
            continue;
        }
            } else {
                Instruction* targetInstr = listing->getInstructionContaining(target);
                if (targetInstr) {
                    doneSubTest.addRange(targetInstr->getMinAddress(),
                                          targetInstr->getMaxAddress());
                    auto* instrCu = dynamic_cast<Instruction*>(cu);
                    if (instrCu) {
                        if (!instrCu->getFlowType() || !instrCu->getFlowType()->isComputed()) {
                            if (shouldBeValidFunction(program, targetInstr)) {
                                disTargets.addRange(target, target);
                            }
                            continue;
                        }
                    } else {
                        if (shouldBeValidFunction(program, targetInstr)) {
                            disTargets.addRange(target, target);
                        }
                        continue;
                    }
                }
            }

            // Check for address tables (stubbed without AddressTable class)
            bool newCodeFound = false;
            auto* instrCu = dynamic_cast<Instruction*>(cu);
            if (instrCu && addressTablesEnabled_) {
                FlowType* ftype = instrCu->getFlowType();
                if (ftype && ((ftype->isJump() || ftype->isCall()) && ftype->isComputed())) {
                    if (ftype->isComputed() && instrCu->getNumOperands() == 1) {
                        auto scalars = instrCu->getOperandScalars(reference->getOperandIndex());
                        for (Scalar* s : scalars) {
                            if (s) {
                                // Address table detection blocked: needs AddressTable class
                                program->getBookmarkManager()->setBookmark(
                                    target, "ANALYSIS", "Potential Address Table");
                                break;
                            }
                        }
                    }
                }
            }

            if (newCodeFound) {
                leftSet = AddressSet(set);
                leftSet.deleteRange(leftSet.getMinAddress(), addr);
                leftSet.addRange(addr, addr);
                break;
            }

            // Subroutine detection
            if (subroutinesEnabled_ && !isUndefinedStuff && !doneSubTest.contains(target)) {
                const RefType* refType = reference->getReferenceType();
                bool isReadWrite = refType && (refType->isRead() || refType->isWrite());
                if (!isReadWrite && !hasDataAccessReferences(program, target)) {
                    auto* instr = dynamic_cast<Instruction*>(cu);
                    if (instr && instr->getFlowType() &&
                        (instr->getFlowType()->isJump() || instr->getFlowType()->isCall())) {
                        continue;
                    }
                    if (!instr) {
                        // Data reference - check if it could be code
                        doneSubTest.addRange(target, target);
                        // Simplified: no PseudoDisassembler available
                        if (executeSet.isEmpty() || executeSet.contains(target) ||
                            isFunctionPointer(listing, reference->getFromAddress())) {
                            disTargets.addRange(target, target);
                        }
                    } else {
                        // Instruction reference that's not directly jumped to
                        doneSubTest.addRange(target, target);
                        if (executeSet.isEmpty() || executeSet.contains(target) ||
                            isFunctionPointer(listing, reference->getFromAddress())) {
                            foundCodeBookmarkLocations.addRange(target, target);
                            disTargets.addRange(target, target);
                        }
                    }
                }
            }

            if (stuffDefined && !isUndefinedStuff) continue;

            // ASCII string detection
            if (asciiEnabled_) {
                int asciiLen = checkAnsiString(memory, target);
                if (asciiLen > 0) {
                    if (!desiredDataMemoryContainsReference(program, target, asciiLen) &&
                        clearAllUndefined(program, target, asciiLen)) {
                        listing->createData(target, nullptr, asciiLen);
                        program->getBookmarkManager()->setBookmark(
                            target, "ANALYSIS", "ASCII");
                    }
                    continue;
                }
            }

            // Unicode string detection
            if (unicodeEnabled_) {
                int uniLen = checkUnicodeString(memory, target);
                if (uniLen > 0) {
                    if (!desiredDataMemoryContainsReference(program, target, 2 * (uniLen + 1)) &&
                        clearAllUndefined(program, target, 2 * (uniLen + 1))) {
                        listing->createData(target, nullptr, 2 * (uniLen + 1));
                        program->getBookmarkManager()->setBookmark(
                            target, "ANALYSIS", "Unicode");
                    }
                    continue;
                }
            }

            // Pointer detection
            if (pointerEnabled_ && !disTargets.contains(target)) {
                if (!isValidRelocationAddress(program, target)) continue;

                uint8_t buf[8] = {};
                int ptrSize = program->getDefaultPointerSize();
                int bytesRead = memory->getBytes(target, buf, ptrSize);
                if (bytesRead < ptrSize) continue;

                uint64_t val = 0;
                if (memory->isBigEndian()) {
                    for (int j = 0; j < ptrSize; j++)
                        val = (val << 8) | buf[j];
                } else {
                    for (int j = ptrSize - 1; j >= 0; j--)
                        val = (val << 8) | buf[j];
                }

                if (val == 0 || val < 4096) continue;
                if (val % static_cast<uint64_t>(switchTableAlignment_) != 0) continue;

                AddressSpace* defSpace =
                    const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
                Address testAddr(defSpace, static_cast<int64_t>(val));

                MemoryBlock* targetBlock = memory->getBlock(testAddr);
                if (!targetBlock) {
                    Symbol* sym = program->getSymbolTable()->getPrimarySymbol(testAddr);
                    if (!sym || sym->getSource() == SourceType::DEFAULT) continue;
                }

                if (desiredDataMemoryContainsReference(program, target, ptrSize)) continue;

                CodeUnit* targetCu = listing->getCodeUnitContaining(testAddr);
                if (targetCu && !(targetCu->getAddress() == testAddr)) continue;

                if (targetCu && dynamic_cast<Instruction*>(targetCu)) {
                    auto* targetInstr = dynamic_cast<Instruction*>(targetCu);
                    if (targetInstr->isInDelaySlot()) continue;
                    Address fallFrom = targetInstr->getFallFrom();
                    if (fallFrom.isValid()) {
                        if (!funcMgr->getFunctionAt(targetInstr->getAddress())) continue;
                    } else {
                        Function* targetFunc = funcMgr->getFunctionContaining(testAddr);
                        if (targetFunc && !(targetFunc->getEntryPoint() == testAddr)) continue;
                    }
                }

                if (clearAllUndefined(program, target, ptrSize)) {
                    DataType* ptrType = program->getDataTypeManager()->getPointer(nullptr, ptrSize);
                    listing->createData(target, ptrType, ptrSize);
                }
                continue;
            }
        }
    }

    // Remove disTargets that have defined data
    AddressSet throwOutSet;
    AddressSet doneDisSet;
    auto disIter = disTargets.getAddressRanges(true);
    while (disIter->hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        const AddressRange& range = disIter->next();
        Address rAddr = range.getMinAddress();
        while (rAddr <= range.getMaxAddress()) {
            ++disTargetsIterations_;
            // PHASE 6: anomaly detection — bail out if iterations explode
            if (disTargetsIterations_ > 100000) {
                ++disTargetsAnomalies_;
                std::cerr << "[WARN] OperandReferenceAnalyzer: disTargets iterations exceeded 100K at "
                          << rAddr.toString() << std::endl;
                break;
            }
            Data* d = listing->getDataContaining(rAddr);
            if (d) {
                if (d->isDefined()) throwOutSet.add(rAddr);
            } else {
                Instruction* ins = listing->getInstructionContaining(rAddr);
                if (ins) doneDisSet.add(rAddr);
            }
            if (rAddr == range.getMaxAddress()) break;
            rAddr = rAddr.next();
        }
    }
    AddressSet doDisTargets = disTargets.subtract(throwOutSet);
    doDisTargets = doDisTargets.subtract(doneDisSet);

    // Create functions at discovered targets
    if (!doDisTargets.isEmpty()) {
        auto funcIter = doDisTargets.getAddressRanges(true);
        while (funcIter->hasNext()) {
            if (monitor && monitor->isCancelled()) break;
            const AddressRange& range = funcIter->next();
            Address rAddr = range.getMinAddress();
            while (rAddr <= range.getMaxAddress()) {
                if (!funcMgr->getFunctionAt(rAddr)) {
                    funcMgr->createFunction("", rAddr, AddressSet(rAddr, rAddr),
                                             SourceType::ANALYSIS);
                }
                if (rAddr == range.getMaxAddress()) break;
                rAddr = rAddr.next();
            }
        }

        // Add bookmarks for found code
        foundCodeBookmarkLocations = foundCodeBookmarkLocations.subtract(throwOutSet);
        auto foundIter = foundCodeBookmarkLocations.getAddressRanges(true);
        while (foundIter->hasNext()) {
            if (monitor && monitor->isCancelled()) break;
            const AddressRange& range = foundIter->next();
            Address rAddr = range.getMinAddress();
            while (rAddr <= range.getMaxAddress()) {
                program->getBookmarkManager()->setBookmark(
                    rAddr, "ANALYSIS", "Found code from operand reference");
                if (rAddr == range.getMaxAddress()) break;
                rAddr = rAddr.next();
            }
        }
    }

    if (mainLoopIterations_ > 0) {
        std::cerr << "[INFO] OperandReferenceAnalyzer: mainLoop=" << mainLoopIterations_
                  << " disTargetsIter=" << disTargetsIterations_
                  << " disTargetsAnomalies=" << disTargetsAnomalies_ << std::endl;
    }

    return true;
}

} // namespace ghidra
