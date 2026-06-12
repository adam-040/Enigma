#pragma once

#include <ghidra/PcodeOp.h>
#include <ghidra/PcodeBlockBasic.h>
#include <list>
#include <any>

namespace ghidra {

class PcodeOpAST : public PcodeOp {
private:
    bool bDead;
    PcodeBlockBasic* parent;                                     // لا يملكه
    std::list<PcodeOpAST*>::iterator basiciter;                  // موقع العملية داخل البلوك
    std::list<PcodeOpAST*>::iterator insertiter;                 // موقع الإدراج

public:
    PcodeOpAST(const SequenceNumber& sq, int op, int numinputs);
    PcodeOpAST(const Address& a, int uq, int op, int numinputs);
    ~PcodeOpAST() = default;

    bool isDead() const;
    void setDead(bool val) { bDead = val; }
    PcodeBlockBasic* getParent() const;
    
    std::list<PcodeOpAST*>::iterator getBasicIter() const;
    std::list<PcodeOpAST*>::iterator getInsertIter() const;

    void setParent(PcodeBlockBasic* par);
    void setBasicIter(std::list<PcodeOpAST*>::iterator iter);
    void setInsertIter(std::list<PcodeOpAST*>::iterator iter);
};

} // namespace ghidra