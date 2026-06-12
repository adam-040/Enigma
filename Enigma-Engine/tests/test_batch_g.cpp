/**
 * Enigma Engine - Batch G (model.pcode VarnodeBank + PcodeOpBank + PcodeSyntaxTree) Test
 * Smoke tests for VarnodeBank, PcodeOpBank, and PcodeSyntaxTree.
 */
#include <ghidra/Varnode.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/VarnodeBank.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/PcodeOpBank.h>
#include <ghidra/PcodeSyntaxTree.h>
#include <ghidra/SequenceNumber.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/DefaultAddressFactory.h>
#include <iostream>
#include <stdexcept>
#include <cstring>

using namespace ghidra;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

int main() {
    std::cout << "=== Batch G (model.pcode Varnode/PcodeOp Banks + SyntaxTree) Test ===\n";

    GenericAddressSpace ramSpace("ram", 32, AddressSpace::TYPE_RAM, 0);
    GenericAddressSpace constSpace("const", 32, AddressSpace::TYPE_CONSTANT, 1);
    Address a0(&ramSpace, 0x100);
    Address a1(&ramSpace, 0x200);
    Address a2(&ramSpace, 0x300);

    {
        VarnodeBank vb;
        TEST("VarnodeBank empty initially", vb.isEmpty());
        Varnode* v0 = vb.create(4, a0, 100);
        Varnode* v1 = vb.create(4, a1, 101);
        TEST("VarnodeBank size 2", vb.size() == 2);
        TEST("VarnodeBank not empty", !vb.isEmpty());
        TEST("VarnodeBank v0 uniqueId", static_cast<VarnodeAST*>(v0)->getUniqueId() == 100);
        TEST("VarnodeBank v1 uniqueId", static_cast<VarnodeAST*>(v1)->getUniqueId() == 101);
        TEST("VarnodeBank v0 size", v0->getSize() == 4);

        auto range = vb.locRange();
        TEST("VarnodeBank locRange size", range.size() == 2);
        TEST("VarnodeBank locRange[0] == v0", range[0] == v0);

        Varnode* found = vb.findInput(4, a0);
        TEST("VarnodeBank findInput missing", found == nullptr);

        Varnode* input = vb.setInput(v0);
        TEST("VarnodeBank setInput non-null", input != nullptr);
        TEST("VarnodeBank setInput isInput", input->isInput());

        Varnode* found2 = vb.findInput(4, a0);
        TEST("VarnodeBank findInput after setInput", found2 != nullptr);
        TEST("VarnodeBank findInput same addr", found2->getAddress() == a0);

        vb.makeFree(found2);
        TEST("VarnodeBank makeFree isFree", v0->isFree());
        TEST("VarnodeBank makeFree not isInput", !v0->isInput());

        vb.destroy(v0);
        TEST("VarnodeBank destroy size 1", vb.size() == 1);

        vb.clear();
        TEST("VarnodeBank clear empty", vb.isEmpty());
    }

    {
        VarnodeBank vb;
        Varnode* v0 = vb.create(4, a0, 0);
        Varnode* v1 = vb.create(4, a1, 1);
        Varnode* v2 = vb.create(4, a2, 2);
        auto range = vb.locRange(a1);
        TEST("VarnodeBank locRange(addr) 1", range.size() == 1);
        TEST("VarnodeBank locRange(addr)[0] == v1", range[0] == v1);

        auto range2 = vb.locRange(a0, a2);
        TEST("VarnodeBank locRange(min,max) 3", range2.size() == 3);

        Varnode* v0_again = vb.create(4, a0, 1);
        TEST("VarnodeBank create second distinct", v0_again != nullptr);
        TEST("VarnodeBank create second size", vb.size() == 4);
    }

    {
        DefaultAddressFactory factory;
        factory.addAddressSpace(&ramSpace);

        PcodeOpBank ob;
        TEST("PcodeOpBank empty initially", ob.isEmpty());
        Address pc(&ramSpace, 0x1000);
        PcodeOp* op0 = ob.create(PcodeOp::INT_ADD, 2, pc);
        TEST("PcodeOpBank create returns op", op0 != nullptr);
        TEST("PcodeOpBank size 1", ob.size() == 1);
        TEST("PcodeOpBank op seqnum uniq", op0->getSeqnum().getTime() == 0);

        PcodeOp* op1 = ob.create(PcodeOp::INT_ADD, 2, pc);
        TEST("PcodeOpBank op1 uniq 1", op1->getSeqnum().getTime() == 1);

        SequenceNumber sq(pc, 5);
        PcodeOp* op2 = ob.create(PcodeOp::COPY, 1, sq);
        TEST("PcodeOpBank op2 uniq 5", op2->getSeqnum().getTime() == 5);
        PcodeOp* op3 = ob.create(PcodeOp::COPY, 1, pc);
        TEST("PcodeOpBank op3 uniq > 5", op3->getSeqnum().getTime() > 5);

        TEST("PcodeOpBank findOp by sq", ob.findOp(sq) == op2);

        auto all = ob.allOrdered();
        TEST("PcodeOpBank allOrdered size 4", all.size() == 4);

        ob.markAlive(op0);
        TEST("PcodeOpBank op0 alive", !static_cast<PcodeOpAST*>(op0)->isDead());
        auto alive = ob.allAlive();
        TEST("PcodeOpBank allAlive size 1", alive.size() == 1);

        ob.markDead(op0);
        TEST("PcodeOpBank op0 dead", static_cast<PcodeOpAST*>(op0)->isDead());

        ob.changeOpcode(op0, PcodeOp::INT_SUB);
        TEST("PcodeOpBank changeOpcode", op0->getOpcode() == PcodeOp::INT_SUB);

        ob.destroy(op0);
        TEST("PcodeOpBank destroy size 3", ob.size() == 3);

        ob.clear();
        TEST("PcodeOpBank clear empty", ob.isEmpty());
    }

    {
        DefaultAddressFactory factory;
        factory.addAddressSpace(&ramSpace);
        factory.addAddressSpace(&constSpace);

        PcodeSyntaxTree st(&factory);
        TEST("PST empty numVarnodes", st.getNumVarnodes() == 0);

        Varnode* v0 = st.newVarnode(4, a0);
        Varnode* v1 = st.newVarnode(4, a1);
        Varnode* c0 = st.newVarnode(4, Address(&constSpace, 0));
        TEST("PST numVarnodes 3", st.getNumVarnodes() == 3);
        TEST("PST v0 isFree", v0->isFree());

        Address pc(&ramSpace, 0x1000);
        SequenceNumber sq(pc, 0);
        std::vector<Varnode*> inputs = {v1, c0};
        PcodeOp* op = st.newOp(sq, PcodeOp::INT_ADD, inputs, v0);
        TEST("PST newOp returns op", op != nullptr);
        TEST("PST newOp inputs num", op->getNumInputs() == 2);
        TEST("PST newOp output", op->getOutput() == v0);

        PcodeOp* def = static_cast<VarnodeAST*>(v0)->getDef();
        TEST("PST v0 def == op", def == op);

        PcodeOp* found = st.getPcodeOp(sq);
        TEST("PST getPcodeOp", found == op);

        PcodeOp* opref = st.getOpRef(0);
        TEST("PST getOpRef", opref == op);

        auto ops = st.getPcodeOps();
        TEST("PST getPcodeOps size 1", ops.size() == 1);

        PcodeOpAST* opast = static_cast<PcodeOpAST*>(op);
        TEST("PST opast isDead", !opast->isDead());

        st.setOpcode(op, PcodeOp::INT_SUB);
        TEST("PST setOpcode", op->getOpcode() == PcodeOp::INT_SUB);

        st.unSetOutput(op);
        TEST("PST unSetOutput null", op->getOutput() == nullptr);

        st.unlink(opast);
        TEST("PST unlink v0 free", v0->isFree());

        st.deleteOp(op);
        TEST("PST deleteOp size 0 ops", st.getPcodeOps().size() == 0);

        Varnode* in0 = st.setInput(v0, true);
        TEST("PST setInput v0", in0 != nullptr);
        TEST("PST setInput isInput", in0->isInput());

        st.clear();
        TEST("PST clear numVarnodes 0", st.getNumVarnodes() == 0);
    }

    {
        DefaultAddressFactory factory;
        factory.addAddressSpace(&ramSpace);
        PcodeSyntaxTree st(&factory);
        Address pc(&ramSpace, 0x2000);
        Varnode* v0 = st.newVarnode(4, Address(&ramSpace, 0x100));
        Varnode* v1 = st.newVarnode(4, Address(&ramSpace, 0x200));
        Varnode* c0 = st.newVarnode(4, Address(&constSpace, 1));

        SequenceNumber sq(pc, 7);
        std::vector<Varnode*> inputs;
        PcodeOp* op = st.newOp(sq, PcodeOp::COPY, inputs, v0);
        Varnode* found = st.findVarnode(4, Address(&ramSpace, 0x100), sq);
        TEST("PST findVarnode with sq", found == v0);
        Varnode* foundpc = st.findVarnode(4, Address(&ramSpace, 0x100), pc);
        TEST("PST findVarnode with pc", foundpc == v0);

        st.setAddrTied(v0, true);
        st.setPersistent(v0, true);
        st.setUnaffected(v0, true);
        st.setMergeGroup(v0, (short)5);
        TEST("PST v0 addrtied", static_cast<VarnodeAST*>(v0)->isAddrTied());
        TEST("PST v0 persistent", static_cast<VarnodeAST*>(v0)->isPersistent());
        TEST("PST v0 unaffected", static_cast<VarnodeAST*>(v0)->isUnaffected());
        TEST("PST v0 mergegroup", static_cast<VarnodeAST*>(v0)->getMergeGroup() == 5);

        Varnode* v0ref = st.newVarnode(4, Address(&ramSpace, 0x100), 42);
        TEST("PST v0ref with id", v0ref != nullptr);
        Varnode* got = st.getRef(42);
        TEST("PST getRef 42", got == v0ref);
    }

    std::cout << "=== Batch G: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
