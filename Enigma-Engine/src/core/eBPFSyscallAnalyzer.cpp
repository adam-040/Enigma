#include <ghidra/eBPFSyscallAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/Language.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/SourceType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <sstream>
#include <unordered_map>

namespace ghidra {

namespace {

const std::unordered_map<int64_t, const char*>& getKnownHelpers() {
    static const std::unordered_map<int64_t, const char*> helpers = {
        {0, "bpf_map_lookup_elem"}, {1, "bpf_map_update_elem"}, {2, "bpf_map_delete_elem"},
        {3, "bpf_map_next_key"}, {4, "bpf_ktime_get_ns"}, {5, "bpf_trace_printk"},
        {6, "bpf_get_prandom_u32"}, {7, "bpf_get_smp_processor_id"}, {8, "bpf_skb_store_bytes"},
        {9, "bpf_l3_csum_replace"}, {10, "bpf_l4_csum_replace"}, {11, "bpf_tail_call"},
        {12, "bpf_clone_redirect"}, {13, "bpf_get_current_pid_tgid"},
        {14, "bpf_get_current_uid_gid"}, {15, "bpf_get_current_comm"},
        {16, "bpf_get_cgroup_classid"}, {17, "bpf_skb_vlan_push"}, {18, "bpf_skb_vlan_pop"},
        {19, "bpf_skb_get_tunnel_key"}, {20, "bpf_skb_set_tunnel_key"},
        {21, "bpf_perf_event_read"}, {22, "bpf_redirect"}, {23, "bpf_get_route_realm"},
        {24, "bpf_perf_event_output"}, {25, "bpf_skb_load_bytes"},
        {26, "bpf_get_stackid"}, {27, "bpf_csum_diff"}, {28, "bpf_skb_get_tunnel_opt"},
        {29, "bpf_skb_set_tunnel_opt"}, {30, "bpf_skb_change_proto"}, {31, "bpf_skb_change_type"},
        {32, "bpf_skb_under_cgroup"}, {33, "bpf_get_hash_recalc"},
        {34, "bpf_get_current_task"}, {35, "bpf_probe_write_user"}, {36, "bpf_current_task_under_cgroup"},
        {37, "bpf_skb_change_tail"}, {38, "bpf_skb_pull_data"}, {39, "bpf_csum_update"},
        {40, "bpf_set_hash_invalid"}, {41, "bpf_get_numa_node_id"},
        {42, "bpf_skb_change_head"}, {43, "bpf_xdp_adjust_head"}, {44, "bpf_probe_read_str"},
        {45, "bpf_get_socket_cookie"}, {46, "bpf_get_socket_uid"},
        {47, "bpf_set_hash"}, {48, "bpf_setsockopt"}, {49, "bpf_skb_adjust_room"},
        {50, "bpf_redirect_map"}, {51, "bpf_sk_redirect_map"}, {52, "bpf_sock_map_update"},
        {53, "bpf_xdp_adjust_meta"}, {54, "bpf_perf_event_read_value"},
        {55, "bpf_perf_prog_read_value"}, {56, "bpf_getsockopt"}, {57, "bpf_override_return"},
        {58, "bpf_sock_ops_cb_flags_set"}, {59, "bpf_msg_redirect_map"},
        {60, "bpf_msg_apply_bytes"}, {61, "bpf_msg_cork_bytes"}, {62, "bpf_msg_pull_data"},
        {63, "bpf_bind"}, {64, "bpf_xdp_adjust_tail"}, {65, "bpf_skb_get_xfrm_state"},
        {66, "bpf_get_stack"}, {67, "bpf_skb_load_bytes_relative"},
        {68, "bpf_fib_lookup"}, {69, "bpf_sock_hash_update"}, {70, "bpf_msg_redirect_hash"},
        {71, "bpf_sk_redirect_hash"}, {72, "bpf_lwt_push_encap"}, {73, "bpf_lwt_seg6_store_bytes"},
        {74, "bpf_lwt_seg6_adjust_srh"}, {75, "bpf_lwt_seg6_action"},
        {76, "bpf_rc_repeat"}, {77, "bpf_rc_keydown"}, {78, "bpf_rc_pointer_rel"},
        {79, "bpf_skb_cgroup_id"}, {80, "bpf_get_current_cgroup_id"},
        {81, "bpf_get_local_storage"}, {82, "bpf_sk_select_reuseport"},
        {83, "bpf_skb_ancestor_cgroup_id"}, {84, "bpf_sk_lookup_tcp"},
        {85, "bpf_sk_lookup_udp"}, {86, "bpf_sk_release"},
        {87, "bpf_map_push_elem"}, {88, "bpf_map_pop_elem"}, {89, "bpf_map_peek_elem"},
        {90, "bpf_msg_push_data"}, {91, "bpf_msg_pop_data"}, {92, "bpf_rc_pointer_rel"},
        {93, "bpf_spin_lock"}, {94, "bpf_spin_unlock"}, {95, "bpf_sk_fullsock"},
        {96, "bpf_tcp_sock"}, {97, "bpf_skb_ecn_set_ce"},
        {98, "bpf_get_listener_sock"}, {99, "bpf_skc_lookup_tcp"},
        {100, "bpf_tcp_check_syncookie"}, {101, "bpf_sysctl_get_name"},
        {102, "bpf_sysctl_get_current_value"}, {103, "bpf_sysctl_set_new_value"},
        {104, "bpf_strtol"}, {105, "bpf_strtoul"}, {106, "bpf_sk_storage_get"},
        {107, "bpf_sk_storage_delete"}, {108, "bpf_send_signal"},
        {109, "bpf_tcp_gen_syncookie"},
    };
    return helpers;
}

} // anonymous namespace

eBPFSyscallAnalyzer::eBPFSyscallAnalyzer()
    : AbstractAnalyzer("eBPF Syscall Functions",
                       "Apply eBPF syscall Functions.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ID_ANALYSIS.before());
    setDefaultEnablement(true);
}

bool eBPFSyscallAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == "eBPF";
}

bool eBPFSyscallAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool eBPFSyscallAnalyzer::added(Program* program, const AddressSetView& set,
                                 TaskMonitor* monitor, MessageLog& log) {
    if (monitor) monitor->setMessage("Applying eBPF syscall function signatures...");
    if (!program) return false;

    auto* addressFactory = program->getAddressFactory();
    auto* funcMgr = program->getFunctionManager();
    if (!addressFactory || !funcMgr) return false;

    const AddressSpace* syscallSpace = addressFactory->getAddressSpace("syscall");
    if (!syscallSpace) return true;

    // Clear error bookmarks in syscall space
    auto* bookmarkMgr = program->getBookmarkManager();
    if (bookmarkMgr) {
        auto bookmarks = bookmarkMgr->getBookmarks("ERROR");
        for (auto* bm : bookmarks) {
            if (monitor && monitor->isCancelled()) break;
            if (bm && bm->getAddress().getAddressSpace() == syscallSpace) {
                bookmarkMgr->removeBookmark(bm->getAddress(), "ERROR");
            }
        }
    }

    FunctionIterator funcIter = funcMgr->getFunctions(set, true);
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;

        Function* func = funcIter.next();
        if (!func) continue;

        Address entry = func->getEntryPoint();
        if (entry.getAddressSpace() != syscallSpace) continue;

        if (func->getSource() != SourceType::DEFAULT) continue;

        int64_t helperId = entry.getOffset();
        const auto& knownHelpers = getKnownHelpers();
        auto it = knownHelpers.find(helperId);
        if (it != knownHelpers.end()) {
            func->setName(std::string(it->second) + "_helper");
        } else {
            std::ostringstream oss;
            oss << "bpf_undef_0x" << std::hex << helperId;
            func->setName(oss.str());
        }
        func->setSource(SourceType::ANALYSIS);
    }

    return true;
}

} // namespace ghidra
