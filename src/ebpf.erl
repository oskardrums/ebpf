%%%-------------------------------------------------------------------
%%% @author Oskar
%%% @copyright (C) 2021, Oskar Mazerath
%%% @doc
%%% Erlang eBPF library
%%% @end
%%% Created :  5 Feb 2021 by Oskar
%%%-------------------------------------------------------------------
-module(ebpf).

%% API
-export([from_beam/1, from_erl/1]).

%%%===================================================================
%%% Includes
%%%===================================================================

-include("ebpf.hrl").
-include("beam.hrl").
-include_lib("compiler/src/beam_disasm.hrl").

%%%===================================================================
%%% Type definitions
%%%===================================================================

-type ebpf_module() :: [#rt{}].

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------
-spec from_beam(#beam_file{}) -> ebpf_module().
from_beam(#beam_file{
    module = _Module,
    labeled_exports = _Exports,
    attributes = _Attributes,
    compile_info = _CompileInfo,
    code = Functions
}) ->
    ebpf_from_beam(Functions).

-spec from_erl(string()) -> [#rt{}].
from_erl(Path) ->
    {ok, _Module, {_Module, _Exports, _Attributes, Functions, _Lc}} = compile:noenv_file(Path, [
        'S',
        binary,
        no_line_info,
        report
    ]),
    ebpf_from_beam(Functions).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec ebpf_from_beam([#function{}]) -> [#rt{}].
ebpf_from_beam(Functions) ->
    lists:map(fun ebpf_from_beam_function/1, Functions).

-spec ebpf_from_beam_function(#function{}) -> #rt{}.
ebpf_from_beam_function(#function{name = Name, code = Code}) ->
    case Name of
        module_info -> #rt{};
        _ -> beam_instructions_to_bpf_rt(Code)
    end.

-spec emit(beam_instruction(), rt()) -> #rt{}.
emit(return, #rt{code = Code, head = Head} = Runtime) ->
    Runtime#rt{code = [ebpf_instructions:exit_insn() | Code], head = Head + 1};
emit({label, Label}, #rt{labels = Labels, head = Head} = Runtime) ->
    Runtime#rt{labels = Labels#{Label => Head}, head = Head + 1};
emit({func_info, {atom, _M}, {atom, _F}, _A}, Runtime) ->
    Runtime;
emit({move, {integer, Imm}, {x, X}}, #rt{code = Code, head = Head} = Runtime) ->
    Runtime#rt{code = [ebpf_instructions:mov32_imm(X, Imm) | Code], head = Head + 1};
emit({move, {x, XSrc}, {x, XDst}}, #rt{code = Code, head = Head} = Runtime) ->
    Runtime#rt{code = [ebpf_instructions:mov32_reg(XDst, XSrc) | Code], head = Head + 1};
emit({allocate, StackNeed, Live}, #rt{stack_need = SN, live = L} = Runtime) ->
    Runtime#rt{stack_need = SN + StackNeed, live = L + Live};
emit({call_ext, _Arity, {extfunc, bpf, Func, _Arity}}, #rt{code = Code, head = Head} = Runtime) ->
    Runtime#rt{
        code = [ebpf_instructions:emit_call(func_atom_to_integer(Func)) | Code],
        head = Head + 1
    };
emit({deallocate, _StackNeed}, Runtime) ->
    Runtime;
emit(
    {gc_bif, Bif, {f, _FailLabel}, _Live, [Arg1, Arg2], {x, OutReg}},
    #rt{code = Code, head = Head} = Runtime
) ->
    case Bif of
        '+' ->
            case {Arg1, Arg2} of
                {{x, OutReg}, {integer, Integer}} ->
                    Runtime#rt{
                        code = [ebpf_instructions:alu64_imm(?BPF_ADD, OutReg, Integer) | Code],
                        head = Head + 1
                    };
                {{x, OutReg}, {x, InReg}} ->
                    Runtime#rt{
                        code = [ebpf_instructions:alu64_reg(?BPF_ADD, OutReg, InReg) | Code],
                        head = Head + 1
                    }
            end
    end.

-spec beam_instructions_to_bpf_rt([beam_instruction()]) -> #rt{}.

beam_instructions_to_bpf_rt([]) ->
    #rt{};
beam_instructions_to_bpf_rt([BeamInstruction | More]) ->
    emit(BeamInstruction, beam_instructions_to_bpf_rt(More)).

-spec func_atom_to_integer(atom()) -> non_neg_integer().
func_atom_to_integer(unspec) -> 0;
func_atom_to_integer(map_lookup_elem) -> 1;
func_atom_to_integer(map_update_elem) -> 2;
func_atom_to_integer(map_delete_elem) -> 3;
func_atom_to_integer(probe_read) -> 4;
func_atom_to_integer(ktime_get_ns) -> 5;
func_atom_to_integer(trace_printk) -> 6;
func_atom_to_integer(get_prandom_u32) -> 7;
func_atom_to_integer(get_smp_processor_id) -> 8;
func_atom_to_integer(skb_store_bytes) -> 9;
func_atom_to_integer(l3_csum_replace) -> 10;
func_atom_to_integer(l4_csum_replace) -> 11;
func_atom_to_integer(tail_call) -> 12;
func_atom_to_integer(clone_redirect) -> 13;
func_atom_to_integer(get_current_pid_tgid) -> 14;
func_atom_to_integer(get_current_uid_gid) -> 15;
func_atom_to_integer(get_current_comm) -> 16;
func_atom_to_integer(get_cgroup_classid) -> 17;
func_atom_to_integer(skb_vlan_push) -> 18;
func_atom_to_integer(skb_vlan_pop) -> 19;
func_atom_to_integer(skb_get_tunnel_key) -> 20;
func_atom_to_integer(skb_set_tunnel_key) -> 21;
func_atom_to_integer(perf_event_read) -> 22;
func_atom_to_integer(redirect) -> 23;
func_atom_to_integer(get_route_realm) -> 24;
func_atom_to_integer(perf_event_output) -> 25;
func_atom_to_integer(skb_load_bytes) -> 26;
func_atom_to_integer(get_stackid) -> 27;
func_atom_to_integer(csum_diff) -> 28;
func_atom_to_integer(skb_get_tunnel_opt) -> 29;
func_atom_to_integer(skb_set_tunnel_opt) -> 30;
func_atom_to_integer(skb_change_proto) -> 31;
func_atom_to_integer(skb_change_type) -> 32;
func_atom_to_integer(skb_under_cgroup) -> 33;
func_atom_to_integer(get_hash_recalc) -> 34;
func_atom_to_integer(get_current_task) -> 35;
func_atom_to_integer(probe_write_user) -> 36;
func_atom_to_integer(current_task_under_cgroup) -> 37;
func_atom_to_integer(skb_change_tail) -> 38;
func_atom_to_integer(skb_pull_data) -> 39;
func_atom_to_integer(csum_update) -> 40;
func_atom_to_integer(set_hash_invalid) -> 41;
func_atom_to_integer(get_numa_node_id) -> 42;
func_atom_to_integer(skb_change_head) -> 43;
func_atom_to_integer(xdp_adjust_head) -> 44;
func_atom_to_integer(probe_read_str) -> 45;
func_atom_to_integer(get_socket_cookie) -> 46;
func_atom_to_integer(get_socket_uid) -> 47;
func_atom_to_integer(set_hash) -> 48;
func_atom_to_integer(setsockopt) -> 49;
func_atom_to_integer(skb_adjust_room) -> 50;
func_atom_to_integer(redirect_map) -> 51;
func_atom_to_integer(sk_redirect_map) -> 52;
func_atom_to_integer(sock_map_update) -> 53;
func_atom_to_integer(xdp_adjust_meta) -> 54;
func_atom_to_integer(perf_event_read_value) -> 55;
func_atom_to_integer(perf_prog_read_value) -> 56;
func_atom_to_integer(getsockopt) -> 57;
func_atom_to_integer(override_return) -> 58;
func_atom_to_integer(sock_ops_cb_flags_set) -> 59;
func_atom_to_integer(msg_redirect_map) -> 60;
func_atom_to_integer(msg_apply_bytes) -> 61;
func_atom_to_integer(msg_cork_bytes) -> 62;
func_atom_to_integer(msg_pull_data) -> 63;
func_atom_to_integer(bind) -> 64;
func_atom_to_integer(xdp_adjust_tail) -> 65;
func_atom_to_integer(skb_get_xfrm_state) -> 66;
func_atom_to_integer(get_stack) -> 67;
func_atom_to_integer(skb_load_bytes_relative) -> 68;
func_atom_to_integer(fib_lookup) -> 69;
func_atom_to_integer(sock_hash_update) -> 70;
func_atom_to_integer(msg_redirect_hash) -> 71;
func_atom_to_integer(sk_redirect_hash) -> 72;
func_atom_to_integer(lwt_push_encap) -> 73;
func_atom_to_integer(lwt_seg6_store_bytes) -> 74;
func_atom_to_integer(lwt_seg6_adjust_srh) -> 75;
func_atom_to_integer(lwt_seg6_action) -> 76;
func_atom_to_integer(rc_repeat) -> 77;
func_atom_to_integer(rc_keydown) -> 78;
func_atom_to_integer(skb_cgroup_id) -> 79;
func_atom_to_integer(get_current_cgroup_id) -> 80;
func_atom_to_integer(get_local_storage) -> 81;
func_atom_to_integer(sk_select_reuseport) -> 82;
func_atom_to_integer(skb_ancestor_cgroup_id) -> 83;
func_atom_to_integer(sk_lookup_tcp) -> 84;
func_atom_to_integer(sk_lookup_udp) -> 85;
func_atom_to_integer(sk_release) -> 86;
func_atom_to_integer(map_push_elem) -> 87;
func_atom_to_integer(map_pop_elem) -> 88;
func_atom_to_integer(map_peek_elem) -> 89;
func_atom_to_integer(msg_push_data) -> 90;
func_atom_to_integer(msg_pop_data) -> 91;
func_atom_to_integer(rc_pointer_rel) -> 92;
func_atom_to_integer(spin_lock) -> 93;
func_atom_to_integer(spin_unlock) -> 94;
func_atom_to_integer(sk_fullsock) -> 95;
func_atom_to_integer(tcp_sock) -> 96;
func_atom_to_integer(skb_ecn_set_ce) -> 97;
func_atom_to_integer(get_listener_sock) -> 98;
func_atom_to_integer(skc_lookup_tcp) -> 99;
func_atom_to_integer(tcp_check_syncookie) -> 100;
func_atom_to_integer(sysctl_get_name) -> 101;
func_atom_to_integer(sysctl_get_current_value) -> 102;
func_atom_to_integer(sysctl_get_new_value) -> 103;
func_atom_to_integer(sysctl_set_new_value) -> 104;
func_atom_to_integer(strtol) -> 105;
func_atom_to_integer(strtoul) -> 106;
func_atom_to_integer(sk_storage_get) -> 107;
func_atom_to_integer(sk_storage_delete) -> 108;
func_atom_to_integer(send_signal) -> 109;
func_atom_to_integer(tcp_gen_syncookie) -> 110;
func_atom_to_integer(skb_output) -> 111;
func_atom_to_integer(probe_read_user) -> 112;
func_atom_to_integer(probe_read_kernel) -> 113;
func_atom_to_integer(probe_read_user_str) -> 114;
func_atom_to_integer(probe_read_kernel_str) -> 115;
func_atom_to_integer(tcp_send_ack) -> 116;
func_atom_to_integer(send_signal_thread) -> 117;
func_atom_to_integer(jiffies64) -> 118;
func_atom_to_integer(read_branch_records) -> 119;
func_atom_to_integer(get_ns_current_pid_tgid) -> 120;
func_atom_to_integer(xdp_output) -> 121;
func_atom_to_integer(get_netns_cookie) -> 122;
func_atom_to_integer(get_current_ancestor_cgroup_id) -> 123;
func_atom_to_integer(sk_assign) -> 124;
func_atom_to_integer(ktime_get_boot_ns) -> 125;
func_atom_to_integer(seq_printf) -> 126;
func_atom_to_integer(seq_write) -> 127;
func_atom_to_integer(sk_cgroup_id) -> 128;
func_atom_to_integer(sk_ancestor_cgroup_id) -> 129;
func_atom_to_integer(ringbuf_output) -> 130;
func_atom_to_integer(ringbuf_reserve) -> 131;
func_atom_to_integer(ringbuf_submit) -> 132;
func_atom_to_integer(ringbuf_discard) -> 133;
func_atom_to_integer(ringbuf_query) -> 134;
func_atom_to_integer(csum_level) -> 135;
func_atom_to_integer(skc_to_tcp6_sock) -> 136;
func_atom_to_integer(skc_to_tcp_sock) -> 137;
func_atom_to_integer(skc_to_tcp_timewait_sock) -> 138;
func_atom_to_integer(skc_to_tcp_request_sock) -> 139;
func_atom_to_integer(skc_to_udp6_sock) -> 140;
func_atom_to_integer(get_task_stack) -> 141;
func_atom_to_integer(load_hdr_opt) -> 142;
func_atom_to_integer(store_hdr_opt) -> 143;
func_atom_to_integer(reserve_hdr_opt) -> 144;
func_atom_to_integer(inode_storage_get) -> 145;
func_atom_to_integer(inode_storage_delete) -> 146;
func_atom_to_integer(d_path) -> 147;
func_atom_to_integer(copy_from_user) -> 148;
func_atom_to_integer(snprintf_btf) -> 149;
func_atom_to_integer(seq_printf_btf) -> 150;
func_atom_to_integer(skb_cgroup_classid) -> 151;
func_atom_to_integer(redirect_neigh) -> 152;
func_atom_to_integer(per_cpu_ptr) -> 153;
func_atom_to_integer(this_cpu_ptr) -> 154;
func_atom_to_integer(redirect_peer) -> 155;
func_atom_to_integer(task_storage_get) -> 156;
func_atom_to_integer(task_storage_delete) -> 157;
func_atom_to_integer(get_current_task_btf) -> 158;
func_atom_to_integer(bprm_opts_set) -> 159;
func_atom_to_integer(ktime_get_coarse_ns) -> 160;
func_atom_to_integer(ima_inode_hash) -> 161;
func_atom_to_integer(sock_from_file) -> 162.
