%%%-------------------------------------------------------------------
%%% @author moskar <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, moskar
%%% @doc
%%% Low level Linux eBPF library
%%% @end
%%% Created :  7 Feb 2021 by user <moskar.drummer@gmail.home>
%%%-------------------------------------------------------------------
-module(ebpf_lib).

%% API
-export([
    assemble/1,
    disassemble/1,
    load/2,
    verify/2,
    attach_socket_filter/2
]).

%% Instruction construction
-export([
    exit_insn/0,
    mov32_imm/2,
    mov64_imm/2,
    mov32_reg/2,
    mov64_reg/2,
    alu64_imm/3,
    alu64_reg/3,
    alu32_reg/3,
    alu32_imm/3,
    emit_call/1,
    bpf_helper_to_int/1,
    bpf_alu_op_to_int/1
]).

-on_load(init/0).

-define(APPNAME, ebpf).
-define(LIBNAME, ?MODULE).

-include("ebpf.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Assembles a list of bpf_instruction records into
%% binary form which can then be loaded to the kernel via load/2.
%% @end
%%--------------------------------------------------------------------
-spec assemble([bpf_instruction()]) -> binary().
assemble(BpfInstructions) ->
    bpf_instructions_to_binary(BpfInstructions).

%%--------------------------------------------------------------------
%% @doc
%% Disassembles an eBPF program in binary form to a
%% list of bpf_instruction records.
%% @end
%%--------------------------------------------------------------------
-spec disassemble(binary()) -> [bpf_instruction()].
disassemble(BpfProgramBin) ->
    lists:reverse(disassemble(BpfProgramBin, [])).

-spec disassemble(binary(), [bpf_instruction()]) -> [bpf_instruction()].
disassemble(<<>>, Acc) ->
    Acc;
disassemble(<<InstructionBin:8/binary-unit:8, More/binary>>, Acc) ->
    disassemble(More, [bpf_instruction_decode(InstructionBin) | Acc]).

%%--------------------------------------------------------------------
%% @doc
%% Verifies an eBPF program in binary form with the kernel's verifier.
%% Reports errors in the program, if any, in textual form as returned
%% by the kernel.
%% @end
%%--------------------------------------------------------------------
-spec verify(bpf_prog_type(), binary()) -> 'ok' | {'error', term()}.
verify(BpfProgramType, BpfProgramBin) ->
    bpf_verify_program(
        bpf_prog_type_to_int(BpfProgramType),
        BpfProgramBin
    ).

%%--------------------------------------------------------------------
%% @doc
%% Attempts to load an eBPF program in binary form to the kernel.
%% see verify/1 for debugging and checking program validity.
%% @end
%%--------------------------------------------------------------------
-spec load(bpf_prog_type(), binary()) -> {'ok', non_neg_integer()} | {'error', term()}.
load(BpfProgramType, BpfProgramBin) ->
    bpf_load_program(
        bpf_prog_type_to_int(BpfProgramType),
        BpfProgramBin
    ).

%%--------------------------------------------------------------------
%% @doc
%% Applies a loaded eBPF program as returned by load/1 to a socket.
%% @end
%%--------------------------------------------------------------------
-spec attach_socket_filter(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', term()}.
attach_socket_filter(SockFd, ProgFd) ->
    bpf_attach_socket_filter(
        SockFd,
        ProgFd
    ).

%%%===================================================================
%%% Instruction construction
%%%===================================================================

-spec alu64_reg(bpf_alu_op(), bpf_reg(), bpf_reg()) -> bpf_instruction().
alu64_reg(Op, Dst, Src) ->
    #bpf_instruction{
        code = ?BPF_ALU64 bor bpf_alu_op_to_int(Op) bor ?BPF_X,
        dst_reg = Dst,
        src_reg = Src
    }.

-spec alu32_reg(bpf_alu_op(), bpf_reg(), bpf_reg()) -> bpf_instruction().
alu32_reg(Op, Dst, Src) ->
    #bpf_instruction{
        code = ?BPF_ALU bor bpf_alu_op_to_int(Op) bor ?BPF_X,
        dst_reg = Dst,
        src_reg = Src
    }.

-spec alu64_imm(bpf_alu_op(), bpf_reg(), bpf_imm()) -> bpf_instruction().
alu64_imm(Op, Dst, Imm) ->
    #bpf_instruction{
        code = ?BPF_ALU64 bor bpf_alu_op_to_int(Op) bor ?BPF_K,
        dst_reg = Dst,
        imm = Imm
    }.

-spec alu32_imm(bpf_alu_op(), bpf_reg(), bpf_imm()) -> bpf_instruction().
alu32_imm(Op, Dst, Imm) ->
    #bpf_instruction{
        code = ?BPF_ALU bor bpf_alu_op_to_int(Op) bor ?BPF_K,
        dst_reg = Dst,
        imm = Imm
    }.

-spec mov64_reg(bpf_reg(), bpf_reg()) -> bpf_instruction().
mov64_reg(Dst, Src) ->
    #bpf_instruction{code = ?BPF_ALU64 bor ?BPF_MOV bor ?BPF_X, dst_reg = Dst, src_reg = Src}.

-spec mov32_reg(bpf_reg(), bpf_reg()) -> bpf_instruction().
mov32_reg(Dst, Src) ->
    #bpf_instruction{code = ?BPF_ALU bor ?BPF_MOV bor ?BPF_X, dst_reg = Dst, src_reg = Src}.

-spec mov64_imm(bpf_reg(), bpf_imm()) -> bpf_instruction().
mov64_imm(Dst, Imm) ->
    #bpf_instruction{code = ?BPF_ALU64 bor ?BPF_MOV bor ?BPF_K, dst_reg = Dst, imm = Imm}.

-spec mov32_imm(bpf_reg(), bpf_imm()) -> bpf_instruction().
mov32_imm(Dst, Imm) ->
    #bpf_instruction{code = ?BPF_ALU bor ?BPF_MOV bor ?BPF_K, dst_reg = Dst, imm = Imm}.

-spec emit_call(bpf_helper()) -> bpf_instruction().
emit_call(Func) ->
    #bpf_instruction{code = ?BPF_JMP bor ?BPF_CALL, imm = bpf_helper_to_int(Func)}.

-spec exit_insn() -> bpf_instruction().
exit_insn() ->
    #bpf_instruction{code = ?BPF_JMP bor ?BPF_EXIT}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%-------------------------------------------------------------------
%%% NIFs and NIF related functions
%%%-------------------------------------------------------------------

-spec bpf_verify_program(non_neg_integer(), binary()) -> 'ok' | {'error', term()}.
bpf_verify_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

-spec bpf_load_program(non_neg_integer(), binary()) ->
    {'ok', non_neg_integer()} | {'error', term()}.
bpf_load_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

-spec bpf_attach_socket_filter(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', term()}.
bpf_attach_socket_filter(_SockFd, _ProgFd) ->
    not_loaded(?LINE).

init() ->
    SoName =
        case code:priv_dir(?APPNAME) of
            {error, bad_name} ->
                case filelib:is_dir(filename:join(["..", priv])) of
                    true ->
                        filename:join(["..", priv, ?LIBNAME]);
                    _ ->
                        filename:join([priv, ?LIBNAME])
                end;
            Dir ->
                filename:join(Dir, ?LIBNAME)
        end,
    erlang:load_nif(SoName, 0).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

%%%-------------------------------------------------------------------
%%% Other internal functions
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc Binary encodes a list of eBPF instructions.
%% @end
%%--------------------------------------------------------------------
-spec bpf_instructions_to_binary([bpf_instruction()]) -> binary().
bpf_instructions_to_binary(BpfInstructions) ->
    lists:foldl(
        fun(Instruction, Acc) ->
            EncodedInstruction = bpf_instruction_encode(Instruction),
            <<Acc/binary, EncodedInstruction/binary>>
        end,
        <<>>,
        BpfInstructions
    ).

-spec bpf_instruction_encode(bpf_instruction()) -> binary().
bpf_instruction_encode(#bpf_instruction{
    code = Code,
    dst_reg = Dst,
    src_reg = Src,
    off = Off,
    imm = Imm
}) ->
    <<Code:8/unsigned, Dst:4/unsigned, Src:4/unsigned, Off:16/signed, Imm:32/signed>>.

-spec bpf_instruction_decode(binary()) -> bpf_instruction().
bpf_instruction_decode(
    <<Code:8/unsigned, Dst:4/unsigned, Src:4/unsigned, Off:16/signed, Imm:32/signed>>
) ->
    #bpf_instruction{code = Code, dst_reg = Dst, src_reg = Src, off = Off, imm = Imm}.

-spec bpf_prog_type_to_int(bpf_prog_type()) -> non_neg_integer().
bpf_prog_type_to_int(unspec) -> 0;
bpf_prog_type_to_int(socket_filter) -> 1;
bpf_prog_type_to_int(kprobe) -> 2;
bpf_prog_type_to_int(sched_cls) -> 3;
bpf_prog_type_to_int(sched_act) -> 4;
bpf_prog_type_to_int(tracepoint) -> 5;
bpf_prog_type_to_int(xdp) -> 6;
bpf_prog_type_to_int(perf_event) -> 7;
bpf_prog_type_to_int(cgroup_skb) -> 8;
bpf_prog_type_to_int(cgroup_sock) -> 9;
bpf_prog_type_to_int(lwt_in) -> 10;
bpf_prog_type_to_int(lwt_out) -> 11;
bpf_prog_type_to_int(lwt_xmit) -> 12;
bpf_prog_type_to_int(sock_ops) -> 13;
bpf_prog_type_to_int(sk_skb) -> 14;
bpf_prog_type_to_int(cgroup_device) -> 15;
bpf_prog_type_to_int(sk_msg) -> 16;
bpf_prog_type_to_int(raw_tracepoint) -> 17;
bpf_prog_type_to_int(cgroup_sock_addr) -> 18;
bpf_prog_type_to_int(lwt_seg6local) -> 19;
bpf_prog_type_to_int(lirc_mode2) -> 20;
bpf_prog_type_to_int(sk_reuseport) -> 21;
bpf_prog_type_to_int(flow_dissector) -> 22;
bpf_prog_type_to_int(cgroup_sysctl) -> 23;
bpf_prog_type_to_int(raw_tracepoint_writable) -> 24;
bpf_prog_type_to_int(cgroup_sockopt) -> 25;
bpf_prog_type_to_int(tracing) -> 26;
bpf_prog_type_to_int(struct_ops) -> 27;
bpf_prog_type_to_int(ext) -> 28;
bpf_prog_type_to_int(lsm) -> 29;
bpf_prog_type_to_int(sk_lookup) -> 30.

-spec bpf_helper_to_int(bpf_helper()) -> bpf_imm().
bpf_helper_to_int(unspec) -> 0;
bpf_helper_to_int(map_lookup_elem) -> 1;
bpf_helper_to_int(map_update_elem) -> 2;
bpf_helper_to_int(map_delete_elem) -> 3;
bpf_helper_to_int(probe_read) -> 4;
bpf_helper_to_int(ktime_get_ns) -> 5;
bpf_helper_to_int(trace_printk) -> 6;
bpf_helper_to_int(get_prandom_u32) -> 7;
bpf_helper_to_int(get_smp_processor_id) -> 8;
bpf_helper_to_int(skb_store_bytes) -> 9;
bpf_helper_to_int(l3_csum_replace) -> 10;
bpf_helper_to_int(l4_csum_replace) -> 11;
bpf_helper_to_int(tail_call) -> 12;
bpf_helper_to_int(clone_redirect) -> 13;
bpf_helper_to_int(get_current_pid_tgid) -> 14;
bpf_helper_to_int(get_current_uid_gid) -> 15;
bpf_helper_to_int(get_current_comm) -> 16;
bpf_helper_to_int(get_cgroup_classid) -> 17;
bpf_helper_to_int(skb_vlan_push) -> 18;
bpf_helper_to_int(skb_vlan_pop) -> 19;
bpf_helper_to_int(skb_get_tunnel_key) -> 20;
bpf_helper_to_int(skb_set_tunnel_key) -> 21;
bpf_helper_to_int(perf_event_read) -> 22;
bpf_helper_to_int(redirect) -> 23;
bpf_helper_to_int(get_route_realm) -> 24;
bpf_helper_to_int(perf_event_output) -> 25;
bpf_helper_to_int(skb_load_bytes) -> 26;
bpf_helper_to_int(get_stackid) -> 27;
bpf_helper_to_int(csum_diff) -> 28;
bpf_helper_to_int(skb_get_tunnel_opt) -> 29;
bpf_helper_to_int(skb_set_tunnel_opt) -> 30;
bpf_helper_to_int(skb_change_proto) -> 31;
bpf_helper_to_int(skb_change_type) -> 32;
bpf_helper_to_int(skb_under_cgroup) -> 33;
bpf_helper_to_int(get_hash_recalc) -> 34;
bpf_helper_to_int(get_current_task) -> 35;
bpf_helper_to_int(probe_write_user) -> 36;
bpf_helper_to_int(current_task_under_cgroup) -> 37;
bpf_helper_to_int(skb_change_tail) -> 38;
bpf_helper_to_int(skb_pull_data) -> 39;
bpf_helper_to_int(csum_update) -> 40;
bpf_helper_to_int(set_hash_invalid) -> 41;
bpf_helper_to_int(get_numa_node_id) -> 42;
bpf_helper_to_int(skb_change_head) -> 43;
bpf_helper_to_int(xdp_adjust_head) -> 44;
bpf_helper_to_int(probe_read_str) -> 45;
bpf_helper_to_int(get_socket_cookie) -> 46;
bpf_helper_to_int(get_socket_uid) -> 47;
bpf_helper_to_int(set_hash) -> 48;
bpf_helper_to_int(setsockopt) -> 49;
bpf_helper_to_int(skb_adjust_room) -> 50;
bpf_helper_to_int(redirect_map) -> 51;
bpf_helper_to_int(sk_redirect_map) -> 52;
bpf_helper_to_int(sock_map_update) -> 53;
bpf_helper_to_int(xdp_adjust_meta) -> 54;
bpf_helper_to_int(perf_event_read_value) -> 55;
bpf_helper_to_int(perf_prog_read_value) -> 56;
bpf_helper_to_int(getsockopt) -> 57;
bpf_helper_to_int(override_return) -> 58;
bpf_helper_to_int(sock_ops_cb_flags_set) -> 59;
bpf_helper_to_int(msg_redirect_map) -> 60;
bpf_helper_to_int(msg_apply_bytes) -> 61;
bpf_helper_to_int(msg_cork_bytes) -> 62;
bpf_helper_to_int(msg_pull_data) -> 63;
bpf_helper_to_int(bind) -> 64;
bpf_helper_to_int(xdp_adjust_tail) -> 65;
bpf_helper_to_int(skb_get_xfrm_state) -> 66;
bpf_helper_to_int(get_stack) -> 67;
bpf_helper_to_int(skb_load_bytes_relative) -> 68;
bpf_helper_to_int(fib_lookup) -> 69;
bpf_helper_to_int(sock_hash_update) -> 70;
bpf_helper_to_int(msg_redirect_hash) -> 71;
bpf_helper_to_int(sk_redirect_hash) -> 72;
bpf_helper_to_int(lwt_push_encap) -> 73;
bpf_helper_to_int(lwt_seg6_store_bytes) -> 74;
bpf_helper_to_int(lwt_seg6_adjust_srh) -> 75;
bpf_helper_to_int(lwt_seg6_action) -> 76;
bpf_helper_to_int(rc_repeat) -> 77;
bpf_helper_to_int(rc_keydown) -> 78;
bpf_helper_to_int(skb_cgroup_id) -> 79;
bpf_helper_to_int(get_current_cgroup_id) -> 80;
bpf_helper_to_int(get_local_storage) -> 81;
bpf_helper_to_int(sk_select_reuseport) -> 82;
bpf_helper_to_int(skb_ancestor_cgroup_id) -> 83;
bpf_helper_to_int(sk_lookup_tcp) -> 84;
bpf_helper_to_int(sk_lookup_udp) -> 85;
bpf_helper_to_int(sk_release) -> 86;
bpf_helper_to_int(map_push_elem) -> 87;
bpf_helper_to_int(map_pop_elem) -> 88;
bpf_helper_to_int(map_peek_elem) -> 89;
bpf_helper_to_int(msg_push_data) -> 90;
bpf_helper_to_int(msg_pop_data) -> 91;
bpf_helper_to_int(rc_pointer_rel) -> 92;
bpf_helper_to_int(spin_lock) -> 93;
bpf_helper_to_int(spin_unlock) -> 94;
bpf_helper_to_int(sk_fullsock) -> 95;
bpf_helper_to_int(tcp_sock) -> 96;
bpf_helper_to_int(skb_ecn_set_ce) -> 97;
bpf_helper_to_int(get_listener_sock) -> 98;
bpf_helper_to_int(skc_lookup_tcp) -> 99;
bpf_helper_to_int(tcp_check_syncookie) -> 100;
bpf_helper_to_int(sysctl_get_name) -> 101;
bpf_helper_to_int(sysctl_get_current_value) -> 102;
bpf_helper_to_int(sysctl_get_new_value) -> 103;
bpf_helper_to_int(sysctl_set_new_value) -> 104;
bpf_helper_to_int(strtol) -> 105;
bpf_helper_to_int(strtoul) -> 106;
bpf_helper_to_int(sk_storage_get) -> 107;
bpf_helper_to_int(sk_storage_delete) -> 108;
bpf_helper_to_int(send_signal) -> 109;
bpf_helper_to_int(tcp_gen_syncookie) -> 110;
bpf_helper_to_int(skb_output) -> 111;
bpf_helper_to_int(probe_read_user) -> 112;
bpf_helper_to_int(probe_read_kernel) -> 113;
bpf_helper_to_int(probe_read_user_str) -> 114;
bpf_helper_to_int(probe_read_kernel_str) -> 115;
bpf_helper_to_int(tcp_send_ack) -> 116;
bpf_helper_to_int(send_signal_thread) -> 117;
bpf_helper_to_int(jiffies64) -> 118;
bpf_helper_to_int(read_branch_records) -> 119;
bpf_helper_to_int(get_ns_current_pid_tgid) -> 120;
bpf_helper_to_int(xdp_output) -> 121;
bpf_helper_to_int(get_netns_cookie) -> 122;
bpf_helper_to_int(get_current_ancestor_cgroup_id) -> 123;
bpf_helper_to_int(sk_assign) -> 124;
bpf_helper_to_int(ktime_get_boot_ns) -> 125;
bpf_helper_to_int(seq_printf) -> 126;
bpf_helper_to_int(seq_write) -> 127;
bpf_helper_to_int(sk_cgroup_id) -> 128;
bpf_helper_to_int(sk_ancestor_cgroup_id) -> 129;
bpf_helper_to_int(ringbuf_output) -> 130;
bpf_helper_to_int(ringbuf_reserve) -> 131;
bpf_helper_to_int(ringbuf_submit) -> 132;
bpf_helper_to_int(ringbuf_discard) -> 133;
bpf_helper_to_int(ringbuf_query) -> 134;
bpf_helper_to_int(csum_level) -> 135;
bpf_helper_to_int(skc_to_tcp6_sock) -> 136;
bpf_helper_to_int(skc_to_tcp_sock) -> 137;
bpf_helper_to_int(skc_to_tcp_timewait_sock) -> 138;
bpf_helper_to_int(skc_to_tcp_request_sock) -> 139;
bpf_helper_to_int(skc_to_udp6_sock) -> 140;
bpf_helper_to_int(get_task_stack) -> 141;
bpf_helper_to_int(load_hdr_opt) -> 142;
bpf_helper_to_int(store_hdr_opt) -> 143;
bpf_helper_to_int(reserve_hdr_opt) -> 144;
bpf_helper_to_int(inode_storage_get) -> 145;
bpf_helper_to_int(inode_storage_delete) -> 146;
bpf_helper_to_int(d_path) -> 147;
bpf_helper_to_int(copy_from_user) -> 148;
bpf_helper_to_int(snprintf_btf) -> 149;
bpf_helper_to_int(seq_printf_btf) -> 150;
bpf_helper_to_int(skb_cgroup_classid) -> 151;
bpf_helper_to_int(redirect_neigh) -> 152;
bpf_helper_to_int(per_cpu_ptr) -> 153;
bpf_helper_to_int(this_cpu_ptr) -> 154;
bpf_helper_to_int(redirect_peer) -> 155;
bpf_helper_to_int(task_storage_get) -> 156;
bpf_helper_to_int(task_storage_delete) -> 157;
bpf_helper_to_int(get_current_task_btf) -> 158;
bpf_helper_to_int(bprm_opts_set) -> 159;
bpf_helper_to_int(ktime_get_coarse_ns) -> 160;
bpf_helper_to_int(ima_inode_hash) -> 161;
bpf_helper_to_int(sock_from_file) -> 162.

-spec bpf_alu_op_to_int(bpf_alu_op()) -> bpf_opcode().
bpf_alu_op_to_int('+') -> ?BPF_ADD;
bpf_alu_op_to_int('-') -> ?BPF_SUB;
bpf_alu_op_to_int('*') -> ?BPF_MUL;
bpf_alu_op_to_int('/') -> ?BPF_DIV;
bpf_alu_op_to_int('bor') -> ?BPF_OR;
bpf_alu_op_to_int('band') -> ?BPF_AND;
bpf_alu_op_to_int('bsl') -> ?BPF_LSH;
bpf_alu_op_to_int('bsr') -> ?BPF_RSH;
bpf_alu_op_to_int('neg') -> ?BPF_NEG;
bpf_alu_op_to_int('bxor') -> ?BPF_XOR;
bpf_alu_op_to_int('rem') -> ?BPF_MOD;
bpf_alu_op_to_int('=') -> ?BPF_MOV.
