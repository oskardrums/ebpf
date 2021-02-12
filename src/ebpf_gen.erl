%%%-------------------------------------------------------------------
%%% @author Oskar Mazerath <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, Oskar Mazerath
%%% @doc
%%% Library module containing eBPF intructions generation methods.
%%% @end
%%% Created :  9 Feb 2021 by Oskar Mazerath <moskar.drummer@gmail.com>
%%%-------------------------------------------------------------------
-module(ebpf_gen).

%% API
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
    ld_imm64_raw_full/6,
    ld_map_fd/2,
    st_mem/4,
    stx_mem/4,
    emit_call/1,
    bpf_helper_to_int/1,
    stack_printk/1,
    stack_printk/2,
    push_binary/1,
    push_binary/2,
    push_string/1,
    push_string/2
]).

-include("ebpf.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that performs ALU operation Op with
%% register arguments Src and Dst, and store the result in Dst.
%% @end
%%--------------------------------------------------------------------
-spec alu64_reg(bpf_alu_op(), bpf_reg(), bpf_reg()) -> bpf_instruction().
alu64_reg(Op, Dst, Src) ->
    #bpf_instruction{
        code = {alu64, x, Op},
        dst_reg = Dst,
        src_reg = Src
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that performs ALU operation Op with
%% register arguments Src and Dst using only the lower 32 bits of
%% each, and store the result in Dst.
%% @end
%%--------------------------------------------------------------------
-spec alu32_reg(bpf_alu_op(), bpf_reg(), bpf_reg()) -> bpf_instruction().
alu32_reg(Op, Dst, Src) ->
    #bpf_instruction{
        code = {alu32, x, Op},
        dst_reg = Dst,
        src_reg = Src
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that performs ALU operation Op with
%% immediate argument Imm and register Dst, and store the result in Dst.
%% @end
%%--------------------------------------------------------------------
-spec alu64_imm(bpf_alu_op(), bpf_reg(), bpf_imm()) -> bpf_instruction().
alu64_imm(Op, Dst, Imm) ->
    #bpf_instruction{
        code = {alu64, k, Op},
        dst_reg = Dst,
        imm = Imm
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that performs ALU operation Op with
%% immediate argument Imm and register Dst using only the lower 32
%% bits of each, and store the result in Dst.
%% @end
%%--------------------------------------------------------------------
-spec alu32_imm(bpf_alu_op(), bpf_reg(), bpf_imm()) -> bpf_instruction().
alu32_imm(Op, Dst, Imm) ->
    #bpf_instruction{
        code = {alu32, k, Op},
        dst_reg = Dst,
        imm = Imm
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that copies Src into Dst.
%% @end
%%--------------------------------------------------------------------
-spec mov64_reg(bpf_reg(), bpf_reg()) -> bpf_instruction().
mov64_reg(Dst, Src) ->
    #bpf_instruction{code = {alu64, x, mov}, dst_reg = Dst, src_reg = Src}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that copies the lower 32 bits of Src
%% into Dst, zeroing the upper 32 bits of Dst in the process.
%% @end
%%--------------------------------------------------------------------
-spec mov32_reg(bpf_reg(), bpf_reg()) -> bpf_instruction().
mov32_reg(Dst, Src) ->
    #bpf_instruction{code = {alu32, x, mov}, dst_reg = Dst, src_reg = Src}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that copies Imm into Dst.
%% @end
%%--------------------------------------------------------------------
-spec mov64_imm(bpf_reg(), bpf_imm()) -> bpf_instruction().
mov64_imm(Dst, Imm) ->
    #bpf_instruction{code = {alu64, k, mov}, dst_reg = Dst, imm = Imm}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that copies Imm into the
%% lower 32 bits of Dst, zeroing the 32 upper bits.
%% @end
%%--------------------------------------------------------------------
-spec mov32_imm(bpf_reg(), bpf_imm()) -> bpf_instruction().
mov32_imm(Dst, Imm) ->
    #bpf_instruction{code = {alu32, k, mov}, dst_reg = Dst, imm = Imm}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that calls an eBPF helper function.
%% @end
%%--------------------------------------------------------------------
-spec emit_call(bpf_helper()) -> bpf_instruction().
emit_call(Func) ->
    #bpf_instruction{code = {jmp64, k, call}, imm = bpf_helper_to_int(Func)}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that returns from the
%% current function.
%% @end
%%--------------------------------------------------------------------
-spec exit_insn() -> bpf_instruction().
exit_insn() ->
    #bpf_instruction{code = {jmp64, k, exit}}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that stores Imm in the memory
%% location pointed by Dst's value plus Off.
%% @end
%%--------------------------------------------------------------------
-spec st_mem(bpf_size(), bpf_reg(), bpf_off(), bpf_imm()) -> bpf_instruction().
st_mem(Size, Dst, Off, Imm) ->
    #bpf_instruction{
        code = {st, Size, mem},
        dst_reg = Dst,
        off = Off,
        imm = Imm
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that loads a 64 bit
%% immediate value computed from (Imm1 bsl 32) bor Imm2 into Dst.
%% Src should be set to 0.
%% @end
%%--------------------------------------------------------------------
-spec ld_imm64_raw_full(bpf_reg(), bpf_reg(), bpf_off(), bpf_off(), bpf_imm(), bpf_imm()) ->
    [bpf_instruction()].
ld_imm64_raw_full(Dst, Src, Off1, Off2, Imm1, Imm2) ->
    [
        #bpf_instruction{
            code = {ld, dw, imm},
            dst_reg = Dst,
            src_reg = Src,
            off = Off1,
            imm = Imm1
        },
        #bpf_instruction{
            code = {ld, w, imm},
            off = Off2,
            imm = Imm2
        }
    ].

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that loads the memory
%% address of an eBPF map given by MapFd into Dst.
%% @end
%%--------------------------------------------------------------------
-spec ld_map_fd(bpf_reg(), bpf_imm()) -> [bpf_instruction()].
ld_map_fd(Dst, MapFd) ->
    ld_imm64_raw_full(Dst, ?BPF_PSEUDO_MAP_FD, 0, 0, MapFd, 0).

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that stores the value of Src in the
%% memory location pointed by Dst's value plus Off.
%% @end
%%--------------------------------------------------------------------
-spec stx_mem(bpf_size(), bpf_reg(), bpf_reg(), bpf_off()) -> bpf_instruction().
stx_mem(Size, Dst, Src, Off) ->
    #bpf_instruction{
        code = {stx, Size, mem},
        dst_reg = Dst,
        src_reg = Src,
        off = Off
    }.

%%--------------------------------------------------------------------
%% @doc
%% Same as stack_printk/2, with StackHead set to 0.
%% @end
%%--------------------------------------------------------------------
-spec stack_printk(string()) -> [bpf_instruction()].
stack_printk(String) ->
    stack_printk(String, 0).

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that stores a string on
%% the eBPF stack and prints it with the trace_printk helper function.
%% The stack is overwritten from
%% StackHead-byte_size(String) to StackHead.
%% @end
%%--------------------------------------------------------------------
-spec stack_printk(string(), integer()) -> [bpf_instruction()].
stack_printk(String, StackHead) ->
    {Instructions0, NewStackHead} = push_string(String, StackHead),
    Instructions =
        Instructions0 ++
            [
                mov64_reg(1, 10),
                alu64_imm(add, 1, NewStackHead),
                mov64_imm(2, -NewStackHead),
                emit_call(trace_printk)
            ],
    Instructions.

%%--------------------------------------------------------------------
%% @doc
%% Same as push_string/2, with StackHead set to 0.
%% @end
%%--------------------------------------------------------------------
-spec push_string(string()) -> {[bpf_instruction()], integer()}.
push_string(String) ->
    push_string(String, 0).

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that stores a string on
%% the eBPF stack from offset StackHead-size(String) to StackHead.
%% @end
%%--------------------------------------------------------------------
-spec push_string(string(), integer()) -> {[bpf_instruction()], integer()}.
push_string(String, StackHead) ->
    push_binary(list_to_binary(String), StackHead).

%%--------------------------------------------------------------------
%% @doc
%% Same as push_binary/2, with StackHead set to 0.
%% @end
%%--------------------------------------------------------------------
-spec push_binary(binary()) -> {[bpf_instruction()], integer()}.
push_binary(Bin) ->
    push_binary(Bin, 0).

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that stores a binary on
%% the eBPF stack from offset StackHead-size(String) to StackHead.
%% @end
%%--------------------------------------------------------------------
-spec push_binary(binary(), integer()) -> {[bpf_instruction()], integer()}.
push_binary(Bin, Head) ->
    Size = byte_size(Bin),
    NewHead = Head - (Size + ((4 - (Size rem 4)) rem 4)),
    {store_buffer(Bin, NewHead), NewHead}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec store_buffer(binary(), integer()) -> [bpf_instruction()].
store_buffer(Bin, Off) ->
    store_buffer(Bin, Off, []).

-spec store_buffer(binary(), integer(), [bpf_instruction()]) -> [bpf_instruction()].
store_buffer(<<Imm:32/big-signed-integer, Bin/binary>>, Off, Acc) ->
    store_buffer(Bin, Off + 4, [st_mem(w, 10, Off, Imm) | Acc]);
store_buffer(<<>>, _Off, Acc) ->
    Acc;
store_buffer(BinImm, Off, Acc) ->
    store_buffer(<<BinImm/binary, 0:(32 - bit_size(BinImm))>>, Off, Acc).

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
