%% instruction classes
-define(BPF_CLASS(Code), Code band 16#07).
-define(BPF_LD, 16#00).
-define(BPF_LDX, 16#01).
-define(BPF_ST, 16#02).
-define(BPF_STX, 16#03).
-define(BPF_ALU, 16#04).
-define(BPF_JMP, 16#05).
-define(BPF_RET, 16#06).
-define(BPF_MISC, 16#07).
-define(BPF_JMP32, 16#06).
-define(BPF_ALU64, 16#07).
%% ld/ldx fields
-define(BPF_SIZE(Code), Code band 16#18).
-define(BPF_W, 16#00).
-define(BPF_H, 16#08).
-define(BPF_B, 16#10).
-define(BPF_DW, 16#18).

-define(BPF_MODE(Code), Code band 16#e0).
-define(BPF_IMM, 16#00).
-define(BPF_ABS, 16#20).
-define(BPF_IND, 16#40).
-define(BPF_MEM, 16#60).
-define(BPF_LEN, 16#80).
-define(BPF_MSH, 16#a0).
-define(BPF_XADD, 16#c0).

%% alu/jmp fields
-define(BPF_OP(Code), Code band 16#f0).
-define(BPF_ADD, 16#00).
-define(BPF_SUB, 16#10).
-define(BPF_MUL, 16#20).
-define(BPF_DIV, 16#30).
-define(BPF_OR, 16#40).
-define(BPF_AND, 16#50).
-define(BPF_LSH, 16#60).
-define(BPF_RSH, 16#70).
-define(BPF_NEG, 16#80).
-define(BPF_MOD, 16#90).
-define(BPF_XOR, 16#a0).
-define(BPF_MOV, 16#b0).
-define(BPF_ARSH, 16#c0).
-define(BPF_JA, 16#00).
-define(BPF_JEQ, 16#10).
-define(BPF_JGT, 16#20).
-define(BPF_JGE, 16#30).
-define(BPF_JSET, 16#40).

-define(BPF_JNE, 16#50).
-define(BPF_JLT, 16#a0).
-define(BPF_JLE, 16#b0).
-define(BPF_JSGT, 16#60).
-define(BPF_JSGE, 16#70).
-define(BPF_JSLT, 16#c0).
-define(BPF_JSLE, 16#d0).
-define(BPF_CALL, 16#80).
-define(BPF_EXIT, 16#90).

-define(BPF_END, 16#d0).
-define(BPF_TO_L, 16#00).
-define(BPF_TO_B, 16#08).
-define(BPF_FROM_LE, ?BPF_TO_LE).
-define(BPF_FROM_BE, ?BPF_TO_BE).

-define(BPF_SRC(Code), Code band 16#08).

-define(BPF_K, 16#00).
-define(BPF_X, 16#08).
%% ret - BPF_K and BPF_X also apply
-define(BPF_RVAL(Code), Code band 16#18).
-define(BPF_A, 16#10).
%% misc
-define(BPF_MISCOP(Code), Code band 16#f8).
-define(BPF_TAX, 16#00).
-define(BPF_TXA, 16#80).

-define(BPF_PSEUDO_MAP_FD, 1).
-define(BPF_PSEUDO_MAP_VALUE, 2).

-type bpf_ld_mode() :: 'imm' | 'abs' | 'mem' | 'ind' | 'xadd'.

-type bpf_alu_op() ::
    'add'
    | 'and'
    | 'arsh'
    | 'div'
    | 'lsh'
    | 'mod'
    | 'mov'
    | 'mul'
    | 'neg'
    | 'or'
    | 'rsh'
    | 'sub'
    | 'xor'.

-type bpf_helper() ::
    'unspec'
    | 'map_lookup_elem'
    | 'map_update_elem'
    | 'map_delete_elem'
    | 'probe_read'
    | 'ktime_get_ns'
    | 'trace_printk'
    | 'get_prandom_u32'
    | 'get_smp_processor_id'
    | 'skb_store_bytes'
    | 'l3_csum_replace'
    | 'l4_csum_replace'
    | 'tail_call'
    | 'clone_redirect'
    | 'get_current_pid_tgid'
    | 'get_current_uid_gid'
    | 'get_current_comm'
    | 'get_cgroup_classid'
    | 'skb_vlan_push'
    | 'skb_vlan_pop'
    | 'skb_get_tunnel_key'
    | 'skb_set_tunnel_key'
    | 'perf_event_read'
    | 'redirect'
    | 'get_route_realm'
    | 'perf_event_output'
    | 'skb_load_bytes'
    | 'get_stackid'
    | 'csum_diff'
    | 'skb_get_tunnel_opt'
    | 'skb_set_tunnel_opt'
    | 'skb_change_proto'
    | 'skb_change_type'
    | 'skb_under_cgroup'
    | 'get_hash_recalc'
    | 'get_current_task'
    | 'probe_write_user'
    | 'current_task_under_cgroup'
    | 'skb_change_tail'
    | 'skb_pull_data'
    | 'csum_update'
    | 'set_hash_invalid'
    | 'get_numa_node_id'
    | 'skb_change_head'
    | 'xdp_adjust_head'
    | 'probe_read_str'
    | 'get_socket_cookie'
    | 'get_socket_uid'
    | 'set_hash'
    | 'setsockopt'
    | 'skb_adjust_room'
    | 'redirect_map'
    | 'sk_redirect_map'
    | 'sock_map_update'
    | 'xdp_adjust_meta'
    | 'perf_event_read_value'
    | 'perf_prog_read_value'
    | 'getsockopt'
    | 'override_return'
    | 'sock_ops_cb_flags_set'
    | 'msg_redirect_map'
    | 'msg_apply_bytes'
    | 'msg_cork_bytes'
    | 'msg_pull_data'
    | 'bind'
    | 'xdp_adjust_tail'
    | 'skb_get_xfrm_state'
    | 'get_stack'
    | 'skb_load_bytes_relative'
    | 'fib_lookup'
    | 'sock_hash_update'
    | 'msg_redirect_hash'
    | 'sk_redirect_hash'
    | 'lwt_push_encap'
    | 'lwt_seg6_store_bytes'
    | 'lwt_seg6_adjust_srh'
    | 'lwt_seg6_action'
    | 'rc_repeat'
    | 'rc_keydown'
    | 'skb_cgroup_id'
    | 'get_current_cgroup_id'
    | 'get_local_storage'
    | 'sk_select_reuseport'
    | 'skb_ancestor_cgroup_id'
    | 'sk_lookup_tcp'
    | 'sk_lookup_udp'
    | 'sk_release'
    | 'map_push_elem'
    | 'map_pop_elem'
    | 'map_peek_elem'
    | 'msg_push_data'
    | 'msg_pop_data'
    | 'rc_pointer_rel'
    | 'spin_lock'
    | 'spin_unlock'
    | 'sk_fullsock'
    | 'tcp_sock'
    | 'skb_ecn_set_ce'
    | 'get_listener_sock'
    | 'skc_lookup_tcp'
    | 'tcp_check_syncookie'
    | 'sysctl_get_name'
    | 'sysctl_get_current_value'
    | 'sysctl_get_new_value'
    | 'sysctl_set_new_value'
    | 'strtol'
    | 'strtoul'
    | 'sk_storage_get'
    | 'sk_storage_delete'
    | 'send_signal'
    | 'tcp_gen_syncookie'
    | 'skb_output'
    | 'probe_read_user'
    | 'probe_read_kernel'
    | 'probe_read_user_str'
    | 'probe_read_kernel_str'
    | 'tcp_send_ack'
    | 'send_signal_thread'
    | 'jiffies64'
    | 'read_branch_records'
    | 'get_ns_current_pid_tgid'
    | 'xdp_output'
    | 'get_netns_cookie'
    | 'get_current_ancestor_cgroup_id'
    | 'sk_assign'
    | 'ktime_get_boot_ns'
    | 'seq_printf'
    | 'seq_write'
    | 'sk_cgroup_id'
    | 'sk_ancestor_cgroup_id'
    | 'ringbuf_output'
    | 'ringbuf_reserve'
    | 'ringbuf_submit'
    | 'ringbuf_discard'
    | 'ringbuf_query'
    | 'csum_level'
    | 'skc_to_tcp6_sock'
    | 'skc_to_tcp_sock'
    | 'skc_to_tcp_timewait_sock'
    | 'skc_to_tcp_request_sock'
    | 'skc_to_udp6_sock'
    | 'get_task_stack'
    | 'load_hdr_opt'
    | 'store_hdr_opt'
    | 'reserve_hdr_opt'
    | 'inode_storage_get'
    | 'inode_storage_delete'
    | 'd_path'
    | 'copy_from_user'
    | 'snprintf_btf'
    | 'seq_printf_btf'
    | 'skb_cgroup_classid'
    | 'redirect_neigh'
    | 'per_cpu_ptr'
    | 'this_cpu_ptr'
    | 'redirect_peer'
    | 'task_storage_get'
    | 'task_storage_delete'
    | 'get_current_task_btf'
    | 'bprm_opts_set'
    | 'ktime_get_coarse_ns'
    | 'ima_inode_hash'
    | 'sock_from_file'.

-type bpf_src() :: 'k' | 'x'.

-type bpf_size() :: 'b' | 'h' | 'w' | 'dw'.

-type bpf_jmp_op() ::
    'a'
    | 'eq'
    | 'gt'
    | 'ge'
    | 'set'
    | 'ne'
    | 'lt'
    | 'le'
    | 'sgt'
    | 'sge'
    | 'slt'
    | 'sle'
    | 'call'
    | 'exit'.

-type bpf_ld_st_class() :: 'ld' | 'ldx' | 'st' | 'stx'.
-type bpf_alu_class() :: 'alu32' | 'alu64'.
-type bpf_jmp_class() :: 'jmp32' | 'jmp64'.

-type bpf_opcode() ::
    {bpf_ld_st_class(), bpf_size(), bpf_ld_mode()}
    | {bpf_alu_class(), bpf_src(), bpf_alu_op()}
    | {bpf_jmp_class(), bpf_src(), bpf_jmp_op()}.
-type bpf_reg() :: 0..10.
-type bpf_off() :: 1 - (1 bsl 15)..(1 bsl 15) - 1.
-type bpf_imm() :: 1 - (1 bsl 31)..(1 bsl 31) - 1.

-record(bpf_instruction, {
    code = 0 :: bpf_opcode(),
    dst_reg = 0 :: bpf_reg(),
    src_reg = 0 :: bpf_reg(),
    off = 0 :: bpf_off(),
    imm = 0 :: bpf_imm()
}).

-type bpf_instruction() :: #bpf_instruction{}.
-type bpf_sequence() :: [bpf_instruction()].
