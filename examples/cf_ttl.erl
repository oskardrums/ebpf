%%%-------------------------------------------------------------------
%%% @author Oskar Mazerath <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, Oskar Mazerath
%%% @doc
%%% An `ebpf' based implementation of Cloudflare's [https://github.com/cloudflare/cloudflare-blog/blob/master/2018-03-ebpf/ebpf.go].
%%% @end
%%% Created : 13 Feb 2021 by Oskar Mazerath <moskar.drummer@gmail.com>
%%%-------------------------------------------------------------------
-module(cf_ttl).

-export([attach_ttl_bpf/1]).

-spec attach_ttl_bpf(integer()) -> 'ok'.
attach_ttl_bpf(SockFd) ->
    {ok, Map} = ebpf_user:create_map(hash, 4, 8, 4, 0),
    Instructions = lists:flatten([
        ebpf_kern:ldx_mem(w, 0, 1, 16),
        ebpf_kern:jmp64_imm(eq, 0, 16#86DD0000, 3),
        ebpf_kern:mov64_reg(6, 1),
        ebpf_kern:ld_abs(b, -16#100000 + 8),
        ebpf_kern:jmp_a(2),
        ebpf_kern:mov64_reg(6, 1),
        ebpf_kern:ld_abs(b, -16#100000 + 7),
        ebpf_kern:stx_mem(w, 10, 0, -4),
        ebpf_kern:mov64_reg(2, 10),
        ebpf_kern:alu64_imm(add, 2, -4),
        ebpf_kern:ld_map_fd(1, Map),
        ebpf_kern:call_helper(map_lookup_elem),
        ebpf_kern:jmp64_imm(eq, 0, 0, 3),
        ebpf_kern:mov64_imm(1, 1),
        ebpf_kern:stx_xadd(dw, 0, 1, 0),
        ebpf_kern:jmp_a(9),
        ebpf_kern:ld_map_fd(1, Map),
        ebpf_kern:mov64_reg(2, 10),
        ebpf_kern:alu64_imm(add, 2, -4),
        ebpf_kern:st_mem(dw, 10, -16, 1),
        ebpf_kern:mov64_reg(3, 10),
        ebpf_kern:alu64_imm(add, 3, -16),
        ebpf_kern:mov64_imm(4, 0),
        ebpf_kern:call_helper(map_update_elem),
        ebpf_kern:mov64_imm(0, -1),
        ebpf_kern:exit_insn()
    ]),
    {ok, Prog} = ebpf_user:load(socket_filter, ebpf_asm:assemble(Instructions)),
    ok = ebpf_user:attach_socket_filter(SockFd, Prog).
