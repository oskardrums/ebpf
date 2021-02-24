%%%-------------------------------------------------------------------
%%% @author Oskar Mazerath <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, Oskar Mazerath
%%% @doc
%%% An `ebpf' based implementation of Cloudflare's [https://github.com/cloudflare/cloudflare-blog/blob/master/2018-03-ebpf/ebpf.go].
%%% @end
%%% Created : 13 Feb 2021 by Oskar Mazerath <moskar.drummer@gmail.com>
%%%-------------------------------------------------------------------
-module(cf_ttl).

-export([attach_ttl_bpf/1, read_ttl_bpf/1]).

-spec attach_ttl_bpf(socket:socket()) -> {'ok', ebpf_maps:ebpf_map()}.
attach_ttl_bpf(Sock) ->
    {ok, Map} = ebpf_maps:new(hash, 4, 8, 4),
    MapFd = ebpf_maps:fd(Map),
    Instructions = lists:flatten([
        ebpf_kern:ldx_mem(w, r0, r1, 16),
        ebpf_kern:jmp64_imm(eq, r0, 16#86DD, 3),
        ebpf_kern:mov64_reg(r6, r1),
        ebpf_kern:ld_abs(b, -16#100000 + 8),
        ebpf_kern:jmp_a(2),
        ebpf_kern:mov64_reg(r6, r1),
        ebpf_kern:ld_abs(b, -16#100000 + 7),
        ebpf_kern:stx_mem(w, r10, r0, -4),
        ebpf_kern:mov64_reg(r2, r10),
        ebpf_kern:alu64_imm(add, r2, -4),
        ebpf_kern:ld_map_fd(r1, MapFd),
        ebpf_kern:call_helper(map_lookup_elem),
        ebpf_kern:jmp64_imm(eq, r0, 0, 3),
        ebpf_kern:mov64_imm(r1, 1),
        ebpf_kern:stx_xadd(dw, r0, r1, 0),
        ebpf_kern:jmp_a(9),
        ebpf_kern:ld_map_fd(r1, MapFd),
        ebpf_kern:mov64_reg(r2, r10),
        ebpf_kern:alu64_imm(add, r2, -4),
        ebpf_kern:st_mem(dw, r10, -16, 1),
        ebpf_kern:mov64_reg(r3, r10),
        ebpf_kern:alu64_imm(add, r3, -16),
        ebpf_kern:mov64_imm(r4, 0),
        ebpf_kern:call_helper(map_update_elem),
        ebpf_kern:mov64_imm(r0, -1),
        ebpf_kern:exit_insn()
    ]),
    {ok, Prog} = ebpf_user:load(socket_filter, ebpf_asm:assemble(Instructions)),
    ok = ebpf_user:attach_socket_filter(Sock, Prog),
    {ok, Map}.

-spec read_ttl_bpf(ebpf_maps:ebpf_map()) -> 'empty' | {'ok', non_neg_integer()} | {error, term()}.
read_ttl_bpf(Map) ->
    read_ttl_bpf(ebpf_maps:next(ebpf_maps:iterator(Map)), error).

-spec read_ttl_bpf('none' | {<<_:32>>, _, _}, _) -> {'ok', _}.
read_ttl_bpf(none, Min) ->
    {ok, Min};
read_ttl_bpf({Key, _Value, Iterator}, Min) ->
    <<Ttl:32/little-unsigned-integer>> = Key,
    if
        Ttl > 128 -> read_ttl_bpf(ebpf_maps:next(Iterator), min(Min, 255 - Ttl));
        Ttl > 64 -> read_ttl_bpf(ebpf_maps:next(Iterator), min(Min, 128 - Ttl));
        Ttl > 32 -> read_ttl_bpf(ebpf_maps:next(Iterator), min(Min, 64 - Ttl));
        true -> read_ttl_bpf(ebpf_maps:next(Iterator), min(Min, 32 - Ttl))
    end.
