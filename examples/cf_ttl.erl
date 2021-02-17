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

-spec attach_ttl_bpf(integer()) -> {'ok', ebpf_user:bpf_map()}.
attach_ttl_bpf(SockFd) ->
    {ok, Map} = ebpf_user:create_map(hash, 4, 8, 4, 0),
    MapFd = ebpf_user:fd(Map),
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
        ebpf_kern:ld_map_fd(1, MapFd),
        ebpf_kern:call_helper(map_lookup_elem),
        ebpf_kern:jmp64_imm(eq, 0, 0, 3),
        ebpf_kern:mov64_imm(1, 1),
        ebpf_kern:stx_xadd(dw, 0, 1, 0),
        ebpf_kern:jmp_a(9),
        ebpf_kern:ld_map_fd(1, MapFd),
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
    ok = ebpf_user:attach_socket_filter(SockFd, Prog),
    {ok, Map}.

-spec read_ttl_bpf(ebpf_user:bpf_map()) -> 'empty' | {'ok', non_neg_integer()} | {error, term()}.
read_ttl_bpf(Map) ->
    read_ttl_bpf(Map, <<0:32>>, empty).

-spec read_ttl_bpf(ebpf_user:bpf_map(), binary(), 'empty' | non_neg_integer()) ->
    'empty' | {'ok', non_neg_integer()} | {error, term()}.
read_ttl_bpf(Map, Key, Min) ->
    case ebpf_user:get_map_next_key(Map, Key) of
        {error, enoent} ->
            Min;
        {ok, <<Ttl:32/little-unsigned-integer>>} ->
            io:format("~p~n~n", [Ttl]),
            if
                Ttl > 128 -> {ok, min(Min, 255 - Ttl)};
                Ttl > 64 -> {ok, min(Min, 128 - Ttl)};
                Ttl > 32 -> {ok, min(Min, 64 - Ttl)};
                true -> {ok, min(Min, 32 - Ttl)}
            end;
        Other ->
            {error, Other}
    end.
