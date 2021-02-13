%%%-------------------------------------------------------------------
%%% @author moskar <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, moskar
%%% @doc
%%% Interactions with the eBPF system
%%% @end
%%% Created :  7 Feb 2021 by user <moskar.drummer@gmail.home>
%%%-------------------------------------------------------------------
-module(ebpf_user).

%% API
-export([
    load/2,
    verify/2,
    verify/3,
    create_map/5,
    attach_socket_filter/2,
    attach_xdp/2,
    close/1
]).

-on_load(init/0).

-define(APPNAME, ebpf).
-define(LIBNAME, ?MODULE).

-include("ebpf_user.hrl").
-export_type([bpf_map/0, bpf_prog/0]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% same as verify/3 with default options.
%% @end
%%--------------------------------------------------------------------
-spec verify(bpf_prog_type(), binary()) ->
    {'ok', string()} | {'error', atom()} | {'error', atom(), string()}.
verify(BpfProgramType, BpfProgramBin) ->
    verify(BpfProgramType, BpfProgramBin, []).

%%--------------------------------------------------------------------
%% @doc
%% Verifies an eBPF program in binary form with the kernel's verifier.
%% Reports errors in the program, if any, in textual form as returned
%% by the kernel.
%%
%% The default values for unspecified options are:
%% * {log_buffer_size, 4096}
%% * {kernel_version, 0}
%% * {license, "GPL"}
%% @end
%%--------------------------------------------------------------------
-spec verify(bpf_prog_type(), binary(), [
    {log_buffer_size, non_neg_integer()}
    | {kernel_version, non_neg_integer()}
    | {license, string()}
]) -> {'ok', string()} | {'error', atom()} | {'error', atom(), string()}.
verify(BpfProgramType, BpfProgramBin, Options) ->
    LogBufferSize = proplists:get_value(log_buffer_size, Options, 4096),
    KernelVersion = proplists:get_value(kernel_version, Options, 0),
    License = proplists:get_value(license, Options, "GPL"),
    bpf_verify_program(
        bpf_prog_type_to_int(BpfProgramType),
        BpfProgramBin,
        LogBufferSize,
        KernelVersion,
        License
    ).

%%--------------------------------------------------------------------
%% @doc
%% Attempts to load an eBPF program in binary form to the kernel.
%% see verify/1 for debugging and checking program validity.
%% @end
%%--------------------------------------------------------------------
-spec load(bpf_prog_type(), binary()) -> {'ok', non_neg_integer()} | {'error', atom()}.
load(BpfProgramType, BpfProgramBin) ->
    bpf_load_program(
        bpf_prog_type_to_int(BpfProgramType),
        BpfProgramBin
    ).

%%--------------------------------------------------------------------
%% @doc
%% Creates a new eBPF map.
%% If successful returns a file descriptor representing the created map.
%% @end
%%--------------------------------------------------------------------
-spec create_map(
    Type :: bpf_map_type(),
    KeySize :: integer(),
    ValueSize :: integer(),
    MaxEntries :: integer(),
    Flags :: non_neg_integer()
) -> {'ok', bpf_map()} | {'error', atom()}.
create_map(Type, KeySize, ValueSize, MaxEntries, Flags) ->
    bpf_create_map(
        bpf_map_type_to_int(Type),
        KeySize,
        ValueSize,
        MaxEntries,
        Flags
    ).

%%--------------------------------------------------------------------
%% @doc
%% Applies a loaded eBPF program as returned by load/1 to a socket.
%% @end
%%--------------------------------------------------------------------
-spec attach_socket_filter(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', atom()}.
attach_socket_filter(SockFd, ProgFd) ->
    bpf_attach_socket_filter(
        SockFd,
        ProgFd
    ).

%%--------------------------------------------------------------------
%% @doc
%% Applies a loaded eBPF XDP program as returned by load/1 to
%% a network interface.
%% @end
%%--------------------------------------------------------------------
-spec attach_xdp(string() | non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', atom()}.
attach_xdp(IfIndex, ProgFd) when is_integer(IfIndex) ->
    bpf_attach_xdp(IfIndex, ProgFd);
attach_xdp(IfName, ProgFd) when is_list(IfName) ->
    {ok, IfIndex} = net:if_name2index(IfName),
    bpf_attach_xdp(IfIndex, ProgFd).

%%--------------------------------------------------------------------
%% @doc
%% Closes an eBPF map or program.
%% @end
%%--------------------------------------------------------------------
-spec close(bpf_map() | integer()) -> 'ok' | {'error', atom()}.
close(Fd) ->
    bpf_close(Fd).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%-------------------------------------------------------------------
%%% NIFs and NIF related functions
%%%-------------------------------------------------------------------

-spec bpf_verify_program(
    non_neg_integer(),
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    string()
) -> {'ok', string()} | {'error', atom()} | {'error', atom(), string()}.
bpf_verify_program(_BpfProgramType, _BpfProgramBin, _LogBufferSize, _KernelVersion, _License) ->
    not_loaded(?LINE).

-spec bpf_load_program(non_neg_integer(), binary()) ->
    {'ok', non_neg_integer()} | {'error', atom()}.
bpf_load_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

-spec bpf_attach_socket_filter(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', atom()}.
bpf_attach_socket_filter(_SockFd, _ProgFd) ->
    not_loaded(?LINE).

-spec bpf_attach_xdp(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', atom()}.
bpf_attach_xdp(_IfIndex, _ProgFd) ->
    not_loaded(?LINE).

-spec bpf_create_map(non_neg_integer(), integer(), integer(), integer(), non_neg_integer()) ->
    {'ok', non_neg_integer()} | {'error', atom()}.
bpf_create_map(_Type, _KeySize, _ValueSize, _MaxEntries, _Flags) ->
    not_loaded(?LINE).

-spec bpf_close(integer()) -> {'ok'} | {'error', atom()}.
bpf_close(_Fd) ->
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

-spec bpf_prog_type_to_int(bpf_prog_type()) -> ebpf_kern:bpf_imm().
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

-spec bpf_map_type_to_int(bpf_map_type()) -> ebpf_kern:bpf_imm().
bpf_map_type_to_int(unspec) -> 0;
bpf_map_type_to_int(hash) -> 1;
bpf_map_type_to_int(array) -> 2;
bpf_map_type_to_int(prog_array) -> 3;
bpf_map_type_to_int(perf_event_array) -> 4;
bpf_map_type_to_int(percpu_hash) -> 5;
bpf_map_type_to_int(percpu_array) -> 6;
bpf_map_type_to_int(stack_trace) -> 7;
bpf_map_type_to_int(cgroup_array) -> 8;
bpf_map_type_to_int(lru_hash) -> 9;
bpf_map_type_to_int(lru_percpu_hash) -> 10;
bpf_map_type_to_int(lpm_trie) -> 11;
bpf_map_type_to_int(array_of_maps) -> 12;
bpf_map_type_to_int(hash_of_maps) -> 13;
bpf_map_type_to_int(devmap) -> 14;
bpf_map_type_to_int(sockmap) -> 15;
bpf_map_type_to_int(cpumap) -> 16;
bpf_map_type_to_int(xskmap) -> 17;
bpf_map_type_to_int(sockhash) -> 18;
bpf_map_type_to_int(cgroup_storage) -> 19;
bpf_map_type_to_int(reuseport_sockarray) -> 20;
bpf_map_type_to_int(percpu_cgroup_storage) -> 21;
bpf_map_type_to_int(queue) -> 22;
bpf_map_type_to_int(stack) -> 23;
bpf_map_type_to_int(sk_storage) -> 24;
bpf_map_type_to_int(devmap_hash) -> 25;
bpf_map_type_to_int(struct_ops) -> 26;
bpf_map_type_to_int(ringbuf) -> 27;
bpf_map_type_to_int(inode_storage) -> 28;
bpf_map_type_to_int(task_storage) -> 29.
