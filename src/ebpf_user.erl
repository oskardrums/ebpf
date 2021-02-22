%%%-------------------------------------------------------------------
%%% @author moskar <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, moskar
%%% @doc
%%% Interactions with the eBPF system
%%%
%%% `ebpf_user' contains functions that expose the Linux eBPF userspace API,
%%% including loading, debugging and applying eBPF programs.
%%%
%%% For generating binary eBPF programs see {@link ebpf_asm} and {@link ebpf_kern}.
%%% Note that the functions in this module can work with any
%%% binary eBPF program, not only those created via `ebpf'.
%%%
%%% @end
%%% Created :  7 Feb 2021 by user <moskar.drummer@gmail.home>
%%%-------------------------------------------------------------------
-module(ebpf_user).

%% API
-export([
    load/2,
    load/3,
    test/4,
    create_map/5,
    update_map_element/4,
    lookup_map_element/4,
    delete_map_element/2,
    get_map_next_key/2,
    attach_socket_filter/2,
    detach_socket_filter/1,
    attach_xdp/2,
    detach_xdp/1,
    close/1,
    fd/1
]).

-on_load(init/0).

-define(APPNAME, ebpf).
-define(LIBNAME, ?MODULE).

-type bpf_prog_type() ::
    'unspec'
    | 'socket_filter'
    | 'kprobe'
    | 'sched_cls'
    | 'sched_act'
    | 'tracepoint'
    | 'xdp'
    | 'perf_event'
    | 'cgroup_skb'
    | 'cgroup_sock'
    | 'lwt_in'
    | 'lwt_out'
    | 'lwt_xmit'
    | 'sock_ops'
    | 'sk_skb'
    | 'cgroup_device'
    | 'sk_msg'
    | 'raw_tracepoint'
    | 'cgroup_sock_addr'
    | 'lwt_seg6local'
    | 'lirc_mode2'
    | 'sk_reuseport'
    | 'flow_dissector'
    | 'cgroup_sysctl'
    | 'raw_tracepoint_writable'
    | 'cgroup_sockopt'
    | 'tracing'
    | 'struct_ops'
    | 'ext'
    | 'lsm'
    | 'sk_lookup'.
%% An `atom' used to specify the type of an eBPF program, see {@link load/2}

-type bpf_map_type() ::
    'unspec'
    | 'hash'
    | 'array'
    | 'prog_array'
    | 'perf_event_array'
    | 'percpu_hash'
    | 'percpu_array'
    | 'stack_trace'
    | 'cgroup_array'
    | 'lru_hash'
    | 'lru_percpu_hash'
    | 'lpm_trie'
    | 'array_of_maps'
    | 'hash_of_maps'
    | 'devmap'
    | 'sockmap'
    | 'cpumap'
    | 'xskmap'
    | 'sockhash'
    | 'cgroup_storage'
    | 'reuseport_sockarray'
    | 'percpu_cgroup_storage'
    | 'queue'
    | 'stack'
    | 'sk_storage'
    | 'devmap_hash'
    | 'struct_ops'
    | 'ringbuf'
    | 'inode_storage'
    | 'task_storage'.
%% An `atom' used to specify the type of an eBPF map, see {@link create_map/4}

-opaque bpf_map() :: integer().
%% An open eBPF map as returned by {@link create_map/4}.

-opaque prog() :: integer().
%% A loaded eBPF program as returned by {@link load/2}.

-type load_option() ::
    'sleepable'
    | {'log_buffer_size', non_neg_integer()}
    | {'license', string()}.

-export_type([bpf_map/0, prog/0]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Loads an eBPF program in binary form to the kernel.
%%
%% The program is verified by the kernel's verifier before returning
%% a handle to the loaded program to the caller.
%%
%% The following `Options' are currently supported:
%%
%% `sleepable' - Loads the eBPF program as sleepable, meaning it can
%% use eBPF helpers that might sleep, e.g. `copy_from_user', but it
%% can only be attached to certain sleepable kernel contexts.
%% Defaults to non-sleepable.
%%
%% `{log_buffer_size, non_neg_integer()}' - Specifies the size of the
%% log buffer used by the kernel's verifier. If set to 0, verifier logs
%% are disabled, otherwise this call returns also the verifier's log
%% as a `string()'.
%% Defaults to 0, i.e. logging is disabled.
%%
%% Note: if `log_buffer_size' is specified to a positive value, but
%% the specified size is found to be insufficient during verification,
%% the kernel may return an error even if the program would otherwise
%% be valid. In that case either specify a bigger `log_buffer_size'
%% or disable the verifier's log completely with `{log_buffer_size, 0}'.
%% `{license, string()}' - Specifies the license for `BinProg'.
%% Some eBPF helpers may only be used by GPL-comliant eBPF programs.
%% Defaults to `""'.
%% @end
%%--------------------------------------------------------------------
-spec load(bpf_prog_type(), binary(), [load_option()]) ->
    {'ok', prog()} | {'ok', prog(), string()} | {'error', atom()} | {'error', atom(), string()}.
load(ProgType, BinProg, Options) ->
    {Flags, LogBufferSize, License} = read_load_options(Options),
    bpf_load_program(
        bpf_prog_type_to_int(ProgType),
        BinProg,
        LogBufferSize,
        License,
        Flags
    ).

%%--------------------------------------------------------------------
%% @doc
%% Same as {@link load/3}, with default options.
%% @end
%%--------------------------------------------------------------------
-spec load(bpf_prog_type(), binary()) ->
    {'ok', prog()} | {'ok', prog(), string()} | {'error', atom()} | {'error', atom(), string()}.
load(ProgType, BinProg) ->
    load(ProgType, BinProg, []).

%%--------------------------------------------------------------------
%% @doc
%% Performs a test run of Prog with Data as input.
%%
%% WARNING: only use with trusted eBPF programs.
%% This function uses the `BPF_PROG_TEST_RUN' Linux feature, which
%% is unfortunately inherently unsafe if not used correctly. The way
%% `BPF_PROG_TEST_RUN' works is that the kernel will write `DataOut',
%% created by applying `Prog' to `Data', into a userspace buffer of some
%% predetermined size, exposed in this function as `DataOutSize'.
%% In most cases this is fine because Prog shouldn't create extensively large
%% `DataOut' in normal use case, but in case where Prog might create an
%% output that is larger DataOutSize, this can lead to buffer overflow.
%% Hence the warning.
%%
%% If `DataOut' is not needed, `DataOutSize' should be set to `0' in which case no `DataOut' will be created.
%%
%% On success, returns the return value of `Prog(Data)', as well as `DataOut'
%% and the duration of the test as reported by the kernel.
%% @end
%%--------------------------------------------------------------------
-spec test(prog(), integer(), binary(), non_neg_integer()) ->
    {'ok', Ret :: non_neg_integer(), DataOut :: binary(), Duration :: non_neg_integer()}
    | {'error', atom()}.
test(Prog, Repeat, Data, DataOutSize) ->
    bpf_test_program(
        Prog,
        Repeat,
        Data,
        DataOutSize
    ).

%%--------------------------------------------------------------------
%% @doc
%% Creates a new eBPF map.
%%
%% If successful, the returned map can be passed to eBPF programs via
%% {@link ebpf_kern:ld_map_fd/2} and manipulated from userspace via the
%% `*_map_element' functions in this module.
%%
%% KeySize and ValueSize are given in octets.
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
%% Sets the value associated with Key in eBPF map Map to Value.
%% @end
%%--------------------------------------------------------------------
-spec update_map_element(
    bpf_map(),
    binary(),
    binary(),
    non_neg_integer()
) -> 'ok' | {'error', atom()}.
update_map_element(Map, Key, Value, Flags) ->
    bpf_update_map_element(
        Map,
        Key,
        Value,
        Flags
    ).

%%--------------------------------------------------------------------
%% @doc
%% Retrieves the value associated with Key in eBPF map Map.
%% @end
%%--------------------------------------------------------------------
-spec lookup_map_element(
    bpf_map(),
    binary(),
    non_neg_integer(),
    non_neg_integer()
) -> {'ok', binary()} | {'error', atom()}.
lookup_map_element(Map, Key, ValueSize, Flags) ->
    bpf_lookup_map_element(
        Map,
        Key,
        ValueSize,
        Flags
    ).

%%--------------------------------------------------------------------
%% @doc
%% Deletes the value associated with Key in eBPF map Map.
%% @end
%%--------------------------------------------------------------------
-spec delete_map_element(bpf_map(), binary()) -> 'ok' | {'error', atom()}.
delete_map_element(Map, Key) ->
    bpf_delete_map_element(Map, Key).

%%--------------------------------------------------------------------
%% @doc
%% Retries the next key after Key in the eBPF map Map.
%%
%% If Key is not in Map, returns the first key in Map.
%%
%% If Key is the last key in Map, returns `{error, enoent}'.
%% @end
%%--------------------------------------------------------------------
-spec get_map_next_key(bpf_map(), binary()) -> {'ok', binary()} | {'error', atom()}.
get_map_next_key(Map, Key) ->
    bpf_get_map_next_key(Map, Key).

%%--------------------------------------------------------------------
%% @doc
%% Applies a loaded eBPF program as returned by {@link load/2} with
%% `socket_filter' as `ProgType' to a socket.
%% @end
%%--------------------------------------------------------------------
-spec attach_socket_filter(socket:socket(), prog()) -> 'ok' | {'error', atom()}.
attach_socket_filter(Sock, Prog) ->
    {ok, SockFd} = socket:getopt(Sock, otp, fd),
    bpf_attach_socket_filter(
        SockFd,
        Prog
    ).

%%--------------------------------------------------------------------
%% @doc
%% Removes the eBPF program attached to socket `Sock'.
%% @end
%%--------------------------------------------------------------------
-spec detach_socket_filter(socket:socket()) -> 'ok' | {'error', atom()}.
detach_socket_filter(Sock) ->
    {ok, SockFd} = socket:getopt(Sock, otp, fd),
    bpf_detach_socket_filter(SockFd).

%%--------------------------------------------------------------------
%% @doc
%% Applies a loaded eBPF XDP program as returned by {@link load/2}
%% with `xdp' a `ProgType' to a network interface.
%% @end
%%--------------------------------------------------------------------
-spec attach_xdp(string() | non_neg_integer(), prog()) -> 'ok' | {'error', atom()}.
attach_xdp(Interface, Prog) when is_integer(Interface) ->
    % Interface is an interface index
    bpf_attach_xdp(Interface, Prog);
attach_xdp(Interface, Prog) when is_list(Interface) ->
    % Interface is an interface name
    {ok, IfIndex} = net:if_name2index(Interface),
    bpf_attach_xdp(IfIndex, Prog).

%%--------------------------------------------------------------------
%% @doc
%% Removes the attached eBPF XDP program from a network interface.
%% @end
%%--------------------------------------------------------------------
-spec detach_xdp(string() | non_neg_integer()) -> 'ok' | {'error', atom()}.
detach_xdp(Interface) when is_integer(Interface) ->
    bpf_attach_xdp(Interface, -1);
detach_xdp(Interface) when is_list(Interface) ->
    {ok, IfIndex} = net:if_name2index(Interface),
    bpf_attach_xdp(IfIndex, -1).

%%--------------------------------------------------------------------
%% @doc
%% Closes an eBPF map or program.
%% @end
%%--------------------------------------------------------------------
-spec close(bpf_map() | prog()) -> 'ok' | {'error', atom()}.
close(ProgOrMap) ->
    bpf_close(ProgOrMap).

%%--------------------------------------------------------------------
%% @doc
%% Returns a File Descriptor for eBPF program or map.
%%
%% Can be used for passing a map to eBPF programs, e.g. via {@link ebpf_kern:ld_map_fd/2}.
%% @end
%%--------------------------------------------------------------------
-spec fd(bpf_map() | prog()) -> non_neg_integer() | {'error', atom()}.
fd(ProgOrMap) -> ProgOrMap.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%-------------------------------------------------------------------
%%% NIFs and NIF related functions
%%%-------------------------------------------------------------------

-spec bpf_load_program(
    non_neg_integer(),
    binary(),
    non_neg_integer(),
    string(),
    non_neg_integer()
) -> {'ok', non_neg_integer()} | {'error', atom()}.
bpf_load_program(_ProgType, _BinProg, _LogBufferSize, _License, _Flags) ->
    not_loaded(?LINE).

-spec bpf_attach_socket_filter(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', atom()}.
bpf_attach_socket_filter(_SockFd, _ProgFd) ->
    not_loaded(?LINE).

-spec bpf_detach_socket_filter(non_neg_integer()) -> 'ok' | {'error', atom()}.
bpf_detach_socket_filter(_SockFd) ->
    not_loaded(?LINE).

-spec bpf_attach_xdp(non_neg_integer(), integer()) -> 'ok' | {'error', atom()}.
bpf_attach_xdp(_IfIndex, _ProgFd) ->
    not_loaded(?LINE).

-spec bpf_create_map(non_neg_integer(), integer(), integer(), integer(), non_neg_integer()) ->
    {'ok', non_neg_integer()} | {'error', atom()}.
bpf_create_map(_Type, _KeySize, _ValueSize, _MaxEntries, _Flags) ->
    not_loaded(?LINE).

-spec bpf_update_map_element(bpf_map(), binary(), binary(), non_neg_integer()) ->
    'ok' | {'error', atom()}.
bpf_update_map_element(_Map, _Key, _Value, _Flags) ->
    not_loaded(?LINE).

-spec bpf_lookup_map_element(bpf_map(), binary(), non_neg_integer(), non_neg_integer()) ->
    {'ok', binary()} | {'error', atom()}.
bpf_lookup_map_element(_Map, _Key, _ValueSize, _Flags) ->
    not_loaded(?LINE).

-spec bpf_delete_map_element(bpf_map(), binary()) -> 'ok' | {'error', atom()}.
bpf_delete_map_element(_Map, _Key) ->
    not_loaded(?LINE).

-spec bpf_get_map_next_key(bpf_map(), binary()) -> {'ok', binary()} | {'error', atom()}.
bpf_get_map_next_key(_Map, _Key) ->
    not_loaded(?LINE).

-spec bpf_test_program(prog(), integer(), binary(), non_neg_integer()) ->
    {'ok', non_neg_integer(), binary(), non_neg_integer()} | {'error', atom()}.
bpf_test_program(_Prog, _Repeat, _Data, _DataOutSize) ->
    not_loaded(?LINE).

-spec bpf_close(integer()) -> 'ok' | {'error', atom()}.
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
-spec read_load_options([load_option()]) -> {non_neg_integer(), non_neg_integer(), string()}.
read_load_options(Options) ->
    read_load_options(Options, {0, 0, ""}).

-spec read_load_options([load_option()], {non_neg_integer(), non_neg_integer(), string()}) ->
    {non_neg_integer(), non_neg_integer(), string()}.
read_load_options([sleepable | More], {Flags0, LogBufferSize0, License0}) ->
    read_load_options(More, {Flags0 bor (1 bsl 4), LogBufferSize0, License0});
read_load_options(
    [{log_buffer_size, LogBufferSize} | More],
    {Flags0, _LogBufferSize0, License0}
) ->
    read_load_options(More, {Flags0, LogBufferSize, License0});
read_load_options([{license, License} | More], {Flags0, LogBufferSize0, _License0}) ->
    read_load_options(More, {Flags0, LogBufferSize0, License});
read_load_options([], Acc) ->
    Acc.

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
