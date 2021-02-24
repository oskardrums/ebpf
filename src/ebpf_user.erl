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
%%% For creating and using eBPF maps see {@link ebpf_maps}.
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
    attach_socket_filter/2,
    detach_socket_filter/1,
    attach_xdp/2,
    detach_xdp/1,
    close/1,
    fd/1
]).

-type prog_type() ::
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

-record(bpf_prog, {type = unspec :: prog_type(), fd = -1 :: integer()}).
-opaque prog() :: #bpf_prog{}.
%% A loaded eBPF program as returned by {@link load/2}.

-type load_option() ::
    'sleepable'
    | {'log_buffer_size', non_neg_integer()}
    | {'license', string()}.

-export_type([prog/0]).

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
-spec load(prog_type(), binary(), [load_option()]) ->
    {'ok', prog()} | {'ok', prog(), string()} | {'error', atom()} | {'error', atom(), string()}.
load(ProgType, BinProg, Options) ->
    {Flags, LogBufferSize, License} = read_load_options(Options),
    case
        ebpf_lib:bpf_load_program(
            bpf_prog_type_to_int(ProgType),
            BinProg,
            LogBufferSize,
            License,
            Flags
        )
    of
        {ok, ProgFd} -> {ok, #bpf_prog{type = ProgType, fd = ProgFd}};
        {ok, ProgFd, Log} -> {ok, #bpf_prog{type = ProgType, fd = ProgFd}, Log};
        Other -> Other
    end.

%%--------------------------------------------------------------------
%% @doc
%% Same as {@link load/3}, with default options.
%% @end
%%--------------------------------------------------------------------
-spec load(prog_type(), binary()) ->
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
    ebpf_lib:bpf_test_program(
        Prog#bpf_prog.fd,
        Repeat,
        Data,
        DataOutSize
    ).

%%--------------------------------------------------------------------
%% @doc
%% Applies a loaded eBPF program as returned by {@link load/2} with
%% `socket_filter' as `ProgType' to a socket.
%% @end
%%--------------------------------------------------------------------
-spec attach_socket_filter(socket:socket(), prog()) -> 'ok' | {'error', atom()}.
attach_socket_filter(Sock, Prog) ->
    {ok, SockFd} = socket:getopt(Sock, otp, fd),
    ebpf_lib:bpf_attach_socket_filter(
        SockFd,
        Prog#bpf_prog.fd
    ).

%%--------------------------------------------------------------------
%% @doc
%% Removes the eBPF program attached to socket `Sock'.
%% @end
%%--------------------------------------------------------------------
-spec detach_socket_filter(socket:socket()) -> 'ok' | {'error', atom()}.
detach_socket_filter(Sock) ->
    {ok, SockFd} = socket:getopt(Sock, otp, fd),
    ebpf_lib:bpf_detach_socket_filter(SockFd).

%%--------------------------------------------------------------------
%% @doc
%% Applies a loaded eBPF XDP program as returned by {@link load/2}
%% with `xdp' a `ProgType' to a network interface.
%% @end
%%--------------------------------------------------------------------
-spec attach_xdp(string() | non_neg_integer(), prog()) -> 'ok' | {'error', atom()}.
attach_xdp(Interface, Prog) when is_integer(Interface) ->
    % Interface is an interface index
    ebpf_lib:bpf_attach_xdp(Interface, Prog#bpf_prog.fd);
attach_xdp(Interface, Prog) when is_list(Interface) ->
    % Interface is an interface name
    {ok, IfIndex} = net:if_name2index(Interface),
    ebpf_lib:bpf_attach_xdp(IfIndex, Prog#bpf_prog.fd).

%%--------------------------------------------------------------------
%% @doc
%% Removes the attached eBPF XDP program from a network interface.
%% @end
%%--------------------------------------------------------------------
-spec detach_xdp(string() | non_neg_integer()) -> 'ok' | {'error', atom()}.
detach_xdp(Interface) when is_integer(Interface) ->
    ebpf_lib:bpf_attach_xdp(Interface, -1);
detach_xdp(Interface) when is_list(Interface) ->
    {ok, IfIndex} = net:if_name2index(Interface),
    ebpf_lib:bpf_attach_xdp(IfIndex, -1).

%%--------------------------------------------------------------------
%% @doc
%% Closes `Prog'.
%% @end
%%--------------------------------------------------------------------
-spec close(prog()) -> 'ok' | {'error', atom()}.
close(Prog) ->
    ebpf_lib:bpf_close(Prog#bpf_prog.fd).

%%--------------------------------------------------------------------
%% @doc
%% Returns a File Descriptor for `Prog'.
%% @end
%%--------------------------------------------------------------------
-spec fd(prog()) -> non_neg_integer().
fd(Prog) -> Prog#bpf_prog.fd.

%%%===================================================================
%%% Internal functions
%%%===================================================================

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

-spec bpf_prog_type_to_int(prog_type()) -> ebpf_kern:bpf_imm().
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
