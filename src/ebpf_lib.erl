%%%-------------------------------------------------------------------
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ebpf_lib).

%% API
-export([load/2, verify/2]).

-on_load(init/0).

-define(APPNAME, ?MODULE).
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

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------
-spec verify(bpf_prog_type(), binary()) -> 'ok' | {'error', term()}.
verify(BpfProgramType, BpfProgramBin) ->
    ebpf_verify_program(bpf_prog_type_to_int(BpfProgramType), BpfProgramBin).

-spec load(bpf_prog_type(), binary()) -> {'ok', non_neg_integer()} | {'error', term()}.
load(BpfProgramType, BpfProgramBin) ->
    ebpf_load_program(bpf_prog_type_to_int(BpfProgramType), BpfProgramBin).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec ebpf_verify_program(non_neg_integer(), binary()) -> 'ok' | {'error', term()}.
ebpf_verify_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

-spec ebpf_load_program(non_neg_integer(), binary()) ->
    {'ok', non_neg_integer()} | {'error', term()}.
ebpf_load_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

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
