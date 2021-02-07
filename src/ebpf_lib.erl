%%%-------------------------------------------------------------------
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ebpf_lib).

%% API
-export([load/2, verify/2, disassemble/1]).

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

-type bpf_code() :: 0..255.
-type bpf_reg() :: 0..127.
-type bpf_off() :: -(1 bsl 15)..1 bsl 15.
-type bpf_imm() :: -(1 bsl 31)..1 bsl 31.

-record(instruction, {
    code = 0 :: bpf_code(),
    dst_reg = 0 :: bpf_reg(),
    src_reg = 0 :: bpf_reg(),
    off = 0 :: bpf_off(),
    imm = 0 :: bpf_imm()
}).

-type bpf_instruction() :: #instruction{}.

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------
-spec verify(bpf_prog_type(), [bpf_instruction()]) -> 'ok' | {'error', term()}.
verify(BpfProgramType, BpfInstructions) ->
    bpf_verify_program(
        bpf_prog_type_to_int(BpfProgramType),
        bpf_instructions_to_binary(BpfInstructions)
    ).

-spec load(bpf_prog_type(), [bpf_instruction()]) -> {'ok', non_neg_integer()} | {'error', term()}.
load(BpfProgramType, BpfInstructions) ->
    bpf_load_program(
        bpf_prog_type_to_int(BpfProgramType),
        bpf_instructions_to_binary(BpfInstructions)
    ).

disassemble(BpfProgramBin) ->
    lists:reverse(disassemble(BpfProgramBin, [])).

disassemble(<<>>, Acc) ->
    Acc;
disassemble(<<InstructionBin:64, More/binary>>, Acc) ->
    disassemble(More, [bpf_decode(InstructionBin) | Acc]).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec bpf_verify_program(non_neg_integer(), binary()) -> 'ok' | {'error', term()}.
bpf_verify_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

-spec bpf_load_program(non_neg_integer(), binary()) ->
    {'ok', non_neg_integer()} | {'error', term()}.
bpf_load_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

bpf_instructions_to_binary(BpfInstructions) ->
    lists:foldl(
        fun(Instruction, Acc) ->
            EncodedInstruction = bpf_encode(Instruction),
            <<Acc/binary, EncodedInstruction/binary>>
        end,
        <<>>,
        BpfInstructions
    ).

-spec bpf_encode(#instruction{}) -> binary().
bpf_encode(#instruction{code = Code, dst_reg = Dst, src_reg = Src, off = Off, imm = Imm}) ->
    <<Code:8/unsigned, Dst:4/unsigned, Src:4/unsigned, Off:16/signed, Imm:32/signed>>.

-spec bpf_decode(binary()) -> #instruction{}.
bpf_decode(<<Code:8/unsigned, Dst:4/unsigned, Src:4/unsigned, Off:16/signed, Imm:32/signed>>) ->
    #instruction{code = Code, dst_reg = Dst, src_reg = Src, off = Off, imm = Imm}.

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
