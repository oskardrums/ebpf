%%%-------------------------------------------------------------------
%%% @author moskar <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, moskar
%%% @doc
%%% Low level Linux eBPF library
%%% @end
%%% Created :  7 Feb 2021 by user <moskar.drummer@gmail.home>
%%%-------------------------------------------------------------------
-module(ebpf_lib).

%% API
-export([
    assemble/1,
    disassemble/1,
    load/2,
    verify/2,
    attach_socket_filter/2,
    attach_xdp/2
]).

-on_load(init/0).

-define(APPNAME, ebpf).
-define(LIBNAME, ?MODULE).

-include("ebpf.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Assembles a list of bpf_instruction records into
%% binary form which can then be loaded to the kernel via load/2.
%% @end
%%--------------------------------------------------------------------
-spec assemble([bpf_instruction()]) -> binary().
assemble(BpfInstructions) ->
    bpf_instructions_to_binary(BpfInstructions).

%%--------------------------------------------------------------------
%% @doc
%% Disassembles an eBPF program in binary form to a
%% list of bpf_instruction records.
%% @end
%%--------------------------------------------------------------------
-spec disassemble(binary()) -> [bpf_instruction()].
disassemble(BpfProgramBin) ->
    lists:reverse(disassemble(BpfProgramBin, [])).

-spec disassemble(binary(), [bpf_instruction()]) -> [bpf_instruction()].
disassemble(<<>>, Acc) ->
    Acc;
disassemble(<<InstructionBin:8/binary-unit:8, More/binary>>, Acc) ->
    disassemble(More, [bpf_instruction_decode(InstructionBin) | Acc]).

%%--------------------------------------------------------------------
%% @doc
%% Verifies an eBPF program in binary form with the kernel's verifier.
%% Reports errors in the program, if any, in textual form as returned
%% by the kernel.
%% @end
%%--------------------------------------------------------------------
-spec verify(bpf_prog_type(), binary()) -> 'ok' | {'error', term()}.
verify(BpfProgramType, BpfProgramBin) ->
    bpf_verify_program(
        bpf_prog_type_to_int(BpfProgramType),
        BpfProgramBin
    ).

%%--------------------------------------------------------------------
%% @doc
%% Attempts to load an eBPF program in binary form to the kernel.
%% see verify/1 for debugging and checking program validity.
%% @end
%%--------------------------------------------------------------------
-spec load(bpf_prog_type(), binary()) -> {'ok', non_neg_integer()} | {'error', term()}.
load(BpfProgramType, BpfProgramBin) ->
    bpf_load_program(
        bpf_prog_type_to_int(BpfProgramType),
        BpfProgramBin
    ).

%%--------------------------------------------------------------------
%% @doc
%% Applies a loaded eBPF program as returned by load/1 to a socket.
%% @end
%%--------------------------------------------------------------------
-spec attach_socket_filter(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', term()}.
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
-spec attach_xdp(string() | non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', term()}.
attach_xdp(IfIndex, ProgFd) when is_integer(IfIndex) ->
    bpf_attach_xdp(IfIndex, ProgFd);
attach_xdp(IfName, ProgFd) when is_list(IfName) ->
    {ok, IfIndex} = net:if_name2index(IfName),
    bpf_attach_xdp(IfIndex, ProgFd).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%-------------------------------------------------------------------
%%% NIFs and NIF related functions
%%%-------------------------------------------------------------------

-spec bpf_verify_program(non_neg_integer(), binary()) -> 'ok' | {'error', term()}.
bpf_verify_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

-spec bpf_load_program(non_neg_integer(), binary()) ->
    {'ok', non_neg_integer()} | {'error', term()}.
bpf_load_program(_BpfProgramType, _BpfProgramBin) ->
    not_loaded(?LINE).

-spec bpf_attach_socket_filter(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', term()}.
bpf_attach_socket_filter(_SockFd, _ProgFd) ->
    not_loaded(?LINE).

-spec bpf_attach_xdp(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', term()}.
bpf_attach_xdp(_IfIndex, _ProgFd) ->
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

%%--------------------------------------------------------------------
%% @doc Binary encodes a list of eBPF instructions.
%% @end
%%--------------------------------------------------------------------
-spec bpf_instructions_to_binary([bpf_instruction()]) -> binary().
bpf_instructions_to_binary(BpfInstructions) ->
    lists:foldl(
        fun(Instruction, Acc) ->
            EncodedInstruction = bpf_instruction_encode(Instruction),
            <<Acc/binary, EncodedInstruction/binary>>
        end,
        <<>>,
        BpfInstructions
    ).

-spec bpf_instruction_encode(bpf_instruction()) -> binary().
bpf_instruction_encode(#bpf_instruction{
    code = Code,
    dst_reg = Dst,
    src_reg = Src,
    off = Off,
    imm = Imm
}) ->
    <<Code:8/unsigned, Src:4/unsigned, Dst:4/unsigned, Off:16/little-signed, Imm:32/little-signed>>.

-spec bpf_instruction_decode(binary()) -> bpf_instruction().
bpf_instruction_decode(
    <<Code:8/unsigned, Src:4/unsigned, Dst:4/unsigned, Off:16/little-signed, Imm:32/little-signed>>
) ->
    #bpf_instruction{code = Code, dst_reg = Dst, src_reg = Src, off = Off, imm = Imm}.

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
