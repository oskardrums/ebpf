%%%-------------------------------------------------------------------
%%% @author user <user@deb10.home>
%%% @copyright (C) 2021, user
%%% @doc
%%% eBPF instructions encoding and decoding
%%% @end
%%% Created :  5 Feb 2021 by user <user@deb10.home>
%%%-------------------------------------------------------------------
-module(ebpf_instructions).

%% binary encoding/decoding
-export([encode/1, decode/1]).

%% instruction generation
-export([
    exit_insn/0,
    mov32_imm/2,
    mov64_imm/2,
    mov32_reg/2,
    mov64_reg/2,
    alu64_imm/3,
    alu64_reg/3,
    alu32_reg/3,
    alu32_imm/3,
    emit_call/1
]).

%%%===================================================================
%%% Includes
%%%===================================================================

-include("ebpf.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------
-spec encode(#instruction{}) -> binary().
encode(#instruction{code = Code, dst_reg = Dst, src_reg = Src, off = Off, imm = Imm}) ->
    <<Code:8/unsigned, Dst:4/unsigned, Src:4/unsigned, Off:16/signed, Imm:32/signed>>.

-spec decode(binary()) -> #instruction{}.
decode(<<Code:8/unsigned, Dst:4/unsigned, Src:4/unsigned, Off:16/signed, Imm:32/signed>>) ->
    #instruction{code = Code, dst_reg = Dst, src_reg = Src, off = Off, imm = Imm}.
-spec alu64_reg(code(), reg(), reg()) -> #instruction{}.
alu64_reg(Op, Dst, Src) ->
    #instruction{code = ?BPF_ALU64 bor ?BPF_OP(Op) bor ?BPF_X, dst_reg = Dst, src_reg = Src}.

-spec alu32_reg(code(), reg(), reg()) -> #instruction{}.
alu32_reg(Op, Dst, Src) ->
    #instruction{code = ?BPF_ALU bor ?BPF_OP(Op) bor ?BPF_X, dst_reg = Dst, src_reg = Src}.

-spec alu64_imm(code(), reg(), imm()) -> #instruction{}.
alu64_imm(Op, Dst, Imm) ->
    #instruction{code = ?BPF_ALU64 bor ?BPF_OP(Op) bor ?BPF_K, dst_reg = Dst, imm = Imm}.

-spec alu32_imm(code(), reg(), imm()) -> #instruction{}.
alu32_imm(Op, Dst, Imm) ->
    #instruction{code = ?BPF_ALU bor ?BPF_OP(Op) bor ?BPF_K, dst_reg = Dst, imm = Imm}.

-spec mov64_reg(reg(), reg()) -> #instruction{}.
mov64_reg(Dst, Src) ->
    #instruction{code = ?BPF_ALU64 bor ?BPF_MOV bor ?BPF_X, dst_reg = Dst, src_reg = Src}.

-spec mov32_reg(reg(), reg()) -> #instruction{}.
mov32_reg(Dst, Src) ->
    #instruction{code = ?BPF_ALU bor ?BPF_MOV bor ?BPF_X, dst_reg = Dst, src_reg = Src}.

-spec mov64_imm(reg(), imm()) -> #instruction{}.
mov64_imm(Dst, Imm) ->
    #instruction{code = ?BPF_ALU64 bor ?BPF_MOV bor ?BPF_K, dst_reg = Dst, imm = Imm}.

-spec mov32_imm(reg(), imm()) -> #instruction{}.
mov32_imm(Dst, Imm) ->
    #instruction{code = ?BPF_ALU bor ?BPF_MOV bor ?BPF_K, dst_reg = Dst, imm = Imm}.

-spec emit_call(imm()) -> #instruction{}.
emit_call(Func) ->
    #instruction{code = ?BPF_JMP bor ?BPF_CALL, imm = Func}.

%%--------------------------------------------------------------------
%% @doc Blah!
%% @spec
%% @end
%%--------------------------------------------------------------------
-spec exit_insn() -> #instruction{}.
exit_insn() ->
    #instruction{code = ?BPF_JMP bor ?BPF_EXIT}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
