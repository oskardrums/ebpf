%%%-------------------------------------------------------------------
%%% @author Oskar Mazerath <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, Oskar Mazerath
%%% @doc
%%% eBPF instructions assembly and disassembly
%%% @end
%%% Created : 13 Feb 2021 by Oskar Mazerath <moskar.drummer@gmail.com>
%%%-------------------------------------------------------------------
-module(ebpf_asm).

%% API
-export([assemble/1, disassemble/1]).

-include("ebpf_kern.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Assembles a list of bpf_instruction records into
%% binary form which can then be loaded to the kernel via {@link ebpf_user:load/2}
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
    code = OpCode,
    dst_reg = Dst,
    src_reg = Src,
    off = Off,
    imm = Imm
}) ->
    Code = bpf_opcode_to_int(OpCode),
    <<Code:8/unsigned, Src:4/unsigned, Dst:4/unsigned, Off:16/little-signed, Imm:32/little-signed>>.

-spec bpf_instruction_decode(binary()) -> bpf_instruction().
bpf_instruction_decode(
    <<Code:8/unsigned, Src:4/unsigned, Dst:4/unsigned, Off:16/little-signed, Imm:32/little-signed>>
) ->
    #bpf_instruction{
        code = bpf_opcode_from_int(Code),
        dst_reg = Dst,
        src_reg = Src,
        off = Off,
        imm = Imm
    }.

-spec bpf_opcode_to_int(bpf_opcode()) -> byte().
bpf_opcode_to_int({ld, Size, Mode}) ->
    ?BPF_LD bor bpf_size_to_int(Size) bor bpf_ld_mode_to_int(Mode);
bpf_opcode_to_int({ldx, Size, Mode}) ->
    ?BPF_LDX bor bpf_size_to_int(Size) bor bpf_ld_mode_to_int(Mode);
bpf_opcode_to_int({st, Size, Mode}) ->
    ?BPF_ST bor bpf_size_to_int(Size) bor bpf_ld_mode_to_int(Mode);
bpf_opcode_to_int({stx, Size, Mode}) ->
    ?BPF_STX bor bpf_size_to_int(Size) bor bpf_ld_mode_to_int(Mode);
bpf_opcode_to_int({alu32, Src, Op}) ->
    ?BPF_ALU bor bpf_src_to_int(Src) bor bpf_alu_op_to_int(Op);
bpf_opcode_to_int({alu64, Src, Op}) ->
    ?BPF_ALU64 bor bpf_src_to_int(Src) bor bpf_alu_op_to_int(Op);
bpf_opcode_to_int({jmp32, Src, Op}) ->
    ?BPF_JMP32 bor bpf_src_to_int(Src) bor bpf_jmp_op_to_int(Op);
bpf_opcode_to_int({jmp64, Src, Op}) ->
    ?BPF_JMP bor bpf_src_to_int(Src) bor bpf_jmp_op_to_int(Op).

-spec bpf_size_to_int(bpf_size()) -> byte().
bpf_size_to_int(b) -> ?BPF_B;
bpf_size_to_int(h) -> ?BPF_H;
bpf_size_to_int(w) -> ?BPF_W;
bpf_size_to_int(dw) -> ?BPF_DW.

-spec bpf_src_to_int(bpf_src()) -> byte().
bpf_src_to_int(k) -> ?BPF_K;
bpf_src_to_int(x) -> ?BPF_X.

-spec bpf_opcode_from_int(byte()) -> bpf_opcode().
bpf_opcode_from_int(Code) ->
    case ?BPF_CLASS(Code) of
        ?BPF_LD ->
            {ld, bpf_size_from_int(?BPF_SIZE(Code)), bpf_ld_mode_from_int(?BPF_MODE(Code))};
        ?BPF_LDX ->
            {ldx, bpf_size_from_int(?BPF_SIZE(Code)), bpf_ld_mode_from_int(?BPF_MODE(Code))};
        ?BPF_ST ->
            {st, bpf_size_from_int(?BPF_SIZE(Code)), bpf_ld_mode_from_int(?BPF_MODE(Code))};
        ?BPF_STX ->
            {stx, bpf_size_from_int(?BPF_SIZE(Code)), bpf_ld_mode_from_int(?BPF_MODE(Code))};
        ?BPF_ALU ->
            {alu32, bpf_src_from_int(?BPF_SRC(Code)), bpf_alu_op_from_int(?BPF_OP(Code))};
        ?BPF_JMP ->
            {jmp64, bpf_src_from_int(?BPF_SRC(Code)), bpf_jmp_op_from_int(?BPF_OP(Code))};
        ?BPF_JMP32 ->
            {jmp32, bpf_src_from_int(?BPF_SRC(Code)), bpf_jmp_op_from_int(?BPF_OP(Code))};
        ?BPF_ALU64 ->
            {alu64, bpf_src_from_int(?BPF_SRC(Code)), bpf_alu_op_from_int(?BPF_OP(Code))}
    end.

-spec bpf_size_from_int(byte()) -> bpf_size().
bpf_size_from_int(?BPF_B) -> b;
bpf_size_from_int(?BPF_H) -> h;
bpf_size_from_int(?BPF_W) -> w;
bpf_size_from_int(?BPF_DW) -> dw.

-spec bpf_src_from_int(byte()) -> bpf_src().
bpf_src_from_int(?BPF_X) -> x;
bpf_src_from_int(?BPF_K) -> k.

-spec bpf_ld_mode_from_int(byte()) -> bpf_ld_mode().
bpf_ld_mode_from_int(?BPF_IMM) -> imm;
bpf_ld_mode_from_int(?BPF_ABS) -> abs;
bpf_ld_mode_from_int(?BPF_MEM) -> mem;
bpf_ld_mode_from_int(?BPF_IND) -> ind;
bpf_ld_mode_from_int(?BPF_XADD) -> xadd.

-spec bpf_ld_mode_to_int(bpf_ld_mode()) -> byte().
bpf_ld_mode_to_int(imm) -> ?BPF_IMM;
bpf_ld_mode_to_int(abs) -> ?BPF_ABS;
bpf_ld_mode_to_int(mem) -> ?BPF_MEM;
bpf_ld_mode_to_int(ind) -> ?BPF_IND;
bpf_ld_mode_to_int(xadd) -> ?BPF_XADD.

-spec bpf_alu_op_from_int(byte()) -> bpf_alu_op().
bpf_alu_op_from_int(?BPF_ADD) -> add;
bpf_alu_op_from_int(?BPF_SUB) -> sub;
bpf_alu_op_from_int(?BPF_MUL) -> mul;
bpf_alu_op_from_int(?BPF_DIV) -> 'div';
bpf_alu_op_from_int(?BPF_OR) -> 'or';
bpf_alu_op_from_int(?BPF_AND) -> 'and';
bpf_alu_op_from_int(?BPF_LSH) -> lsh;
bpf_alu_op_from_int(?BPF_RSH) -> rsh;
bpf_alu_op_from_int(?BPF_NEG) -> neg;
bpf_alu_op_from_int(?BPF_MOD) -> mod;
bpf_alu_op_from_int(?BPF_XOR) -> 'xor';
bpf_alu_op_from_int(?BPF_MOV) -> mov;
bpf_alu_op_from_int(?BPF_ARSH) -> arsh.

-spec bpf_alu_op_to_int(bpf_alu_op()) -> byte().
bpf_alu_op_to_int(add) -> ?BPF_ADD;
bpf_alu_op_to_int(sub) -> ?BPF_SUB;
bpf_alu_op_to_int(mul) -> ?BPF_MUL;
bpf_alu_op_to_int('div') -> ?BPF_DIV;
bpf_alu_op_to_int('or') -> ?BPF_OR;
bpf_alu_op_to_int('and') -> ?BPF_AND;
bpf_alu_op_to_int(lsh) -> ?BPF_LSH;
bpf_alu_op_to_int(rsh) -> ?BPF_RSH;
bpf_alu_op_to_int(neg) -> ?BPF_NEG;
bpf_alu_op_to_int(mod) -> ?BPF_MOD;
bpf_alu_op_to_int('xor') -> ?BPF_XOR;
bpf_alu_op_to_int(mov) -> ?BPF_MOV;
bpf_alu_op_to_int(arsh) -> ?BPF_ARSH.

-spec bpf_jmp_op_from_int(byte()) -> bpf_jmp_op().
bpf_jmp_op_from_int(?BPF_JA) -> a;
bpf_jmp_op_from_int(?BPF_JEQ) -> eq;
bpf_jmp_op_from_int(?BPF_JGT) -> gt;
bpf_jmp_op_from_int(?BPF_JGE) -> ge;
bpf_jmp_op_from_int(?BPF_JSET) -> set;
bpf_jmp_op_from_int(?BPF_JNE) -> ne;
bpf_jmp_op_from_int(?BPF_JLT) -> lt;
bpf_jmp_op_from_int(?BPF_JLE) -> le;
bpf_jmp_op_from_int(?BPF_JSGT) -> sgt;
bpf_jmp_op_from_int(?BPF_JSGE) -> sge;
bpf_jmp_op_from_int(?BPF_JSLT) -> slt;
bpf_jmp_op_from_int(?BPF_JSLE) -> sle;
bpf_jmp_op_from_int(?BPF_CALL) -> call;
bpf_jmp_op_from_int(?BPF_EXIT) -> exit.

-spec bpf_jmp_op_to_int(bpf_jmp_op()) -> byte().
bpf_jmp_op_to_int(a) -> ?BPF_JA;
bpf_jmp_op_to_int(eq) -> ?BPF_JEQ;
bpf_jmp_op_to_int(gt) -> ?BPF_JGT;
bpf_jmp_op_to_int(ge) -> ?BPF_JGE;
bpf_jmp_op_to_int(set) -> ?BPF_JSET;
bpf_jmp_op_to_int(ne) -> ?BPF_JNE;
bpf_jmp_op_to_int(lt) -> ?BPF_JLT;
bpf_jmp_op_to_int(le) -> ?BPF_JLE;
bpf_jmp_op_to_int(sgt) -> ?BPF_JSGT;
bpf_jmp_op_to_int(sge) -> ?BPF_JSGE;
bpf_jmp_op_to_int(slt) -> ?BPF_JSLT;
bpf_jmp_op_to_int(sle) -> ?BPF_JSLE;
bpf_jmp_op_to_int(call) -> ?BPF_CALL;
bpf_jmp_op_to_int(exit) -> ?BPF_EXIT.
