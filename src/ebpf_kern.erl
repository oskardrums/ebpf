%%%-------------------------------------------------------------------
%%% @author Oskar Mazerath <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, Oskar Mazerath
%%% @doc
%%% eBPF instructions generation.
%%%
%%% The functions in this module don't <em>do</em> what they names
%%% imply, they generate eBPF instructions implementing the implied
%%% (and documented) semantics.
%%% @end
%%% Created :  9 Feb 2021 by Oskar Mazerath <moskar.drummer@gmail.com>
%%%-------------------------------------------------------------------
-module(ebpf_kern).

%% API
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
    jmp64_reg/4,
    jmp64_imm/4,
    jmp32_reg/4,
    jmp32_imm/4,
    jmp_a/1,
    ld_imm64_raw_full/6,
    ld_map_fd/2,
    st_mem/4,
    stx_mem/4,
    emit_call/1,
    bpf_helper_to_int/1,
    stack_printk/1,
    stack_printk/2,
    push_binary/1,
    push_binary/2,
    push_string/1,
    push_string/2,
    assemble/1,
    disassemble/1
]).

-include("ebpf_kern.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that performs ALU operation Op with
%% register arguments Src and Dst, and store the result in Dst.
%% @end
%%--------------------------------------------------------------------
-spec alu64_reg(bpf_alu_op(), bpf_reg(), bpf_reg()) -> bpf_instruction().
alu64_reg(Op, Dst, Src) ->
    #bpf_instruction{
        code = {alu64, x, Op},
        dst_reg = Dst,
        src_reg = Src
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that performs ALU operation Op with
%% register arguments Src and Dst using only the lower 32 bits of
%% each, and store the result in Dst.
%% @end
%%--------------------------------------------------------------------
-spec alu32_reg(bpf_alu_op(), bpf_reg(), bpf_reg()) -> bpf_instruction().
alu32_reg(Op, Dst, Src) ->
    #bpf_instruction{
        code = {alu32, x, Op},
        dst_reg = Dst,
        src_reg = Src
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that performs ALU operation Op with
%% immediate argument Imm and register Dst, and store the result in Dst.
%% @end
%%--------------------------------------------------------------------
-spec alu64_imm(bpf_alu_op(), bpf_reg(), bpf_imm()) -> bpf_instruction().
alu64_imm(Op, Dst, Imm) ->
    #bpf_instruction{
        code = {alu64, k, Op},
        dst_reg = Dst,
        imm = Imm
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that performs ALU operation Op with
%% immediate argument Imm and register Dst using only the lower 32
%% bits of each, and store the result in Dst.
%% @end
%%--------------------------------------------------------------------
-spec alu32_imm(bpf_alu_op(), bpf_reg(), bpf_imm()) -> bpf_instruction().
alu32_imm(Op, Dst, Imm) ->
    #bpf_instruction{
        code = {alu32, k, Op},
        dst_reg = Dst,
        imm = Imm
    }.

%%--------------------------------------------------------------------
%% @doc
%% `if (Src Op Dst) skip Off instructions'
%% @end
%%--------------------------------------------------------------------
-spec jmp64_reg(bpf_jmp_op(), bpf_reg(), bpf_reg(), bpf_off()) -> bpf_instruction().
jmp64_reg(Op, Dst, Src, Off) ->
    #bpf_instruction{
        code = {jmp64, x, Op},
        dst_reg = Dst,
        src_reg = Src,
        off = Off
    }.

%%--------------------------------------------------------------------
%% @doc
%% `if ((Src bsr 32) Op (Dst bsr 32)) skip Off instructions'
%% @end
%%--------------------------------------------------------------------
-spec jmp32_reg(bpf_jmp_op(), bpf_reg(), bpf_reg(), bpf_off()) -> bpf_instruction().
jmp32_reg(Op, Dst, Src, Off) ->
    #bpf_instruction{
        code = {jmp32, x, Op},
        dst_reg = Dst,
        src_reg = Src,
        off = Off
    }.

%%--------------------------------------------------------------------
%% @doc
%% `if (Imm Op Dst) skip Off instructions'
%% @end
%%--------------------------------------------------------------------
-spec jmp64_imm(bpf_jmp_op(), bpf_reg(), bpf_imm(), bpf_off()) -> bpf_instruction().
jmp64_imm(Op, Dst, Imm, Off) ->
    #bpf_instruction{
        code = {jmp64, x, Op},
        dst_reg = Dst,
        off = Off,
        imm = Imm
    }.

%%--------------------------------------------------------------------
%% @doc
%% `if ((Imm bsr 32) Op (Dst bsr 32)) skip Off instructions'
%% @end
%%--------------------------------------------------------------------
-spec jmp32_imm(bpf_jmp_op(), bpf_reg(), bpf_imm(), bpf_off()) -> bpf_instruction().
jmp32_imm(Op, Dst, Imm, Off) ->
    #bpf_instruction{
        code = {jmp32, x, Op},
        dst_reg = Dst,
        off = Off,
        imm = Imm
    }.

%%--------------------------------------------------------------------
%% @doc
%% `skip Off instructions'
%% @end
%%--------------------------------------------------------------------
-spec jmp_a(bpf_off()) -> bpf_instruction().
jmp_a(Off) ->
    #bpf_instruction{
        code = {jmp32, k, a},
        off = Off
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that copies Src into Dst.
%% @end
%%--------------------------------------------------------------------
-spec mov64_reg(bpf_reg(), bpf_reg()) -> bpf_instruction().
mov64_reg(Dst, Src) ->
    #bpf_instruction{code = {alu64, x, mov}, dst_reg = Dst, src_reg = Src}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that copies the lower 32 bits of Src
%% into Dst, zeroing the upper 32 bits of Dst in the process.
%% @end
%%--------------------------------------------------------------------
-spec mov32_reg(bpf_reg(), bpf_reg()) -> bpf_instruction().
mov32_reg(Dst, Src) ->
    #bpf_instruction{code = {alu32, x, mov}, dst_reg = Dst, src_reg = Src}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that copies Imm into Dst.
%% @end
%%--------------------------------------------------------------------
-spec mov64_imm(bpf_reg(), bpf_imm()) -> bpf_instruction().
mov64_imm(Dst, Imm) ->
    #bpf_instruction{code = {alu64, k, mov}, dst_reg = Dst, imm = Imm}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that copies Imm into the
%% lower 32 bits of Dst, zeroing the 32 upper bits.
%% @end
%%--------------------------------------------------------------------
-spec mov32_imm(bpf_reg(), bpf_imm()) -> bpf_instruction().
mov32_imm(Dst, Imm) ->
    #bpf_instruction{code = {alu32, k, mov}, dst_reg = Dst, imm = Imm}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that calls an eBPF helper function.
%% @end
%%--------------------------------------------------------------------
-spec emit_call(bpf_helper()) -> bpf_instruction().
emit_call(Func) ->
    #bpf_instruction{code = {jmp64, k, call}, imm = bpf_helper_to_int(Func)}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that returns from the
%% current function.
%% @end
%%--------------------------------------------------------------------
-spec exit_insn() -> bpf_instruction().
exit_insn() ->
    #bpf_instruction{code = {jmp64, k, exit}}.

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that stores Imm in the memory
%% location pointed by Dst's value plus Off.
%% @end
%%--------------------------------------------------------------------
-spec st_mem(bpf_size(), bpf_reg(), bpf_off(), bpf_imm()) -> bpf_instruction().
st_mem(Size, Dst, Off, Imm) ->
    #bpf_instruction{
        code = {st, Size, mem},
        dst_reg = Dst,
        off = Off,
        imm = Imm
    }.

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that loads a 64 bit
%% immediate value computed from (Imm1 bsl 32) bor Imm2 into Dst.
%% Src should be set to 0.
%% @end
%%--------------------------------------------------------------------
-spec ld_imm64_raw_full(bpf_reg(), bpf_reg(), bpf_off(), bpf_off(), bpf_imm(), bpf_imm()) ->
    [bpf_instruction()].
ld_imm64_raw_full(Dst, Src, Off1, Off2, Imm1, Imm2) ->
    [
        #bpf_instruction{
            code = {ld, dw, imm},
            dst_reg = Dst,
            src_reg = Src,
            off = Off1,
            imm = Imm1
        },
        #bpf_instruction{
            code = {ld, w, imm},
            off = Off2,
            imm = Imm2
        }
    ].

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that loads the memory
%% address of an eBPF map given by MapFd into Dst.
%% @end
%%--------------------------------------------------------------------
-spec ld_map_fd(bpf_reg(), bpf_imm()) -> [bpf_instruction()].
ld_map_fd(Dst, MapFd) ->
    ld_imm64_raw_full(Dst, ?BPF_PSEUDO_MAP_FD, 0, 0, MapFd, 0).

%%--------------------------------------------------------------------
%% @doc
%% Generates an eBPF instruction that stores the value of Src in the
%% memory location pointed by Dst's value plus Off.
%% @end
%%--------------------------------------------------------------------
-spec stx_mem(bpf_size(), bpf_reg(), bpf_reg(), bpf_off()) -> bpf_instruction().
stx_mem(Size, Dst, Src, Off) ->
    #bpf_instruction{
        code = {stx, Size, mem},
        dst_reg = Dst,
        src_reg = Src,
        off = Off
    }.

%%--------------------------------------------------------------------
%% @doc
%% Same as stack_printk/2, with StackHead set to 0.
%% @end
%%--------------------------------------------------------------------
-spec stack_printk(string()) -> [bpf_instruction()].
stack_printk(String) ->
    stack_printk(String, 0).

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that stores a string on
%% the eBPF stack and prints it with the trace_printk helper function.
%% The stack is overwritten from
%% StackHead-byte_size(String) to StackHead.
%% @end
%%--------------------------------------------------------------------
-spec stack_printk(string(), integer()) -> [bpf_instruction()].
stack_printk(String, StackHead) ->
    {Instructions0, NewStackHead} = push_string(String, StackHead),
    Instructions =
        Instructions0 ++
            [
                mov64_reg(1, 10),
                alu64_imm(add, 1, NewStackHead),
                mov64_imm(2, -NewStackHead),
                emit_call(trace_printk)
            ],
    Instructions.

%%--------------------------------------------------------------------
%% @doc
%% Same as push_string/2, with StackHead set to 0.
%% @end
%%--------------------------------------------------------------------
-spec push_string(string()) -> {[bpf_instruction()], integer()}.
push_string(String) ->
    push_string(String, 0).

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that stores a string on
%% the eBPF stack from offset StackHead-size(String) to StackHead.
%% @end
%%--------------------------------------------------------------------
-spec push_string(string(), integer()) -> {[bpf_instruction()], integer()}.
push_string(String, StackHead) ->
    push_binary(list_to_binary(String), StackHead).

%%--------------------------------------------------------------------
%% @doc
%% Same as push_binary/2, with StackHead set to 0.
%% @end
%%--------------------------------------------------------------------
-spec push_binary(binary()) -> {[bpf_instruction()], integer()}.
push_binary(Bin) ->
    push_binary(Bin, 0).

%%--------------------------------------------------------------------
%% @doc
%% Generates a sequence of eBPF instructions that stores a binary on
%% the eBPF stack from offset StackHead-size(String) to StackHead.
%% @end
%%--------------------------------------------------------------------
-spec push_binary(binary(), integer()) -> {[bpf_instruction()], integer()}.
push_binary(Bin, Head) ->
    Size = byte_size(Bin),
    NewHead = Head - (Size + ((4 - (Size rem 4)) rem 4)),
    {store_buffer(Bin, NewHead), NewHead}.

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

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec store_buffer(binary(), integer()) -> [bpf_instruction()].
store_buffer(Bin, Off) ->
    store_buffer(Bin, Off, []).

-spec store_buffer(binary(), integer(), [bpf_instruction()]) -> [bpf_instruction()].
store_buffer(<<Imm:32/big-signed-integer, Bin/binary>>, Off, Acc) ->
    store_buffer(Bin, Off + 4, [st_mem(w, 10, Off, Imm) | Acc]);
store_buffer(<<>>, _Off, Acc) ->
    Acc;
store_buffer(BinImm, Off, Acc) ->
    store_buffer(<<BinImm/binary, 0:(32 - bit_size(BinImm))>>, Off, Acc).
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

%%%===================================================================
%%% Convenient "enum"s
%%%
%%% used as Imm argument for some eBPF instructions
%%%===================================================================

-spec bpf_helper_to_int(bpf_helper()) -> bpf_imm().
bpf_helper_to_int(unspec) -> 0;
bpf_helper_to_int(map_lookup_elem) -> 1;
bpf_helper_to_int(map_update_elem) -> 2;
bpf_helper_to_int(map_delete_elem) -> 3;
bpf_helper_to_int(probe_read) -> 4;
bpf_helper_to_int(ktime_get_ns) -> 5;
bpf_helper_to_int(trace_printk) -> 6;
bpf_helper_to_int(get_prandom_u32) -> 7;
bpf_helper_to_int(get_smp_processor_id) -> 8;
bpf_helper_to_int(skb_store_bytes) -> 9;
bpf_helper_to_int(l3_csum_replace) -> 10;
bpf_helper_to_int(l4_csum_replace) -> 11;
bpf_helper_to_int(tail_call) -> 12;
bpf_helper_to_int(clone_redirect) -> 13;
bpf_helper_to_int(get_current_pid_tgid) -> 14;
bpf_helper_to_int(get_current_uid_gid) -> 15;
bpf_helper_to_int(get_current_comm) -> 16;
bpf_helper_to_int(get_cgroup_classid) -> 17;
bpf_helper_to_int(skb_vlan_push) -> 18;
bpf_helper_to_int(skb_vlan_pop) -> 19;
bpf_helper_to_int(skb_get_tunnel_key) -> 20;
bpf_helper_to_int(skb_set_tunnel_key) -> 21;
bpf_helper_to_int(perf_event_read) -> 22;
bpf_helper_to_int(redirect) -> 23;
bpf_helper_to_int(get_route_realm) -> 24;
bpf_helper_to_int(perf_event_output) -> 25;
bpf_helper_to_int(skb_load_bytes) -> 26;
bpf_helper_to_int(get_stackid) -> 27;
bpf_helper_to_int(csum_diff) -> 28;
bpf_helper_to_int(skb_get_tunnel_opt) -> 29;
bpf_helper_to_int(skb_set_tunnel_opt) -> 30;
bpf_helper_to_int(skb_change_proto) -> 31;
bpf_helper_to_int(skb_change_type) -> 32;
bpf_helper_to_int(skb_under_cgroup) -> 33;
bpf_helper_to_int(get_hash_recalc) -> 34;
bpf_helper_to_int(get_current_task) -> 35;
bpf_helper_to_int(probe_write_user) -> 36;
bpf_helper_to_int(current_task_under_cgroup) -> 37;
bpf_helper_to_int(skb_change_tail) -> 38;
bpf_helper_to_int(skb_pull_data) -> 39;
bpf_helper_to_int(csum_update) -> 40;
bpf_helper_to_int(set_hash_invalid) -> 41;
bpf_helper_to_int(get_numa_node_id) -> 42;
bpf_helper_to_int(skb_change_head) -> 43;
bpf_helper_to_int(xdp_adjust_head) -> 44;
bpf_helper_to_int(probe_read_str) -> 45;
bpf_helper_to_int(get_socket_cookie) -> 46;
bpf_helper_to_int(get_socket_uid) -> 47;
bpf_helper_to_int(set_hash) -> 48;
bpf_helper_to_int(setsockopt) -> 49;
bpf_helper_to_int(skb_adjust_room) -> 50;
bpf_helper_to_int(redirect_map) -> 51;
bpf_helper_to_int(sk_redirect_map) -> 52;
bpf_helper_to_int(sock_map_update) -> 53;
bpf_helper_to_int(xdp_adjust_meta) -> 54;
bpf_helper_to_int(perf_event_read_value) -> 55;
bpf_helper_to_int(perf_prog_read_value) -> 56;
bpf_helper_to_int(getsockopt) -> 57;
bpf_helper_to_int(override_return) -> 58;
bpf_helper_to_int(sock_ops_cb_flags_set) -> 59;
bpf_helper_to_int(msg_redirect_map) -> 60;
bpf_helper_to_int(msg_apply_bytes) -> 61;
bpf_helper_to_int(msg_cork_bytes) -> 62;
bpf_helper_to_int(msg_pull_data) -> 63;
bpf_helper_to_int(bind) -> 64;
bpf_helper_to_int(xdp_adjust_tail) -> 65;
bpf_helper_to_int(skb_get_xfrm_state) -> 66;
bpf_helper_to_int(get_stack) -> 67;
bpf_helper_to_int(skb_load_bytes_relative) -> 68;
bpf_helper_to_int(fib_lookup) -> 69;
bpf_helper_to_int(sock_hash_update) -> 70;
bpf_helper_to_int(msg_redirect_hash) -> 71;
bpf_helper_to_int(sk_redirect_hash) -> 72;
bpf_helper_to_int(lwt_push_encap) -> 73;
bpf_helper_to_int(lwt_seg6_store_bytes) -> 74;
bpf_helper_to_int(lwt_seg6_adjust_srh) -> 75;
bpf_helper_to_int(lwt_seg6_action) -> 76;
bpf_helper_to_int(rc_repeat) -> 77;
bpf_helper_to_int(rc_keydown) -> 78;
bpf_helper_to_int(skb_cgroup_id) -> 79;
bpf_helper_to_int(get_current_cgroup_id) -> 80;
bpf_helper_to_int(get_local_storage) -> 81;
bpf_helper_to_int(sk_select_reuseport) -> 82;
bpf_helper_to_int(skb_ancestor_cgroup_id) -> 83;
bpf_helper_to_int(sk_lookup_tcp) -> 84;
bpf_helper_to_int(sk_lookup_udp) -> 85;
bpf_helper_to_int(sk_release) -> 86;
bpf_helper_to_int(map_push_elem) -> 87;
bpf_helper_to_int(map_pop_elem) -> 88;
bpf_helper_to_int(map_peek_elem) -> 89;
bpf_helper_to_int(msg_push_data) -> 90;
bpf_helper_to_int(msg_pop_data) -> 91;
bpf_helper_to_int(rc_pointer_rel) -> 92;
bpf_helper_to_int(spin_lock) -> 93;
bpf_helper_to_int(spin_unlock) -> 94;
bpf_helper_to_int(sk_fullsock) -> 95;
bpf_helper_to_int(tcp_sock) -> 96;
bpf_helper_to_int(skb_ecn_set_ce) -> 97;
bpf_helper_to_int(get_listener_sock) -> 98;
bpf_helper_to_int(skc_lookup_tcp) -> 99;
bpf_helper_to_int(tcp_check_syncookie) -> 100;
bpf_helper_to_int(sysctl_get_name) -> 101;
bpf_helper_to_int(sysctl_get_current_value) -> 102;
bpf_helper_to_int(sysctl_get_new_value) -> 103;
bpf_helper_to_int(sysctl_set_new_value) -> 104;
bpf_helper_to_int(strtol) -> 105;
bpf_helper_to_int(strtoul) -> 106;
bpf_helper_to_int(sk_storage_get) -> 107;
bpf_helper_to_int(sk_storage_delete) -> 108;
bpf_helper_to_int(send_signal) -> 109;
bpf_helper_to_int(tcp_gen_syncookie) -> 110;
bpf_helper_to_int(skb_output) -> 111;
bpf_helper_to_int(probe_read_user) -> 112;
bpf_helper_to_int(probe_read_kernel) -> 113;
bpf_helper_to_int(probe_read_user_str) -> 114;
bpf_helper_to_int(probe_read_kernel_str) -> 115;
bpf_helper_to_int(tcp_send_ack) -> 116;
bpf_helper_to_int(send_signal_thread) -> 117;
bpf_helper_to_int(jiffies64) -> 118;
bpf_helper_to_int(read_branch_records) -> 119;
bpf_helper_to_int(get_ns_current_pid_tgid) -> 120;
bpf_helper_to_int(xdp_output) -> 121;
bpf_helper_to_int(get_netns_cookie) -> 122;
bpf_helper_to_int(get_current_ancestor_cgroup_id) -> 123;
bpf_helper_to_int(sk_assign) -> 124;
bpf_helper_to_int(ktime_get_boot_ns) -> 125;
bpf_helper_to_int(seq_printf) -> 126;
bpf_helper_to_int(seq_write) -> 127;
bpf_helper_to_int(sk_cgroup_id) -> 128;
bpf_helper_to_int(sk_ancestor_cgroup_id) -> 129;
bpf_helper_to_int(ringbuf_output) -> 130;
bpf_helper_to_int(ringbuf_reserve) -> 131;
bpf_helper_to_int(ringbuf_submit) -> 132;
bpf_helper_to_int(ringbuf_discard) -> 133;
bpf_helper_to_int(ringbuf_query) -> 134;
bpf_helper_to_int(csum_level) -> 135;
bpf_helper_to_int(skc_to_tcp6_sock) -> 136;
bpf_helper_to_int(skc_to_tcp_sock) -> 137;
bpf_helper_to_int(skc_to_tcp_timewait_sock) -> 138;
bpf_helper_to_int(skc_to_tcp_request_sock) -> 139;
bpf_helper_to_int(skc_to_udp6_sock) -> 140;
bpf_helper_to_int(get_task_stack) -> 141;
bpf_helper_to_int(load_hdr_opt) -> 142;
bpf_helper_to_int(store_hdr_opt) -> 143;
bpf_helper_to_int(reserve_hdr_opt) -> 144;
bpf_helper_to_int(inode_storage_get) -> 145;
bpf_helper_to_int(inode_storage_delete) -> 146;
bpf_helper_to_int(d_path) -> 147;
bpf_helper_to_int(copy_from_user) -> 148;
bpf_helper_to_int(snprintf_btf) -> 149;
bpf_helper_to_int(seq_printf_btf) -> 150;
bpf_helper_to_int(skb_cgroup_classid) -> 151;
bpf_helper_to_int(redirect_neigh) -> 152;
bpf_helper_to_int(per_cpu_ptr) -> 153;
bpf_helper_to_int(this_cpu_ptr) -> 154;
bpf_helper_to_int(redirect_peer) -> 155;
bpf_helper_to_int(task_storage_get) -> 156;
bpf_helper_to_int(task_storage_delete) -> 157;
bpf_helper_to_int(get_current_task_btf) -> 158;
bpf_helper_to_int(bprm_opts_set) -> 159;
bpf_helper_to_int(ktime_get_coarse_ns) -> 160;
bpf_helper_to_int(ima_inode_hash) -> 161;
bpf_helper_to_int(sock_from_file) -> 162.
