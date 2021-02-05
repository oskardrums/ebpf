%% instruction classes
-define(BPF_CLASS(Code), Code band 16#07).
-define(BPF_LD, 16#00).
-define(BPF_LDX, 16#01).
-define(BPF_ST, 16#02).
-define(BPF_STX, 16#03).
-define(BPF_ALU, 16#04).
-define(BPF_JMP, 16#05).
-define(BPF_RET, 16#06).
-define(BPF_MISC, 16#07).
-define(BPF_JMP32, 16#06).
-define(BPF_ALU64, 16#07).
%% ld/ldx fields
-define(BPF_SIZE(Code), Code band 16#18).
-define(BPF_W, 16#00).
-define(BPF_H, 16#08).
-define(BPF_B, 16#10).
-define(BPF_DW, 16#18).
-define(BPF_MODE(Code), Code band 16#e0).
-define(BPF_IMM, 16#00).
-define(BPF_ABS, 16#20).
-define(BPF_IND, 16#40).
-define(BPF_MEM, 16#60).
-define(BPF_LEN, 16#80).
-define(BPF_MSH, 16#a0).
-define(BPF_XADD, 16#c0).
-define(BPF_MOV, 16#b0).
-define(BPF_ARSH, 16#c0).
%% alu/jmp fields
-define(BPF_OP(Code), Code band 16#f0).
-define(BPF_ADD, 16#00).
-define(BPF_SUB, 16#10).
-define(BPF_MUL, 16#20).
-define(BPF_DIV, 16#30).
-define(BPF_OR, 16#40).
-define(BPF_AND, 16#50).
-define(BPF_LSH, 16#60).
-define(BPF_RSH, 16#70).
-define(BPF_NEG, 16#80).
-define(BPF_JA, 16#00).
-define(BPF_JEQ, 16#10).
-define(BPF_JGT, 16#20).
-define(BPF_JGE, 16#30).
-define(BPF_JSET, 16#40).

-define(BPF_JNE, 16#50).
-define(BPF_JLT, 16#a0).
-define(BPF_JLE, 16#b0).
-define(BPF_JSGT, 16#60).
-define(BPF_JSGE, 16#70).
-define(BPF_JSLT, 16#c0).
-define(BPF_JSLE, 16#d0).
-define(BPF_CALL, 16#80).
-define(BPF_EXIT, 16#90).

-define(BPF_END, 16#d0).
-define(BPF_TO_L, 16#00).
-define(BPF_TO_B, 16#08).
-define(BPF_FROM_LE, ?BPF_TO_LE).
-define(BPF_FROM_BE, ?BPF_TO_BE).

-define(BPF_SRC(Code), Code band 16#08).

-define(BPF_K, 16#00).
-define(BPF_X, 16#08).
%% ret - BPF_K and BPF_X also apply
-define(BPF_RVAL(Code), Code band 16#18).
-define(BPF_A, 16#10).
%% misc
-define(BPF_MISCOP(Code), Code band 16#f8).
-define(BPF_TAX, 16#00).
-define(BPF_TXA, 16#80).

-type code() :: 0..255.
-type reg() :: 0..127.
-type off() :: -(1 bsl 15)..1 bsl 15.
-type imm() :: -(1 bsl 31)..1 bsl 31.

-record(instruction, {
    code = 0 :: code(),
    dst_reg = 0 :: reg(),
    src_reg = 0 :: reg(),
    off = 0 :: off(),
    imm = 0 :: imm()
}).

-type instruction() :: #instruction{}.

-record(rt, {
    code = [] :: [instruction()],
    labels = #{} :: #{term() => non_neg_integer()},
    head = 0 :: non_neg_integer(),
    stack_need = 0 :: non_neg_integer(),
    live = 0 :: non_neg_integer()
}).

-type rt() :: #rt{}.
