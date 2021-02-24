-module(prop_ebpf).

-include_lib("proper/include/proper.hrl").
-include("ebpf_kern.hrl").

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

prop_disassemble_assemble_symmetry() ->
    ?FORALL(
        Instructions,
        bpf_sequence(),
        begin
            Instructions = ebpf_asm:disassemble(ebpf_asm:assemble(Instructions)),
            true
        end
    ).

prop_assemble_produces_sane_binaries() ->
    ?FORALL(
        Instructions,
        bpf_sequence(),
        begin
            byte_size(ebpf_asm:assemble(Instructions)) rem 8 == 0
        end
    ).

prop_kern_exit_returns_given_value() ->
    ?FORALL(
        Val,
        non_neg_integer(),
        begin
            Data = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>,
            {ok, Prog} = ebpf_user:load(
                xdp,
                ebpf_asm:assemble(ebpf_kern:return(Val))
            ),
            {ok, Val, Data, _Duration1} = ebpf_user:test(Prog, 1, Data, byte_size(Data)),
            {ok, Val, <<>>, _Duration2} = ebpf_user:test(Prog, 1, Data, 0),
            ok = ebpf_user:close(Prog),
            true
        end
    ).

%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%
