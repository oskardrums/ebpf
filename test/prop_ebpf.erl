-module(prop_ebpf).

-include_lib("proper/include/proper.hrl").
-include("ebpf.hrl").

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

prop_disassemble_assemble_symmetry() ->
    ?FORALL(
        Instructions,
        bpf_sequence(),
        begin
            Instructions = ebpf_lib:disassemble(ebpf_lib:assemble(Instructions)),
            true
        end
    ).

prop_assemble_produces_sane_binaries() ->
    ?FORALL(
        Instructions,
        bpf_sequence(),
        begin
            byte_size(ebpf_lib:assemble(Instructions)) rem 8 == 0
        end
    ).

%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%
