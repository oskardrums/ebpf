%%%-------------------------------------------------------------------
%%% @author Oskar Mazerath <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, Oskar Mazerath
%%% @doc
%%%
%%% @end
%%% Created : 11 Feb 2021 by Oskar Mazerath <moskar.drummer@gmail.com>
%%%-------------------------------------------------------------------
-module(ebpf_SUITE).

%% Note: This directive should only be used in test suites.
-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include("ebpf_kern.hrl").

%%--------------------------------------------------------------------
%% COMMON TEST CALLBACK FUNCTIONS
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc
%%  Returns list of tuples to set default properties
%%  for the suite.
%%
%% Function: suite() -> Info
%%
%% Info = [tuple()]
%%   List of key/value pairs.
%%
%% Note: The suite/0 function is only meant to be used to return
%% default data values, not perform any other operations.
%%
%% @spec suite() -> Info
%% @end
%%--------------------------------------------------------------------
suite() ->
    [{timetrap, {minutes, 10}}].

%%--------------------------------------------------------------------
%% @doc
%% Initialization before the whole suite
%%
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for skipping the suite.
%%
%% Note: This function is free to add any key/value pairs to the Config
%% variable, but should NOT alter/remove any existing entries.
%%
%% @spec init_per_suite(Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% @end
%%--------------------------------------------------------------------
init_per_suite(Config) ->
    Config.

%%--------------------------------------------------------------------
%% @doc
%% Cleanup after the whole suite
%%
%% Config - [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%%
%% @spec end_per_suite(Config) -> _
%% @end
%%--------------------------------------------------------------------
end_per_suite(_Config) ->
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Initialization before each test case group.
%%
%% GroupName = atom()
%%   Name of the test case group that is about to run.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding configuration data for the group.
%% Reason = term()
%%   The reason for skipping all test cases and subgroups in the group.
%%
%% @spec init_per_group(GroupName, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% @end
%%--------------------------------------------------------------------
init_per_group(_GroupName, Config) ->
    Config.

%%--------------------------------------------------------------------
%% @doc
%% Cleanup after each test case group.
%%
%% GroupName = atom()
%%   Name of the test case group that is finished.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding configuration data for the group.
%%
%% @spec end_per_group(GroupName, Config0) ->
%%               term() | {save_config,Config1}
%% @end
%%--------------------------------------------------------------------
end_per_group(_GroupName, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Initialization before each test case
%%
%% TestCase - atom()
%%   Name of the test case that is about to be run.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for skipping the test case.
%%
%% Note: This function is free to add any key/value pairs to the Config
%% variable, but should NOT alter/remove any existing entries.
%%
%% @spec init_per_testcase(TestCase, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% @end
%%--------------------------------------------------------------------
init_per_testcase(_TestCase, Config) ->
    Config.

%%--------------------------------------------------------------------
%% @doc
%% Cleanup after each test case
%%
%% TestCase - atom()
%%   Name of the test case that is finished.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%%
%% @spec end_per_testcase(TestCase, Config0) ->
%%               term() | {save_config,Config1} | {fail,Reason}
%% @end
%%--------------------------------------------------------------------
end_per_testcase(_TestCase, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Returns a list of test case group definitions.
%%
%% Group = {GroupName,Properties,GroupsAndTestCases}
%% GroupName = atom()
%%   The name of the group.
%% Properties = [parallel | sequence | Shuffle | {RepeatType,N}]
%%   Group properties that may be combined.
%% GroupsAndTestCases = [Group | {group,GroupName} | TestCase]
%% TestCase = atom()
%%   The name of a test case.
%% Shuffle = shuffle | {shuffle,Seed}
%%   To get cases executed in random order.
%% Seed = {integer(),integer(),integer()}
%% RepeatType = repeat | repeat_until_all_ok | repeat_until_all_fail |
%%              repeat_until_any_ok | repeat_until_any_fail
%%   To get execution of cases repeated.
%% N = integer() | forever
%%
%% @spec: groups() -> [Group]
%% @end
%%--------------------------------------------------------------------
groups() ->
    [
        {ebpf_kern_ct, [parallel], [
            alu64_reg_known_good_result_1,
            ld_imm64_raw_full_known_good_result_1,
            ld_map_fd_known_good_result_1
        ]},
        {ebpf_user_ct, [sequence], [
            test_user_create_map_hash_1,
            test_user_map_hash_1,
            test_example_from_ebpf_kern_docs_1,
            test_user_test_program_1,
            test_user_test_program_2,
            simple_socket_filter_1,
            simple_xdp_1,
            readme_example_1,
            test_load_cf_ttl_1,
            test_load_cf_ttl_2
        ]}
    ].

%%--------------------------------------------------------------------
%% @doc
%%  Returns the list of groups and test cases that
%%  are to be executed.
%%
%% GroupsAndTestCases = [{group,GroupName} | TestCase]
%% GroupName = atom()
%%   Name of a test case group.
%% TestCase = atom()
%%   Name of a test case.
%% Reason = term()
%%   The reason for skipping all groups and test cases.
%%
%% @spec all() -> GroupsAndTestCases | {skip,Reason}
%% @end
%%--------------------------------------------------------------------
all() ->
    [{group, ebpf_kern_ct}, {group, ebpf_user_ct}].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc
%%  Test case info function - returns list of tuples to set
%%  properties for the test case.
%%
%% Info = [tuple()]
%%   List of key/value pairs.
%%
%% Note: This function is only meant to be used to return a list of
%% values, not perform any other operations.
%%
%% @spec TestCase() -> Info
%% @end
%%--------------------------------------------------------------------
simple_socket_filter_1() ->
    [].

%%--------------------------------------------------------------------
%% @doc Test case function. (The name of it must be specified in
%%              the all/0 list or in a test case group for the test case
%%              to be executed).
%%
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for skipping the test case.
%% Comment = term()
%%   A comment about the test case that will be printed in the html log.
%%
%% @spec TestCase(Config0) ->
%%           ok | exit() | {skip,Reason} | {comment,Comment} |
%%           {save_config,Config1} | {skip_and_save,Reason,Config1}
%% @end
%%--------------------------------------------------------------------
simple_socket_filter_1(_Config) ->
    {ok, Prog} = ebpf_user:load(
        socket_filter,
        ebpf_asm:assemble([
            % R0 = 0
            ebpf_kern:mov64_imm(0, 0),
            % return R0
            ebpf_kern:exit_insn()
        ])
    ),
    {ok, Sock} = socket:open(inet, stream, {raw, 0}),
    ok = ebpf_user:attach_socket_filter(Sock, Prog),
    ok = ebpf_user:detach_socket_filter(Sock),
    ok = ebpf_user:close(Prog),
    ok = socket:close(Sock).

simple_xdp_1() -> [].
simple_xdp_1(_Config) ->
    {ok, Prog} = ebpf_user:load(
        xdp,
        ebpf_asm:assemble([
            % R0 = 0
            ebpf_kern:mov64_imm(0, 0),
            % return R0
            ebpf_kern:exit_insn()
        ])
    ),
    ok = ebpf_user:attach_xdp("lo", Prog),
    ok = ebpf_user:detach_xdp("lo"),
    ok = ebpf_user:close(Prog).

readme_example_1() -> [].
readme_example_1(_Config) ->
    BinProg = ebpf_asm:assemble([
        % Drop all packets

        % r0 = 0
        ebpf_kern:mov64_imm(0, 0),
        % return r0
        ebpf_kern:exit_insn()
    ]),
    {ok, FilterProg} = ebpf_user:load(socket_filter, BinProg),
    {ok, Sock} = socket:open(inet, stream, {raw, 0}),
    % All new input to Sock is
    ok = ebpf_user:attach_socket_filter(Sock, FilterProg),
    % Sock is back to normal and FilterProg can be
    ok = ebpf_user:detach_socket_filter(Sock),

    % FilterProg is unloaded from the kernel
    ok = ebpf_user:close(FilterProg),

    {ok, XdpProg} = ebpf_user:load(xdp, BinProg),
    % Try pinging 127.0.0.1, go ahead
    ok = ebpf_user:attach_xdp("lo", XdpProg),
    % Now, that's better :)
    ok = ebpf_user:detach_xdp("lo"),
    ok = ebpf_user:close(XdpProg).

test_user_create_map_hash_1() -> [].
test_user_create_map_hash_1(_Config) ->
    case ebpf_maps:new(hash, 4, 4, 255) of
        {error, Reason} -> {error, Reason};
        Map -> ebpf_maps:close(Map)
    end.

test_user_map_hash_1() -> [].
test_user_map_hash_1(_Config) ->
    case ebpf_maps:new(hash, 4, 4, 5) of
        {error, Reason} ->
            {error, Reason};
        Map0 ->
            Key = <<1, 2, 3, 4>>,
            Value = <<5, 6, 7, 8>>,
            Map1 = ebpf_maps:put(Key, Value, Map0),
            Value = ebpf_maps:get(Key, Map1),
            Map2 = ebpf_maps:remove(Key, Map1),
            Default = <<"leet">>,
            Default = ebpf_maps:get(Key, Map1, Default),
            Map3 = ebpf_maps:remove(Key, Map2),
            ok = ebpf_maps:close(Map3)
    end.

test_user_test_program_1() -> [].
test_user_test_program_1(_Config) ->
    Data =
        <<220, 166, 50, 111, 234, 102, 178, 104, 223, 17, 67, 189, 8, 0, 69, 0, 0, 60, 13, 111, 64,
            0, 64, 6, 147, 181, 10, 3, 141, 147, 1, 1, 1, 1, 185, 218, 0, 80, 189, 122, 208, 241, 0,
            0, 0, 0, 160, 2, 250, 240, 194, 210, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 3, 173, 164, 96,
            0, 0, 0, 0, 1, 3, 3, 7>>,

    case
        ebpf_user:load(
            xdp,
            ebpf_asm:assemble(
                lists:flatten([
                    ebpf_kern:mov64_imm(0, -1),
                    ebpf_kern:exit_insn()
                ])
            )
        )
    of
        {ok, Prog} ->
            {ok, 16#FFFFFFFF, Data, _Duration} = ebpf_user:test(
                Prog,
                128,
                Data,
                byte_size(Data)
            );
        {error, eperm} ->
            {skip, eperm};
        Other ->
            {error, Other}
    end.

test_user_test_program_2() -> [].
test_user_test_program_2(_Config) ->
    Data =
        <<220, 166, 50, 111, 234, 102, 178, 104, 223, 17, 67, 189, 8, 0, 69, 0, 0, 60, 13, 111, 64,
            0, 64, 6, 147, 181, 10, 3, 141, 147, 1, 1, 1, 1, 185, 218, 0, 80, 189, 122, 208, 241, 0,
            0, 0, 0, 160, 2, 250, 240, 194, 210, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 3, 173, 164, 96,
            0, 0, 0, 0, 1, 3, 3, 7>>,

    case
        ebpf_user:load(
            xdp,
            ebpf_asm:assemble(
                lists:flatten([
                    ebpf_kern:mov64_imm(0, -1),
                    ebpf_kern:exit_insn()
                ])
            )
        )
    of
        {ok, Prog} ->
            {ok, 16#FFFFFFFF, <<>>, _Duration} = ebpf_user:test(Prog, 128, Data, 0);
        {error, eperm} ->
            {skip, eperm};
        Other ->
            {error, Other}
    end.

test_example_from_ebpf_kern_docs_1() -> [].
test_example_from_ebpf_kern_docs_1(_Config) ->
    Instructions = lists:flatten([
        ebpf_kern:stack_printk("Hey ebpf"),
        ebpf_kern:exit_insn()
    ]),
    case ebpf_user:load(xdp, ebpf_asm:assemble(Instructions)) of
        {ok, XdpGreetProg} -> ok = ebpf_user:close(XdpGreetProg);
        {error, eperm} -> {skip, eperm};
        Other -> {error, Other}
    end.

alu64_reg_known_good_result_1() -> [].
alu64_reg_known_good_result_1(_Config) ->
    #bpf_instruction{
        code = {alu64, x, add},
        dst_reg = 1,
        src_reg = 2
    } = ebpf_kern:alu64_reg(
        add,
        1,
        2
    ).

ld_imm64_raw_full_known_good_result_1() -> [].
ld_imm64_raw_full_known_good_result_1(_Config) ->
    [
        #bpf_instruction{
            code = {ld, dw, imm},
            dst_reg = 1,
            src_reg = 2,
            off = 1337,
            imm = 16#beef
        },
        #bpf_instruction{
            code = {ld, w, imm},
            dst_reg = 0,
            src_reg = 0,
            off = 8008,
            imm = 16#feed
        }
    ] = ebpf_kern:ld_imm64_raw_full(
        1,
        2,
        1337,
        8008,
        16#beef,
        16#feed
    ).

ld_map_fd_known_good_result_1() -> [].
ld_map_fd_known_good_result_1(_Config) ->
    [
        #bpf_instruction{
            code = {ld, dw, imm},
            dst_reg = 1,
            src_reg = ?BPF_PSEUDO_MAP_FD,
            off = 0,
            imm = 17
        },
        #bpf_instruction{
            code = {ld, w, imm},
            dst_reg = 0,
            src_reg = 0,
            off = 0,
            imm = 0
        }
    ] = ebpf_kern:ld_map_fd(1, 17).

test_load_cf_ttl_1() -> [].
test_load_cf_ttl_1(_Config) ->
    Expected =
        "0: (61) r0 = *(u32 *)(r1 +16)\n"
        "1: (15) if r0 == 0x86dd goto pc+3\n"
        " R0=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R1=ctx(id=0,off=0,imm=0) R10=fp0,call_-1\n"
        "2: (bf) r6 = r1\n"
        "3: (30) r0 = *(u8 *)skb[-1048568]\n"
        "4: (05) goto pc+2\n"
        "7: (63) *(u32 *)(r10 -4) = r0\n"
        "8: (bf) r2 = r10\n"
        "9: (07) r2 += -4\n",
    %   "10: (18) r1 = 0xffff914d76c96800\n"
    %   "12: (85) call bpf_map_lookup_elem#1\n"
    %   "13: (15) if r0 == 0x0 goto pc+3\n"
    %   " R0=map_value(id=0,off=0,ks=4,vs=8,imm=0) R6=ctx(id=0,off=0,imm=0) R10=fp0,call_-1\n"
    %   "14: (b7) r1 = 1\n"
    %   "15: (db) lock *(u64 *)(r0 +0) += r1\n"
    %   " R0=map_value(id=0,off=0,ks=4,vs=8,imm=0) R1_w=inv1 R6=ctx(id=0,off=0,imm=0) R10=fp0,call_-1\n"
    %   " R0=map_value(id=0,off=0,ks=4,vs=8,imm=0) R1_w=inv1 R6=ctx(id=0,off=0,imm=0) R10=fp0,call_-1\n"
    %   "16: (05) goto pc+9\n"
    %   "26: (b7) r0 = -1\n"
    %   "27: (95) exit\n"
    %   "\n"
    %   "from 13 to 17: R0=inv0 R6=ctx(id=0,off=0,imm=0) R10=fp0,call_-1\n"
    %   "17: (18) r1 = 0xffff914d76c96800\n"
    %   "19: (bf) r2 = r10\n"
    %   "20: (07) r2 += -4\n"
    %   "21: (7a) *(u64 *)(r10 -16) = 1\n"
    %   "22: (bf) r3 = r10\n"
    %   "23: (07) r3 += -16\n"
    %   "24: (b7) r4 = 0\n"
    %   "25: (85) call bpf_map_update_elem#2\n"
    %   "26: safe\n"
    %   "\n"
    %   "from 1 to 5: R0=inv-2032336896 R1=ctx(id=0,off=0,imm=0) R10=fp0,call_-1\n"
    %   "5: (bf) r6 = r1\n"
    %   "6: (30) r0 = *(u8 *)skb[-1048569]\n"
    %   "7: (63) *(u32 *)(r10 -4) = r0\n"
    %   "8: (bf) r2 = r10\n"
    %   "9: (07) r2 += -4\n"
    %   "10: (18) r1 = 0xffff914d76c96800\n"
    %   "12: (85) call bpf_map_lookup_elem#1\n"
    %   "13: safe\n"
    %   "processed 33 insns (limit 131072), stack depth 16\n",
    Map = ebpf_maps:new(hash, 4, 8, 4),
    MapFd = ebpf_maps:fd(Map),
    Instructions = lists:flatten([
        ebpf_kern:ldx_mem(w, 0, 1, 16),
        ebpf_kern:jmp64_imm(eq, 0, 16#86DD, 3),
        ebpf_kern:mov64_reg(6, 1),
        ebpf_kern:ld_abs(b, -16#100000 + 8),
        ebpf_kern:jmp_a(2),
        ebpf_kern:mov64_reg(6, 1),
        ebpf_kern:ld_abs(b, -16#100000 + 7),
        ebpf_kern:stx_mem(w, 10, 0, -4),
        ebpf_kern:mov64_reg(2, 10),
        ebpf_kern:alu64_imm(add, 2, -4),
        ebpf_kern:ld_map_fd(1, MapFd),
        ebpf_kern:call_helper(map_lookup_elem),
        ebpf_kern:jmp64_imm(eq, 0, 0, 3),
        ebpf_kern:mov64_imm(1, 1),
        ebpf_kern:stx_xadd(dw, 0, 1, 0),
        ebpf_kern:jmp_a(9),
        ebpf_kern:ld_map_fd(1, MapFd),
        ebpf_kern:mov64_reg(2, 10),
        ebpf_kern:alu64_imm(add, 2, -4),
        ebpf_kern:st_mem(dw, 10, -16, 1),
        ebpf_kern:mov64_reg(3, 10),
        ebpf_kern:alu64_imm(add, 3, -16),
        ebpf_kern:mov64_imm(4, 0),
        ebpf_kern:call_helper(map_update_elem),
        ebpf_kern:mov64_imm(0, -1),
        ebpf_kern:exit_insn()
    ]),
    {ok, Prog, Desc} = ebpf_user:load(socket_filter, ebpf_asm:assemble(Instructions), [
        {log_buffer_size, 4096},
        {license, "Dual BSD/GPL"},
        sleepable
    ]),
    Expected = lists:sublist(Desc, length(Expected)),
    ok = ebpf_user:close(Prog),
    ok = ebpf_maps:close(Map).

test_load_cf_ttl_2() -> [].
test_load_cf_ttl_2(_Config) ->
    Map = ebpf_maps:new(hash, 4, 8, 4),
    MapFd = ebpf_maps:fd(Map),
    Instructions = lists:flatten([
        ebpf_kern:ldx_mem(w, 0, 1, 16),
        ebpf_kern:jmp64_imm(eq, 0, 16#86DD, 3),
        ebpf_kern:mov64_reg(6, 1),
        ebpf_kern:ld_abs(b, -16#100000 + 8),
        ebpf_kern:jmp_a(2),
        ebpf_kern:mov64_reg(6, 1),
        ebpf_kern:ld_abs(b, -16#100000 + 7),
        ebpf_kern:stx_mem(w, 10, 0, -4),
        ebpf_kern:mov64_reg(2, 10),
        ebpf_kern:alu64_imm(add, 2, -4),
        ebpf_kern:ld_map_fd(1, MapFd),
        ebpf_kern:call_helper(map_lookup_elem),
        ebpf_kern:jmp64_imm(eq, 0, 0, 3),
        ebpf_kern:mov64_imm(1, 1),
        ebpf_kern:stx_xadd(dw, 0, 1, 0),
        ebpf_kern:jmp_a(9),
        ebpf_kern:ld_map_fd(1, MapFd),
        ebpf_kern:mov64_reg(2, 10),
        ebpf_kern:alu64_imm(add, 2, -4),
        ebpf_kern:st_mem(dw, 10, -16, 1),
        ebpf_kern:mov64_reg(3, 10),
        ebpf_kern:alu64_imm(add, 3, -16),
        ebpf_kern:mov64_imm(4, 0),
        ebpf_kern:call_helper(map_update_elem),
        ebpf_kern:mov64_imm(0, -1),
        ebpf_kern:exit_insn()
    ]),
    {ok, Prog} = ebpf_user:load(
        socket_filter,
        ebpf_asm:assemble(Instructions),
        [{log_buffer_size, 0}]
    ),
    ok = ebpf_user:close(Prog),
    ok = ebpf_maps:close(Map).
