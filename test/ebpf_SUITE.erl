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
            simple_socket_filter_1
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
    meck:new(ebpf_user, [passthrough]),
    meck:expect(
        ebpf_user,
        load,
        fun(socket_filter, <<183, 0, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0>>) -> {ok, 666} end
    ),
    meck:expect(ebpf_user, attach_socket_filter, fun(_SockFd, 666) -> ok end),

    {ok, ProgFd} = ebpf_user:load(
        socket_filter,
        ebpf_kern:assemble([
            % R0 = 0
            ebpf_kern:mov64_imm(0, 0),
            % return R0
            ebpf_kern:exit_insn()
        ])
    ),
    {ok, S} = socket:open(inet, stream, {raw, 0}),
    {ok, SockFd} = socket:getopt(S, otp, fd),
    ok = ebpf_user:attach_socket_filter(SockFd, ProgFd),

    true = meck:validate(ebpf_user),
    meck:unload(ebpf_user).

test_user_create_map_hash_1() -> [].
test_user_create_map_hash_1(_Config) ->
    case ebpf_user:create_map(hash, 4, 4, 255, 0) of
        {ok, _Map} -> ok;
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
