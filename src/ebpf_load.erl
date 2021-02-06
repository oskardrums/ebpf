%%%-------------------------------------------------------------------
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ebpf_load).

%% API
-export([repeat/2, attach_xdp/2, verify/1]).

-on_load(init/0).

-define(APPNAME, ebpf_load).
-define(LIBNAME, ebpf_load).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------
repeat(_, _) ->
    not_loaded(?LINE).
xdp(_, _) ->
    not_loaded(?LINE).
verify(_) ->
    not_loaded(?LINE).
attach_xdp(IfName, BinCode) ->
    case net:if_name2index(IfName) of
        {ok, IfIndex} ->
            xdp(IfIndex, BinCode);
        {error, Reason} ->
            {error, {IfName, Reason}}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================
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
