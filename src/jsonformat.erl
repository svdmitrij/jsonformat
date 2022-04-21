%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2020, Kivra
%%%
%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%%%
%%% @doc Custom formatter for the Erlang OTP logger application which
%%%      outputs single-line JSON formatted data
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(jsonformat).

%%%_* Exports ==========================================================
-export([format/2]).
-export([system_time_to_iso8601/1]).
-export([system_time_to_iso8601_nano/1]).

%%%_* Types ============================================================
-type config() :: #{ new_line => boolean()
                   , key_mapping => #{atom() => atom()}
                   , format_funs => #{atom() => fun((_) -> _)}
                   , chars_limit => non_neg_integer()}.

-export_type([config/0]).

%%%_* Macros ===========================================================
%%%_* Options ----------------------------------------------------------
-define(NEW_LINE, false).

%%%_* Code =============================================================
%%%_ * API -------------------------------------------------------------
-spec format(logger:log_event(), config()) -> unicode:chardata().
format(#{msg:={report, #{format:=Format, args:=Args, label:={error_logger, _}}}} = Map, Config) ->
  Report = #{text => io_lib:format(Format, Args, chars_limit(Config))},
  format(Map#{msg := {report, Report}}, Config);
format(#{level:=Level, msg:={report, Msg}, meta:=Meta}, Config) when is_map(Msg) ->
  Data0 = Msg,
  Data1 = apply_key_mapping(Data0, Config),
  Data2 = apply_format_funs(Data1, Config),
  encode(#{report => [pre_encode(Meta#{level => Level}, Config), pre_encode(Data2, Config)]}, Config);
format(Map = #{msg := {report, KeyVal}}, Config) when is_list(KeyVal) ->
  format(Map#{msg := {report, maps:from_list(KeyVal)}}, Config);
format(Map = #{msg := {string, String}}, Config) ->
  Report = #{text => unicode:characters_to_binary(String)},
  format(Map#{msg := {report, Report}}, Config);
format(Map = #{msg := {Format, Terms}}, Config) ->
  format(Map#{msg := {string, io_lib:format(Format, Terms, chars_limit(Config))}}, Config).

chars_limit(Config) ->
    [{chars_limit, maps:get(chars_limit, Config, -1)}].

%%% Useful for converting logger:timestamp() to a readable timestamp.
-spec system_time_to_iso8601(integer()) -> binary().
system_time_to_iso8601(Epoch) ->
  system_time_to_iso8601(Epoch, microsecond).

-spec system_time_to_iso8601_nano(integer()) -> binary().
system_time_to_iso8601_nano(Epoch) ->
  system_time_to_iso8601(1000 * Epoch, nanosecond).

-spec system_time_to_iso8601(integer(), erlang:time_unit()) -> binary().
system_time_to_iso8601(Epoch, Unit) ->
  binary:list_to_bin(calendar:system_time_to_rfc3339(Epoch, [{unit, Unit}, {offset, "Z"}])).

%%%_* Private functions ================================================
pre_encode(Data, Config) ->
  maps:fold(
    fun(K, V, Acc) when is_map(V) ->
      maps:put(jsonify(K, Config), pre_encode(V, Config), Acc);
       (K, Vs, Acc) when is_list(Vs), is_map(hd(Vs)) -> % assume list of maps
      maps:put(jsonify(K, Config), [pre_encode(V, Config) || V <- Vs, is_map(V)], Acc);
       (K, V, Acc) ->
      maps:put(jsonify(K, Config), jsonify(V, Config), Acc)
    end,
    maps:new(),
    Data).

encode(Data, Config) ->
  Json = jsx:encode(Data),
  case new_line(Config) of
    true -> [Json, <<"\n">>];
    false -> Json
  end.

jsonify(A, _Config) when is_atom(A)     -> A;
jsonify(B, _Config) when is_binary(B)   -> B;
jsonify(I, _Config) when is_integer(I)  -> I;
jsonify(F, _Config) when is_float(F)    -> F;
jsonify(B, _Config) when is_boolean(B)  -> B;
jsonify(P, Config) when is_pid(P)      -> jsonify(pid_to_list(P), Config);
jsonify(P, Config) when is_port(P)     -> jsonify(port_to_list(P), Config);
jsonify(F, Config) when is_function(F) -> jsonify(erlang:fun_to_list(F), Config);
jsonify(L, Config) when is_list(L)     ->
  try list_to_binary(L) of
    S -> S
  catch error:badarg ->
    unicode:characters_to_binary(io_lib:format("~0p", [L], chars_limit(Config)))
  end;
jsonify({M, F, A}, _Config) when is_atom(M), is_atom(F), is_integer(A) ->
  <<(a2b(M))/binary,$:,(a2b(F))/binary,$/,(integer_to_binary(A))/binary>>;
jsonify(Any, Config)                   -> unicode:characters_to_binary(io_lib:format("~0p", [Any], chars_limit(Config))).

a2b(A) -> atom_to_binary(A, utf8).

apply_format_funs(Data, #{format_funs := Callbacks}) ->
  maps:fold(fun(K, Fun, Acc) when is_map_key(K, Data) -> maps:update_with(K, Fun, Acc);
               (_, _, Acc)                            -> Acc
            end, Data, Callbacks);
apply_format_funs(Data, _) ->
  Data.

apply_key_mapping(Data, #{key_mapping := Mapping}) ->
  DataOnlyMapped =
    maps:fold(fun(K, V, Acc) when is_map_key(K, Data) -> Acc#{V => maps:get(K, Data)};
                 (_, _, Acc)                          -> Acc
              end, #{}, Mapping),
  DataNoMapped = maps:without(maps:keys(Mapping), Data),
  maps:merge(DataNoMapped, DataOnlyMapped);
apply_key_mapping(Data, _) ->
  Data.

new_line(Config) -> maps:get(new_line, Config, ?NEW_LINE).

meta_without(Meta, Config) ->
    maps:without(maps:get(meta_without, Config, [report_cb]), Meta).

meta_with(Meta, #{ meta_with := Ks}) ->
    maps:with(Ks, Meta);
meta_with(Meta, _ConfigNotPresent) ->
    Meta.


%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

format_test() ->
  ?assertEqual( <<"{\"level\":\"alert\",\"text\":\"derp\"}">>
              , format(#{level => alert, msg => {string, "derp"}, meta => #{}}, #{}) ),
  ?assertEqual( <<"{\"herp\":\"derp\",\"level\":\"alert\"}">>
              , format(#{level => alert, msg => {report, #{herp => derp}}, meta => #{}}, #{}) ).

format_funs_test() ->
  Config1 = #{format_funs => #{ time  => fun(Epoch) -> Epoch + 1 end
                              , level => fun(alert) -> info      end}},
  ?assertEqual( <<"{\"level\":\"info\",\"text\":\"derp\",\"time\":2}">>
              , format(#{level => alert, msg => {string, "derp"}, meta => #{time => 1}}, Config1)),

  Config2 = #{format_funs => #{ time  => fun(Epoch) -> Epoch + 1 end
                              , foobar => fun(alert) -> info      end}},
  ?assertEqual( <<"{\"level\":\"alert\",\"text\":\"derp\",\"time\":2}">>
              , format(#{level => alert, msg => {string, "derp"}, meta => #{time => 1}}, Config2)).

key_mapping_test() ->
  Config1 = #{key_mapping => #{ level => lvl
                              , text => message}},
  ?assertEqual( <<"{\"lvl\":\"alert\",\"message\":\"derp\"}">>
              , format(#{level => alert, msg => {string, "derp"}, meta => #{}}, Config1)),

  Config2 = #{key_mapping => #{ level => lvl
                              , text => level}},
  ?assertEqual( <<"{\"level\":\"derp\",\"lvl\":\"alert\"}">>
              , format(#{level => alert, msg => {string, "derp"}, meta => #{}}, Config2)),

  Config3 = #{key_mapping => #{ level => lvl
                              , foobar => level}},
  ?assertEqual( <<"{\"lvl\":\"alert\",\"text\":\"derp\"}">>
              , format(#{level => alert, msg => {string, "derp"}, meta => #{}}, Config3)),

  Config4 = #{ key_mapping => #{time => timestamp}
             , format_funs => #{timestamp => fun(T) -> T + 1 end}},
  ?assertEqual( <<"{\"level\":\"alert\",\"text\":\"derp\",\"timestamp\":2}">>
              , format(#{level => alert, msg => {string, "derp"}, meta => #{time => 1}}, Config4)).

list_format_test() ->
    ErrorReport =
        #{level => error,
          meta => #{time => 1},
          msg => {report,#{report => [{hej,"hopp"}]}}},
    ?assertEqual( <<"{\"level\":\"error\",\"report\":\"[{hej,\\\"hopp\\\"}]\",\"time\":1}">>
                , format(ErrorReport, #{})).

meta_without_test() ->
    Error = #{ level => info
             , msg => {report, #{answer => 42}}
             , meta => #{secret => xyz}},
    ?assertEqual([ {<<"answer">>, 42}
                 , {<<"level">>, <<"info">>}
                 , {<<"secret">>, <<"xyz">>}
                 ],
        jsx:decode(format(Error, #{}))),
    Config2 = #{ meta_without => [secret]},
    ?assertEqual([ {<<"answer">>, 42}
                 , {<<"level">>, <<"info">>}
                 ],
        jsx:decode(format(Error, Config2))),
    ok.

meta_with_test() ->
    Error = #{ level => info
             , msg => {report, #{answer => 42}}
             , meta => #{secret => xyz}},
    ?assertEqual([ {<<"answer">>, 42}
                 , {<<"level">>, <<"info">>}
                 , {<<"secret">>, <<"xyz">>}
                 ],
        jsx:decode(format(Error, #{}))),
    Config2 = #{ meta_with => [level]},
    ?assertEqual([ {<<"answer">>, 42}
                 , {<<"level">>, <<"info">>}
                 ],
        jsx:decode(format(Error, Config2))),
    ok.

-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% vim: sw=2 ts=2 et
%%%
%%% End:
