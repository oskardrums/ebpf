-type beam_literal() :: {'integer', integer()}.
-type beam_register_kind() :: 'x' | 'y'.
-type beam_register() :: {beam_register_kind(), non_neg_integer}.
-type beam_value() :: beam_register() | beam_literal().
-type beam_label() :: non_neg_integer().
-type beam_instruction() :: 
	'return'
      | {'label', beam_label()}
      | {'func_info', {'atom', atom()}, {'atom', atom()}, non_neg_integer()}
      | {'move', beam_register(), beam_value()}
      | {'allocate', non_neg_integer(), non_neg_integer()}
      | {'deallocate', non_neg_integer()}
      | {'call_ext', non_neg_integer(), {'extfunc', atom(), atom(), non_neg_integer()}}
      | {'gc_bif', atom(), {'f', non_neg_integer()}, non_neg_integer(), [beam_value()], beam_register()}
.

