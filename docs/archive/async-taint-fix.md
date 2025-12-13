# Async Taint Propagation Fix

## Problem
The taint analysis was failing to propagate taint through `async` functions. Specifically, when an `async` function is lowered to MIR, it becomes a state machine (generator). The arguments to the async function are stored in the generator state (e.g., `_1`). Inside the generator, these fields are accessed via a chain of dereferences and casts:
1. `_1` is the generator state.
2. `_1.0` is a dereference of the state (often aliased to a temporary like `_24`).
3. `((*_1.0) as variant#3).0` accesses a specific field in a specific state variant.

The previous analysis failed to track the connection between the temporary alias (e.g., `_24`) and the generator state `_1`, causing taint to be lost when fields were accessed via the alias.

## Solution
We implemented **Alias Tracking** in the field-sensitive analysis:
1. **Alias Detection**: When a statement like `_N = deref_copy (_M.field)` is encountered, we record that `_N` is an alias for `_M.field`.
2. **Alias Substitution**: In subsequent statements, we substitute occurrences of `_N` with `_M.field`. This allows the existing field-sensitive logic to correctly identify that we are accessing a field of the generator state.
3. **Robust Parsing**: We improved `contains_field_access` and `extract_variable` to handle complex MIR expressions involving dereferences (`*`), downcasts (`as variant#N`), and parentheses.

## Results
The `test_async_flow` test case now passes. Taint is correctly propagated from:
1. `get_async_input()` (Source) -> `_4`
2. `_4` -> `into_future` -> `_3`
3. `_3` -> Generator State Field (via alias)
4. Generator State Field -> `poll` -> Return Value

This enables accurate taint tracking through async/await chains, which is critical for analyzing modern Rust web frameworks (Axum, Actix, Tokio).
