# Dangling Pointer Use-After-Free Rule Design

## Objective
Detect scenarios where a raw pointer (or reference exposed as a raw pointer) is dereferenced, returned, or otherwise consumed after the memory it references has been freed, reallocated, or gone out of scope. The rule targets unsafe blocks, FFI boundaries, global stores, and pointer escapes that lead to use-after-free vulnerabilities.

## Detection Contract
- **Inputs:** MIR for each function (`MirFunction::body`), plus helper analyses (current `MirDataflow`, upcoming pointer lifetime tracker).
- **Outputs:** Findings containing the pointer variable, owning allocation, and MIR evidence lines leading to the hazardous use.
- **Success Criteria:**
  1. Flag pointer dereferences (`*ptr`, `ptr::read`, `ptr::copy[_nonoverlapping]`, etc.) when the base allocation has been dropped or reallocated.
  2. Flag pointer escapes (return values, struct/global stores, closure captures) when the base allocation is stack-bound.
  3. Avoid false positives for `'static` data, deliberately leaked memory (`Box::leak`, `Box::into_raw` without reclamation), and ownership transfers where the callee guarantees validity.

## MIR Event Model
We classify MIR statements into three event families. Pattern matching will reuse the existing textual analysis style used elsewhere in `mir-extractor`.

| Event Type | Example MIR Snippet | Notes |
|------------|---------------------|-------|
| `PointerCreate` | `_5 = &raw const (*_3);`<br>`_1 = &(*_2);`<br>`_7 = alloc::boxed::Box::<i32>::into_raw(move _6);` | Captures the pointer variable (`_5`) and its *owner* (`_3`, `_6`, etc.). Owners can be locals, arguments, Box/Vec/String, or temporaries. |
| `OwnerDrop` | `drop(_3) -> ...;`<br>`_0 = drop_in_place::<Vec<i32>>(move _2);`<br>`_0 = alloc::alloc::dealloc(move _1, move _2);` | Indicates that the owner no longer guarantees the pointer’s validity. Includes implicit drops at block ends (`drop` terminators), explicit `drop` calls, and allocator/deallocation APIs. |
| `PointerUse` | `* _5 = ...;`<br>`_0 = core::ptr::read::<i32>(move _5);`<br>`_0 = _5 as *const i32;` | Represents dereferences or escapes. Additional “escape” contexts are return statements, struct field stores, `static mut` writes, and arguments to calls. |

## Owner Classification
We model each pointer’s backing resource to reason about lifetime:

1. **Stack locals:** `_ptr = &raw const (*_local);` or derived via casts. The local dies at scope end (implicit `drop` terminator). Any pointer escaping the function is suspicious.
2. **Heap owners:** Box, Vec, String, CString, `VecDeque`, etc. Freed on explicit drop or when methods that reallocate are invoked (`Vec::push`, `Vec::reserve`, `Vec::shrink_to`).
3. **Borrowed inputs:** References derived from parameters (`_1 = _arg;`). Escapes can be allowed; focus on reallocation-induced invalidation.
4. **Manually leaked:** `Box::leak`, `ManuallyDrop`, `std::mem::forget`. Treat as safe once leak detected.

Each `PointerCreate` maps pointer ID → `PointerInfo` containing:
- `ptr_var`: MIR temp holding the pointer.
- `owner`: either a variable (`_x`) or call expression (for heap allocation).
- `source_kind`: enumerated (LocalRef, BoxRaw, VecAsPtr, AddrOf, Unknown).
- `evidence`: MIR lines leading to creation.

## Algorithm Sketch

1. **Collect Assignments & Terminators**
   - Reuse `MirDataflow` to parse assignments. Extend it (or the rule) with `collect_pointer_events(function)` to iterate `function.body` and classify lines.
   - Track block terminators to catch implicit drops (`drop(_x) -> [return: bbY, unwind: bbZ];`).

2. **Build Ownership Graph**
   - For each pointer, resolve the owner variable and alias chain. Propagate through simple copies (`_7 = _5;`) via `MirDataflow`.
   - When owner is a local stack slot (identified by RHS patterns like `&raw const (*_N)` where `_N` originates from `_local = const`), mark pointer as `StackBound`.
   - When owner is a heap container, register invalidation triggers: explicit drop, calls to known reallocation methods, or assignment overwriting the container.

3. **Detect Invalidation**
   - Maintain `owner_state`: `Alive`, `Dropped`, `MaybeReallocated`.
   - Transitions:
     - `OwnerDrop` → `Dropped`.
     - Reallocating call (`Vec::push`, `Vec::extend`, `String::push_str`, etc.) → `MaybeReallocated`.
     - `ManuallyDrop` / `Box::leak` → mark as `Leaked` (safe).

4. **Emit Findings**
   - For each `PointerUse` after owner is no longer `Alive`, emit `Finding` with severity `High` and include the MIR lines from creation, invalidation, and use.
   - For pointer escapes (return/closure/global store) when owner is `StackBound`, emit `Medium` severity (configurable).
   - Include heuristics to suppress duplicates (dedupe by pointer + basic block).

5. **False Positive Mitigations**
   - Whitelist `'static` borrows: detect literals or `&'static` references (lines containing `const` or `"static"` type).
   - Recognize `Box::from_raw` immediately following `into_raw` with same pointer and treat as ownership transfer.
   - Allow immediate use before drop (safe_local_use pattern) by checking block ordering: if invalidation and use are in same block but use precedes drop terminator, do not flag.

## Implementation Plan

1. **Infrastructure additions (current task)**
   - Implement `PointerEvent` extractor in `mir-advanced-rules` to classify `PointerCreate`, `OwnerDrop`, `PointerUse`, `PointerEscape` events.
   - Leverage `MirDataflow` to follow simple variable aliases.

2. **Phase 1 Heuristics**
   - Cover stack-bound locals (`&raw`, `addr_of`) and heap owners (`Vec::as_ptr`, `Vec::as_mut_ptr`, `Box::as_ptr`, `String::as_ptr`).
   - Handle explicit `drop(_)` and `Vec::push` invalidations.
   - Flag dereferences and return-value escapes past invalidation.

3. **Phase 2 Enhancements**
   - Model closure captures and global stores (`static mut`).
   - Recognize more deallocation APIs (`Vec::shrink_to_fit`, `Vec::drain`, `CString::from_raw`, `libc::free`).
   - Integrate interprocedural summaries (call arguments that receive pointers).

4. **Phase 3 Hard Cases**
   - Field-sensitive tracking (pointers stored in structs, fields dropped).
   - Integration with HIR type metadata for precise container detection.
   - Async/concurrency contexts (pointer live across await).

## Test Coverage Targets

| Scenario | Example (`examples/raw-pointer-escape`) | Expected Outcome |
|----------|------------------------------------------|------------------|
| Stack pointer returned | `bad_return_stack_ptr` | Finding (escape) |
| Stack pointer stored in global | `bad_store_in_global` | Finding (escape) |
| Vec pointer after `push` | `bad_ptr_after_push` | Finding (invalidated) |
| Temp expression pointer | `bad_temp_expression_ptr` | Finding (owner dropped on temp drop) |
| Closure capture | `bad_closure_escape` | Finding (escape) |
| Immediate safe use | `safe_local_use` | No finding |
| `'static` pointer | `safe_static_ptr` | No finding |
| Box leak | `safe_leaked_ptr` | No finding |
| ManuallyDrop | `safe_manually_drop` | No finding |

## Next Steps
- Translate this design into parsing helpers and state machines inside `DanglingPointerUseAfterFreeRule::evaluate`.
- Add regression tests using the `raw-pointer-escape` example once analysis is wired into `cargo-cola` integration tests.
