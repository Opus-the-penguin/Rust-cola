# Infinite Iterator Test Cases

This example demonstrates detection of infinite iterators without proper termination conditions.

## The Risk

Infinite iterators like `std::iter::repeat()`, `.cycle()`, and `repeat_with()` create sequences with no natural end. If these are consumed without termination methods, they cause:

1. **Denial of Service (DoS)**: Unbounded loops that never complete
2. **Resource Exhaustion**: Memory consumption grows without bound when collecting
3. **Application Hang**: The program becomes unresponsive

## Common Patterns

### Problematic (No Termination)

```rust
// Would hang forever trying to collect infinite elements
iter::repeat(42).collect()
vec![1, 2, 3].into_iter().cycle().collect()
iter::repeat_with(|| get_value()).collect()
```

### Safe (With Termination)

```rust
// Properly bounded
iter::repeat(42).take(10).collect()
vec![1, 2, 3].into_iter().cycle().take(100).collect()
iter::repeat_with(|| get_value()).take_while(|x| x.is_valid()).collect()

// Short-circuit methods that consume until condition
iter::repeat(42).find(|&x| x == target)
iter::repeat(42).any(|x| x > threshold)
iter::repeat(42).position(|&x| x == target)
```

## Detection Strategy

RUSTCOLA054 uses heuristic detection:

1. **Identify infinite iterators**: Look for `repeat`, `cycle`, or `repeat_with` calls
2. **Check for terminators**: Look for `take`, `take_while`, `any`, `find`, or `position`
3. **Flag if missing**: Report when infinite iterator lacks termination

## Limitations

This is a heuristic rule with limitations:

- **Manual breaks**: Cannot detect `for` loops with manual `break` statements
- **Dataflow**: Doesn't track if termination happens in separate statement
- **False positives**: May flag code that terminates through control flow

Despite limitations, this rule catches the most common dangerous pattern: directly collecting from infinite iterators.

## References

- Sonar RSPEC-7464: Infinite iterators should have a termination condition
