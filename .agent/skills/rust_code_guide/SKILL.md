# Rust code guide

In rust code always follow these coding guidelines when available:

## Error Handling:
- Once the programs are initiallized the program **MUST NOT** panic
- No .unwrap() or .expect() outside of program initiallization

## Code Style:
- When using format! and you can inline variables into {}, always do that.
- When possible, make match statements exhaustive and avoid wildcard arms.
- Always collapse if statements per https://rust-lang.github.io/rust-clippy/master/index.html#collapsible_if
- Always inline format! args when possible per https://rust-lang.github.io/rust-clippy/master/index.html#uninlined_format_args
- Use method references over closures when possible per https://rust-lang.github.io/rust-clippy/master/index.html#redundant_closure_for_method_calls
- Never place `use` statements inside functions. All imports at file top.
- Do not create small helper methods that are referenced only once.
- If you have three or more repetitions, make a jig. This is a hard rule: 3+ repetitions = create an abstraction. Less than 3 = duplicate the pattern.
- For authentication secret related fields in the API definitions wrap them in the `Secret`, defined in [secrets](../../../server/babel-api-definition/src/secrets/), and add use `#[serde(serialize_with = "expose_secret")]` to expose the secret for serialization.
- For logging prefer the macros `mimic_log!`, `mimic_error!` and `mimic_success!` over the standard output macros in crates where `std` is available
- Reduce allocations by using things like ``with_capacity`` to Pre-allocate


## Documentation:
- `//` comments explain why (safety, workarounds, design rationale)
- `///` doc comments explain what and how for public APIs
- Enable `#![deny(missing_docs)]` for libraries

## Linting:
- Check code quality with `cargo clippy` reqularly
- Key lints to watch for:
  - ``redundant_clone`` - unnecessary cloning
  - ``large_enum_variant`` - oversized variants (consider boxing)
  - ``needless_collect`` - premature collection
- Use `#[expect(clippy::lint)]` over `#[allow(...)]` with justification comment.

## Dependencies:
- Do not add new single-use dependencies, without the users permission, if they can be implemented within less than 5 small functions.

**IMPORTANT**: All Rust dependencies MUST be added to the workspace root `Cargo.toml`, not individual crate `Cargo.toml` files.

1. Add to `[workspace.dependencies]` in root `Cargo.toml`:
   ```toml
   new-crate = { version = "1.0.0", features = ["feature1"] }
   ```

2. Reference in crate's `Cargo.toml`:
   ```toml
   [dependencies]
   new-crate.workspace = true
   ```

## Async Best Practices:

**Don'ts**
- Don't block - Never use std::thread::sleep in async
- Don't hold locks across awaits - Causes deadlocks
- Don't ignore errors - Propagate with ? or log


