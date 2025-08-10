# Zig Regex Engine

> [!WARNING]
> The engine is not intended for production use and built purely as learning project.

A custom Regex Engine written in Zig **for educational purposes only**. This engine
was built entirely from scratch without external guides, with the primary goal
of understanding regex internals and exploring Zig's features.

## Features

- **Compile-Time AST**: The regex pattern is parsed and compiled at Zig's
  `comptime`. Meaning, the final binary contains only the parsed AST, not
  the original regex string.
- **Basic Operators**:
  - Alternation: `|`
  - Character sets: `[abc]`, `[^a-z]`, `[a-z]`, etc
  - Dot operator: `.`
  - Groups: `(...)`
  - Quantifiers: `?` (optional), `*` (zero or more), `+` (one or more)
  - Literal characters

## Limitations

- Only supports full-string match checks.

## Getting Started

- Zig `0.14.1`

Run all the tests, located in [`src/Regex.zig`](./src/Regex.zig):

```console
$ zig build test
```

Run a simple example, located in [`src/main.zig`](./src/main.zig):

```console
$ zig build run
```

## Usage

```
const regex = Regex.init("gr(a|e)y");
const is_match = regex.isMatch("gray");
std.debug.print("{any}\n", .{is_match});
// true
```
