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
