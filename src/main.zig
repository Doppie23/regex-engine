const std = @import("std");

const Regex = struct {
    ast: RegexAst,

    const RegexAst = union(enum) {
        boolean: struct {
            left: *const RegexAst,
            right: *const RegexAst,
        },
        list: []const RegexInst,
    };

    const RegexInst = struct {
        regex_type: RegexType,
        modifier: Modifier,
    };

    const RegexType = union(enum) {
        literal: u8,
        group: *const RegexAst,
        dot,
        set: Set,
    };

    const Set = struct {
        not: bool,
        items: []const Item,

        const Item = union(enum) {
            literal: u8,
            range: struct {
                from: u8,
                to: u8,
            },
        };
    };

    const Modifier = enum {
        none,
        optional,
        star,
        plus,
    };

    fn init(comptime regex_string: []const u8) Regex {
        return .{
            .ast = comptime compile(regex_string),
        };
    }

    fn compile(comptime regex_string: []const u8) RegexAst {
        comptime {
            var list: []const RegexInst = &.{};

            var i = 0;

            while (i < regex_string.len) {
                const c = regex_string[i];

                const regex_type: RegexType = switch (c) {
                    '+', '*', '?' => {
                        @compileError("Error parsing regex, cannot start with modifier: " ++ .{c});
                    },
                    '|' => {
                        const rest = regex_string[i + 1 ..];
                        const left: RegexAst = .{ .list = list };
                        const right = compile(rest);
                        return .{
                            .boolean = .{
                                .left = &left,
                                .right = &right,
                            },
                        };
                    },
                    '[' => blk: {
                        const start = i;
                        while (regex_string[i] != ']') : (i += 1) {}
                        const set_string = regex_string[start + 1 .. i];
                        i += 1;

                        if (set_string.len == 0) {
                            @compileError("Error parsing regex, cannot have an empty set []");
                        }

                        var set_items: []const Set.Item = &.{};
                        var j = 0;

                        const not = set_string[j] == '^';
                        if (not) j += 1;

                        while (j < set_string.len) {
                            const char = set_string[j];
                            if (j + 1 < set_string.len and set_string[j + 1] == '-' and
                                j + 2 < set_string.len)
                            {
                                const range_to = set_string[j + 2];
                                set_items = set_items ++ &[_]Set.Item{.{ .range = .{ .from = char, .to = range_to } }};
                                j += 3;
                            } else {
                                set_items = set_items ++ &[_]Set.Item{.{ .literal = char }};
                                j += 1;
                            }
                        }

                        break :blk .{
                            .set = .{
                                .not = not,
                                .items = set_items,
                            },
                        };
                    },
                    '(' => blk: {
                        // find matching closing bracket and recurse
                        const start = i;
                        var extras = 0;

                        // consume the (
                        i += 1;

                        while (i < regex_string.len) : (i += 1) {
                            const nc = regex_string[i];
                            if (nc == '(') {
                                extras += 1;
                            }
                            if (nc == ')') {
                                if (extras == 0) {
                                    break;
                                } else {
                                    extras -= 1;
                                }
                            }
                        }
                        if (i >= regex_string.len) {
                            @compileError("Error parsing regex: NoClosingBracketFound");
                        }

                        const group = regex_string[start + 1 .. i]; // +1 because we do not want to include the brackets
                        const comp_group = compile(group);

                        // finally consume the )
                        i += 1;

                        break :blk .{ .group = &comp_group };
                    },
                    '.' => blk: {
                        i += 1;
                        break :blk .dot;
                    },
                    '\\' => blk: {
                        // consume the \
                        i += 1;
                        if (i >= regex_string.len) {
                            @compileError("Error parsing regex: InvalidEscapeSeqAtEOF");
                        }

                        const next_char = regex_string[i];
                        // consume the next char
                        i += 1;

                        break :blk .{ .literal = next_char };
                    },
                    else => blk: {
                        i += 1;
                        break :blk .{ .literal = c };
                    }
                };

                const modifier: Modifier =
                    if (i < regex_string.len)
                        switch (regex_string[i]) {
                            '*' => blk: {
                                i += 1;
                                break :blk .star;
                            },
                            '+' => blk: {
                                i += 1;
                                break :blk .plus;
                            },
                            '?' => blk: {
                                i += 1;
                                break :blk .optional;
                            },
                            else => .none,
                        }
                    else
                        .none;

                list = list ++ &[_]RegexInst{.{
                    .regex_type = regex_type,
                    .modifier = modifier,
                }};
            }

            return .{ .list = list };
        }
    }

    pub fn isMatch(self: Regex, allocator: std.mem.Allocator, string: []const u8) !bool {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const res = try consumeMatch(arena.allocator(), self.ast, string, .only_full);
        return res.len > 0;
    }

    const MatchType = enum {
        only_full,
        partial,
    };

    /// returns for all possible valid paths (paths where we can exhaust all instructions) the amount of consumed characters
    fn consumeMatch(arena: std.mem.Allocator, ast: RegexAst, string: []const u8, match_type: MatchType) ![]usize {
        switch (ast) {
            .list => |instructions| {
                const State = struct {
                    instruction_idx: usize,
                    string_idx: usize,
                };

                var possible_matches = std.ArrayList(usize).init(arena);
                defer possible_matches.deinit();

                var queue = std.ArrayList(State).init(arena);
                defer queue.deinit();

                try queue.append(.{
                    .instruction_idx = 0,
                    .string_idx = 0,
                });

                while (queue.items.len > 0) {
                    const state = queue.pop().?;

                    if (state.instruction_idx >= instructions.len and state.string_idx >= string.len) {
                        // done with string and instructions, means a full match
                        try possible_matches.append(state.string_idx);
                        if (match_type == .only_full) {
                            break;
                        } else {
                            continue;
                        }
                    }

                    if (state.instruction_idx >= instructions.len) {
                        // went through all instructions, yet still part of string left
                        // so a partial match

                        if (match_type == .partial) {
                            try possible_matches.append(state.string_idx);
                        }
                        continue;
                    }
                    const inst = instructions[state.instruction_idx];

                    const maybe_char = if (state.string_idx < string.len) string[state.string_idx] else null;

                    // get all the possible valid paths based on the regex instruction
                    const amounts_consumed: []const usize = blk: switch (inst.regex_type) {
                        .literal => |expected| {
                            if (maybe_char) |char| {
                                break :blk &.{(if (char == expected) 1 else 0)};
                            } else {
                                break :blk &.{0};
                            }
                        },
                        .dot => {
                            if (maybe_char) |_| {
                                break :blk &.{1};
                            } else {
                                break :blk &.{0};
                            }
                        },
                        .set => |set| {
                            if (maybe_char) |char| {
                                var any_matches = false;
                                outer: for (set.items) |item| {
                                    switch (item) {
                                        .literal => |expected| {
                                            if (char == expected) {
                                                any_matches = true;
                                                break :outer;
                                            }
                                        },
                                        .range => |range| {
                                            if (range.from <= char and char <= range.to) {
                                                any_matches = true;
                                                break :outer;
                                            }
                                        }
                                    }
                                }
                                if (set.not) {
                                    any_matches = !any_matches;
                                }
                                break :blk &.{if (any_matches) 1 else 0};
                            } else {
                                break :blk &.{0};
                            }
                        },
                        .group => |group_instructions| {
                            // NOTE: we dont free the returned value here, we just assume it gets cleaned up when the arena is freed.
                            break :blk try consumeMatch(arena, group_instructions.*, string[state.string_idx..], .partial);
                        },
                    };

                    // determine based on the modifier all the extra paths we can follow
                    switch (inst.modifier) {
                        .none => {
                            for (amounts_consumed) |consumed| {
                                if (consumed > 0) {
                                    try queue.append(.{
                                        .instruction_idx = state.instruction_idx + 1,
                                        .string_idx = state.string_idx + consumed,
                                    });
                                }
                            }
                        },
                        .plus => {
                            for (amounts_consumed) |consumed| {
                                if (consumed > 0) {
                                    try queue.append(.{
                                        .instruction_idx = state.instruction_idx + 1,
                                        .string_idx = state.string_idx + consumed,
                                    });
                                    try queue.append(.{
                                        .instruction_idx = state.instruction_idx,
                                        .string_idx = state.string_idx + consumed,
                                    });
                                }
                            }
                        },
                        .star => {
                            for (amounts_consumed) |consumed| {
                                if (consumed > 0) {
                                    try queue.append(.{
                                        .instruction_idx = state.instruction_idx + 1,
                                        .string_idx = state.string_idx + consumed,
                                    });
                                    try queue.append(.{
                                        .instruction_idx = state.instruction_idx,
                                        .string_idx = state.string_idx + consumed,
                                    });
                                }
                            }
                            try queue.append(.{
                                .instruction_idx = state.instruction_idx + 1,
                                .string_idx = state.string_idx,
                            });
                        },
                        .optional => {
                            for (amounts_consumed) |consumed| {
                                if (consumed > 0) {
                                    try queue.append(.{
                                        .instruction_idx = state.instruction_idx + 1,
                                        .string_idx = state.string_idx + consumed,
                                    });
                                }
                            }
                            try queue.append(.{
                                .instruction_idx = state.instruction_idx + 1,
                                .string_idx = state.string_idx,
                            });
                        },
                    }
                }

                return possible_matches.toOwnedSlice();
            },
            .boolean => |b| {
                const res_left = try consumeMatch(arena, b.left.*, string, match_type);
                const res_right = try consumeMatch(arena, b.right.*, string, match_type);

                var buffer = try arena.alloc(usize, res_left.len + res_right.len);
                var i: usize = 0;

                for (res_left) |e| {
                    buffer[i] = e;
                    i += 1;
                }

                for (res_right) |e| {
                    buffer[i] = e;
                    i += 1;
                }

                return buffer;
            },
        }
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // const string = "a+(b|c)?";
    // const regex_string = "a?b";
    // const regex_string = "\\*a*ab?b";
    // const regex_string = "a?(bc?)+";
    // const regex_string = "gr(a|e)y";
    const regex_string = "gr(a|e)y";
    const regex = Regex.init(regex_string);

    // std.debug.print("{any}\n", .{regex.ast.list[2]});
    // std.debug.print("{any}\n", .{regex.ast.list[2].regex_type.group.boolean.left.list[0]});
    // std.debug.print("{any}\n", .{regex.ast.list[2].regex_type.group.boolean.right.list[0]});

    const string = "gryy";

    const b = regex.isMatch(allocator, string);

    std.debug.print("{any}\n", .{b});
    // std.debug.print("{any}\n", .{regex[1]});
    // std.debug.print("{any}\n", .{regex[1].regex_type.group});

    // const regex = [_]RegexChar{
    //     .{
    //         .regex_type = .{
    //             .literal = 'a',
    //         },
    //         .modifier = .plus,
    //     },
    //     .{
    //         .regex_type = .{
    //             .either = .{
    //                 .left = &.{
    //                     .regex_type = .{
    //                         .literal = 'b',
    //                     },
    //                     .modifier = .none,
    //                 },
    //                 .right = &.{
    //                     .regex_type = .{
    //                         .literal = 'c',
    //                     },
    //                     .modifier = .none,
    //                 },
    //             },
    //         },
    //         .modifier = .optional,
    //     },
    // };
    //
}

test "regex compilation modifiers" {
    const Test = struct {
        expected: []const Regex.RegexInst,
        regex_string: []const u8,
    };

    const tests = [_]Test{
        Test{
            .regex_string = "a?",
            .expected = &[_]Regex.RegexInst{
                .{
                    .regex_type = .{ .literal = 'a' },
                    .modifier = .optional,
                },
            },
        },
        Test{
            .regex_string = "ab?",
            .expected = &[_]Regex.RegexInst{
                .{
                    .regex_type = .{ .literal = 'a' },
                    .modifier = .none,
                },
                .{
                    .regex_type = .{ .literal = 'b' },
                    .modifier = .optional,
                },
            },
        },
        Test{
            .regex_string = "a*",
            .expected = &[_]Regex.RegexInst{
                .{
                    .regex_type = .{ .literal = 'a' },
                    .modifier = .star,
                },
            },
        },
        Test{
            .regex_string = "a+",
            .expected = &[_]Regex.RegexInst{
                .{
                    .regex_type = .{ .literal = 'a' },
                    .modifier = .plus,
                },
            },
        },
        Test{
            .regex_string = ".+",
            .expected = &[_]Regex.RegexInst{
                .{
                    .regex_type = .dot,
                    .modifier = .plus,
                },
            },
        },
        Test{
            .regex_string = ".\\.+",
            .expected = &[_]Regex.RegexInst{
                .{
                    .regex_type = .dot,
                    .modifier = .none,
                },
                .{
                    .regex_type = .{ .literal = '.' },
                    .modifier = .plus,
                },
            },
        },
    };

    inline for (tests) |t| {
        const regex = Regex.init(t.regex_string);
        const actual = regex.ast.list;
        try std.testing.expectEqualSlices(Regex.RegexInst, t.expected, actual);
    }
}

test "regex compilation groups" {
    const string = "a?(bc?)+";
    const expected = &[_]Regex.RegexInst{
        .{
            .regex_type = .{ .literal = 'a' },
            .modifier = .optional,
        },
        .{
            .regex_type = .{ .group = &.{ .list = &[_]Regex.RegexInst{
                .{ .modifier = .none, .regex_type = .{ .literal = 'b' } },
                .{ .modifier = .optional, .regex_type = .{ .literal = 'c' } },
            } } },
            .modifier = .plus,
        },
    };

    const regex = Regex.init(string);
    const actual = regex.ast.list;

    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected[0], actual[0]);
    try std.testing.expectEqual(expected[1].modifier, actual[1].modifier);
    try std.testing.expectEqualSlices(Regex.RegexInst, expected[1].regex_type.group.list, actual[1].regex_type.group.list);
}

test "regex compilation boolean or" {
    const string = "a?|b+";
    const expected = Regex.RegexAst{
        .boolean = .{
            .left = &.{
                .list = &.{
                    .{ .regex_type = .{ .literal = 'a' }, .modifier = .optional },
                },
            },
            .right = &.{
                .list = &.{
                    .{ .regex_type = .{ .literal = 'b' }, .modifier = .plus },
                },
            },
        },
    };

    const regex = Regex.init(string);
    const actual = regex.ast;

    try std.testing.expectEqualSlices(Regex.RegexInst, expected.boolean.left.list, actual.boolean.left.list);
    try std.testing.expectEqualSlices(Regex.RegexInst, expected.boolean.right.list, actual.boolean.right.list);
}

test "regex compilation set" {
    const string = "[^abc-d]?c";
    const expected = &[_]Regex.RegexInst{
        .{
            .regex_type = .{ .set = .{
                .not = true,
                .items = &.{
                    .{ .literal = 'a' },
                    .{ .literal = 'b' },
                    .{ .range = .{ .from = 'c', .to = 'd' } },
                },
            } },
            .modifier = .optional,
        },
        .{
            .regex_type = .{ .literal = 'c' },
            .modifier = .none,
        },
    };

    const regex = Regex.init(string);
    const actual = regex.ast.list;

    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected[0].modifier, actual[0].modifier);
    try std.testing.expectEqual(expected[0].regex_type.set.not, actual[0].regex_type.set.not);
    try std.testing.expectEqualSlices(Regex.Set.Item, expected[0].regex_type.set.items, actual[0].regex_type.set.items);

    try std.testing.expectEqual(expected[1], actual[1]);
}

test "matches" {
    const allocator = std.testing.allocator;

    const TestString = struct {
        string: []const u8,
        is_match: bool,
    };

    const Test = struct {
        regex_string: []const u8,
        test_strings: []const TestString,
    };

    const tests = [_]Test{
        .{
            .regex_string = "ab?",
            .test_strings = &[_]TestString{
                .{ .string = "ab", .is_match = true },
                .{ .string = "a", .is_match = true },
            },
        },
        .{
            .regex_string = "ab*",
            .test_strings = &[_]TestString{
                .{ .string = "ab", .is_match = true },
                .{ .string = "abbb", .is_match = true },
                .{ .string = "a", .is_match = true },
            },
        },
        .{
            .regex_string = "ab+",
            .test_strings = &[_]TestString{
                .{ .string = "ab", .is_match = true },
                .{ .string = "abbb", .is_match = true },
                .{ .string = "a", .is_match = false },
            },
        },
        .{
            .regex_string = "a*a",
            .test_strings = &[_]TestString{
                .{ .string = "aa", .is_match = true },
                .{ .string = "a", .is_match = true },
                .{ .string = "aaaaaa", .is_match = true },
                .{ .string = "ab", .is_match = false },
            },
        },
        .{
            .regex_string = "a+a",
            .test_strings = &[_]TestString{
                .{ .string = "aa", .is_match = true },
                .{ .string = "aaaaaa", .is_match = true },
                .{ .string = "ab", .is_match = false },
                .{ .string = "a", .is_match = false },
            },
        },
        .{
            .regex_string = ".*a",
            .test_strings = &[_]TestString{
                .{ .string = "aa", .is_match = true },
                .{ .string = "aaaaaa", .is_match = true },
                .{ .string = "babaa", .is_match = true },
                .{ .string = "a", .is_match = true },
            },
        },
        .{
            .regex_string = "a*ab?b",
            .test_strings = &[_]TestString{
                .{ .string = "ab", .is_match = true },
                .{ .string = "aaaab", .is_match = true },
                .{ .string = "aaaabb", .is_match = true },
                .{ .string = "aaaabbb", .is_match = false },
            },
        },
        .{
            .regex_string = "(ab)*ab",
            .test_strings = &[_]TestString{
                .{ .string = "ab", .is_match = true },
                .{ .string = "abab", .is_match = true },
                .{ .string = "ababab", .is_match = true },
                .{ .string = "ba", .is_match = false },
            },
        },
        .{
            .regex_string = "(ab)*ab?",
            .test_strings = &[_]TestString{
                .{ .string = "ab", .is_match = true },
                .{ .string = "ababab", .is_match = true },
                .{ .string = "a", .is_match = true },
                .{ .string = "ababa", .is_match = true },
                .{ .string = "ba", .is_match = false },
            },
        },
        .{
            .regex_string = "a|b",
            .test_strings = &[_]TestString{
                .{ .string = "a", .is_match = true },
                .{ .string = "b", .is_match = true },
                .{ .string = "c", .is_match = false },
            },
        },
        .{
            .regex_string = "a|b|c",
            .test_strings = &[_]TestString{
                .{ .string = "a", .is_match = true },
                .{ .string = "b", .is_match = true },
                .{ .string = "c", .is_match = true },
                .{ .string = "d", .is_match = false },
            },
        },
        .{
            .regex_string = "gray|grey",
            .test_strings = &[_]TestString{
                .{ .string = "gray", .is_match = true },
                .{ .string = "grey", .is_match = true },
                .{ .string = "gruy", .is_match = false },
            },
        },
        .{
            .regex_string = "gr(e|a)y",
            .test_strings = &[_]TestString{
                .{ .string = "gray", .is_match = true },
                .{ .string = "grey", .is_match = true },
                .{ .string = "gruy", .is_match = false },
            },
        },
        .{
            .regex_string = "ab(ab|cd)+e",
            .test_strings = &[_]TestString{
                .{ .string = "abcdabe", .is_match = true },
                .{ .string = "ababcde", .is_match = true },
                .{ .string = "abcde", .is_match = true },
                .{ .string = "abade", .is_match = false },
            },
        },
        .{
            .regex_string = "ab(ab|cd)*e?",
            .test_strings = &[_]TestString{
                .{ .string = "abcdabe", .is_match = true },
                .{ .string = "abcdab", .is_match = true },
                .{ .string = "ababcde", .is_match = true },
                .{ .string = "ababcd", .is_match = true },
                .{ .string = "abcde", .is_match = true },
                .{ .string = "abe", .is_match = true },
                .{ .string = "ab", .is_match = true },
                .{ .string = "abade", .is_match = false },
            },
        },
        .{
            .regex_string = "a(b+|c+)*d",
            .test_strings = &[_]TestString{
                .{ .string = "ad", .is_match = true },
                .{ .string = "acccccd", .is_match = true },
                .{ .string = "abbbbbd", .is_match = true },
                .{ .string = "accbbbcccd", .is_match = true },
                .{ .string = "add", .is_match = false },
            },
        },
        .{
            .regex_string = "a(bc?d|efg)+",
            .test_strings = &[_]TestString{
                .{ .string = "abcdbdefgbd", .is_match = true },
            },
        },
        .{
            .regex_string = "[abc]d",
            .test_strings = &[_]TestString{
                .{ .string = "ad", .is_match = true },
                .{ .string = "bd", .is_match = true },
                .{ .string = "cd", .is_match = true },
                .{ .string = "dd", .is_match = false },
            },
        },
        .{
            .regex_string = "[^abc]d",
            .test_strings = &[_]TestString{
                .{ .string = "dd", .is_match = true },
                .{ .string = "ad", .is_match = false },
                .{ .string = "bd", .is_match = false },
                .{ .string = "cd", .is_match = false },
            },
        },
        .{
            .regex_string = "[a-e]+",
            .test_strings = &[_]TestString{
                .{ .string = "abcde", .is_match = true },
                .{ .string = "abcdef", .is_match = false },
            },
        },
        .{
            .regex_string = "[^a-ei-z]+",
            .test_strings = &[_]TestString{
                .{ .string = "fgh", .is_match = true },
                .{ .string = "fghijk", .is_match = false },
                .{ .string = "abcde", .is_match = false },
            },
        },
        .{
            .regex_string = "[a-egh]+",
            .test_strings = &[_]TestString{
                .{ .string = "abcdegh", .is_match = true },
                .{ .string = "abcdef", .is_match = false },
            },
        },
        .{
            .regex_string = "[a-zA-Z0-9]+@[a-zA-Z]+\\.com",
            .test_strings = &[_]TestString{
                .{ .string = "a10@a.com", .is_match = true },
                .{ .string = "a+@a.com", .is_match = false },
                .{ .string = "a10@10.com", .is_match = false },
                .{ .string = "a10@10.com", .is_match = false },
            },
        },
    };

    inline for (tests) |t| {
        const regex = Regex.init(t.regex_string);
        for (t.test_strings) |test_string| {
            const actual = regex.isMatch(allocator, test_string.string);

            const fmt = "regex: {s}; string: {s} - {any}";
            const expected = try std.fmt.allocPrint(allocator, fmt, .{ t.regex_string, test_string.string, test_string.is_match });
            defer allocator.free(expected);
            try std.testing.expectFmt(expected, fmt, .{ t.regex_string, test_string.string, actual });
        }
    }
}
