const std = @import("std");

const Regex = struct {
    allocator: std.mem.Allocator,
    instructions: []RegexInst,

    const RegexInst = struct {
        regex_type: union(enum) {
            literal: u8,
            group: []const RegexInst,
            dot,
        },
        modifier: enum {
            none,
            optional,
            star,
            plus,
        },
    };

    fn init(allocator: std.mem.Allocator, regex_string: []const u8) !Regex {
        const insts = try compile(allocator, regex_string);
        return .{
            .allocator = allocator,
            .instructions = insts,
        };
    }

    fn compile(allocator: std.mem.Allocator, regex_string: []const u8) ![]RegexInst {
        var list = std.ArrayList(RegexInst).init(allocator);
        defer list.deinit();

        var current: ?RegexInst = null;

        var i: usize = 0;
        while (true) {
            if (i >= regex_string.len) {
                break;
            }
            const c = regex_string[i];
            defer i += 1;

            switch (c) {
                '*' => {
                    if (current != null) {
                        current.?.modifier = .star;
                    } else {
                        return error.InvalidStarLoc;
                    }
                },
                '+' => {
                    if (current != null) {
                        current.?.modifier = .plus;
                    } else {
                        return error.InvalidPlusLoc;
                    }
                },
                '?' => {
                    if (current != null) {
                        current.?.modifier = .optional;
                    } else {
                        return error.InvalidQuestionMarkLoc;
                    }
                },
                '(' => {
                    if (current) |e| {
                        try list.append(e);
                    }

                    // find matching closing bracket and recurse
                    const start = i;
                    var extras: usize = 0;
                    while (true) {
                        i += 1;
                        if (i >= regex_string.len) {
                            return error.NoClosingBracketFound;
                        }
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

                    const group = regex_string[start + 1 .. i]; // +1 because we do not want to include the brackets
                    const comp_group = try compile(allocator, group);

                    current = .{
                        .regex_type = .{ .group = comp_group },
                        .modifier = .none,
                    };
                },
                '.' => {
                    if (current) |e| {
                        try list.append(e);
                    }

                    current = .{
                        .regex_type = .dot,
                        .modifier = .none,
                    };
                },
                else => {
                    if (current) |e| {
                        try list.append(e);
                    }

                    current = .{
                        .regex_type = .{
                            .literal = c,
                        },
                        .modifier = .none,
                    };
                },
            }
        }
        if (current) |e| {
            try list.append(e);
        }

        return try list.toOwnedSlice();
    }

    pub fn deinit(self: Regex) void {
        Regex.internalDeinit(self.allocator, self.instructions);
    }

    fn internalDeinit(allocator: std.mem.Allocator, insts: []const RegexInst) void {
        for (insts) |inst| {
            switch (inst.regex_type) {
                .group => |g| {
                    internalDeinit(allocator, g);
                },
                else => {},
            }
        }
        allocator.free(insts);
    }

    pub fn isMatch(self: Regex, string: []const u8) !bool {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();

        const res = try consumeMatch(arena.allocator(), self.instructions, string, .only_full);
        return res.len > 0;
    }

    const MatchType = enum {
        only_full,
        partial,
    };

    /// returns the amount of consumed characters
    fn consumeMatch(arena: std.mem.Allocator, instructions: []const RegexInst, string: []const u8, match_type: MatchType) ![]usize {
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
                .group => |group_instructions| {
                    // NOTE: we dont free the returned value here, we just assume it gets cleaned up when the arena is freed.
                    break :blk try consumeMatch(arena, group_instructions, string[state.string_idx..], .partial);
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
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // const string = "a+(b|c)?";
    // const string = "a?b";
    // const regex_string = "a*ab?b";
    const regex_string = "(ab)*ab?";
    // const regex_string = "ab?";
    const regex = try Regex.init(allocator, regex_string);

    // std.debug.print("{any}\n", .{regex.instructions});

    const string = "a";

    const b = regex.isMatch(string);

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
    const allocator = std.testing.allocator;

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
    };

    for (tests) |t| {
        const regex = try Regex.init(allocator, t.regex_string);
        defer regex.deinit();
        const actual = regex.instructions;
        try std.testing.expectEqualSlices(Regex.RegexInst, t.expected, actual);
    }
}

test "regex compilation groups" {
    const allocator = std.testing.allocator;

    const string = "a?(bc?)+";
    const expected = &[_]Regex.RegexInst{
        .{
            .regex_type = .{ .literal = 'a' },
            .modifier = .optional,
        },
        .{
            .regex_type = .{ .group = &[_]Regex.RegexInst{
                .{ .modifier = .none, .regex_type = .{ .literal = 'b' } },
                .{ .modifier = .optional, .regex_type = .{ .literal = 'c' } },
            } },
            .modifier = .plus,
        },
    };

    const regex = try Regex.init(allocator, string);
    defer regex.deinit();
    const actual = regex.instructions;

    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected[0], actual[0]);
    try std.testing.expectEqual(expected[1].modifier, actual[1].modifier);
    try std.testing.expectEqualSlices(Regex.RegexInst, expected[1].regex_type.group, actual[1].regex_type.group);
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
    };

    for (tests) |t| {
        const regex = try Regex.init(allocator, t.regex_string);
        defer regex.deinit();
        for (t.test_strings) |test_string| {
            const actual = regex.isMatch(test_string.string);

            const fmt = "regex: {s}; string: {s} - {any}";
            const expected = try std.fmt.allocPrint(allocator, fmt, .{ t.regex_string, test_string.string, test_string.is_match });
            defer allocator.free(expected);
            try std.testing.expectFmt(expected, fmt, .{ t.regex_string, test_string.string, actual });
        }
    }
}
