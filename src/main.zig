const std = @import("std");

const Regex = struct {
    allocator: std.mem.Allocator,
    instructions: []RegexInst,

    const RegexInst = struct {
        regex_type: union(enum) {
            literal: u8,
            // either: struct {
            //     left: *const RegexChar,
            //     right: *const RegexChar,
            // },
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
        const State = struct {
            instruction_idx: usize,
            string_idx: usize,
        };

        var queue = std.ArrayList(State).init(self.allocator);
        defer queue.deinit();

        try queue.append(.{
            .instruction_idx = 0,
            .string_idx = 0,
        });

        while (queue.items.len > 0) {
            const state = queue.pop().?;

            if (state.instruction_idx >= self.instructions.len and state.string_idx >= string.len) {
                // done with string and instructions, means a match
                return true;
            }

            if (state.instruction_idx >= self.instructions.len) {
                // went through all instructions, yet still part of string left
                continue;
            }
            const inst = self.instructions[state.instruction_idx];
            if (state.string_idx >= string.len) {
                // went through the entire string, but still instructions left
                continue;
            }
            const char = string[state.string_idx];

            const instruction_completed = blk: switch (inst.regex_type) {
                .literal => |expected| {
                    break :blk (char == expected);
                },
                .dot => {
                    break :blk true;
                },
                .group => {
                    // TODO:
                    // make this function recursive, return all possible
                    // matches, with how many consumed, with a bool indicating
                    // if we should get partal or full matches
                    // add all matches to the queue based on below modifier logic
                    return error.Unimplemented;
                },
            };

            switch (inst.modifier) {
                .none => {
                    if (instruction_completed) {
                        try queue.append(.{
                            .instruction_idx = state.instruction_idx + 1,
                            .string_idx = state.string_idx + 1,
                        });
                    }
                },
                .plus => {
                    if (instruction_completed) {
                        try queue.append(.{
                            .instruction_idx = state.instruction_idx + 1,
                            .string_idx = state.string_idx + 1,
                        });
                        try queue.append(.{
                            .instruction_idx = state.instruction_idx,
                            .string_idx = state.string_idx + 1,
                        });
                    }
                },
                .star => {
                    if (instruction_completed) {
                        try queue.append(.{
                            .instruction_idx = state.instruction_idx + 1,
                            .string_idx = state.string_idx + 1,
                        });
                        try queue.append(.{
                            .instruction_idx = state.instruction_idx,
                            .string_idx = state.string_idx + 1,
                        });
                    }
                    try queue.append(.{
                        .instruction_idx = state.instruction_idx + 1,
                        .string_idx = state.string_idx,
                    });
                },
                .optional => {
                    if (instruction_completed) {
                        try queue.append(.{
                            .instruction_idx = state.instruction_idx + 1,
                            .string_idx = state.string_idx + 1,
                        });
                    }
                    try queue.append(.{
                        .instruction_idx = state.instruction_idx + 1,
                        .string_idx = state.string_idx,
                    });
                },
            }
        }

        return false;
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // const string = "a+(b|c)?";
    // const string = "a?b";
    const regex_string = "a*ab?b";
    const regex = try Regex.init(allocator, regex_string);

    // std.debug.print("{any}\n", .{regex.instructions});

    const string = "ab";

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
