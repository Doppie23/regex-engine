const std = @import("std");
const Regex = @import("Regex.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const regex_string = "gr(a|e)y";
    const regex = Regex.init(regex_string);

    const strings = [_][]const u8{
        "gray",
        "grey",
        "not gray",
    };

    std.debug.print("Regex: {s}\n", .{regex_string});
    for (strings) |string| {
        const is_match = try regex.isMatch(allocator, string);
        std.debug.print("\"{s}\" {s}\n", .{ string, if (is_match) "is a match" else "is not a match" });
    }
}
