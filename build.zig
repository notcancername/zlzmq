const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    b.addModule("zlzmq", .{
        .root_source_file = "zmq.zig",
        .target = target,
        .optimize = optimize,
    });
}
