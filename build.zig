const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    _ = b.addModule("zlzmq", .{
        .root_source_file = b.path("zmq.zig"),
        .target = target,
        .optimize = optimize,
    });
}
