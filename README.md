# zlzmq
- Tight Zig wrapper or bindings to [libzmq](https://github.com/zeromq/libzmq), with some minimal
helpers.
- For a more high-level API, see [zzmq](https://github.com/nine-lives-later/zzmq).

## Using from Zig

```shell-session
$ zig fetch --save 'git+https://github.com/notcancername/zlzmq#master'
```

```zig
const zlzmq_dep = b.dependency("zlzmq", .{});
exe.root_module.addImport("zlzmq", zlzmq_dep.module("zlzmq"));
```

### Vendoring libzmq
To vendor and statically link libzmq, you can use
[notcancername/libzmq](https://github.com/notcancername/libzmq). See that for features and libraries
you might want. Note that this is a security risk since it makes updates impossible without
recompiling.

```shell-session
$ zig fetch --save 'git+https://github.com/notcancername/libzmq#master'
```

```zig
const libzmq_dep = b.dependency("libzmq", .{ .target = target, .optimize = .optimize, .shared = false });
const libzmq = libzmq_dep.artifact("libzmq");
exe.linkLibrary(libzmq);
```

## Basic mappings
- `Context`: used by `zmq_ctx_*` functions
- `Socket`: used by  all functions that operate on sockets
- `Message`: `zmq_msg_t`
- `z85`: functions that deal with Z85

## Echo server

```zig
const zmq = @import("zlzmq");

pub fn main() !void {
    const ctx = try zmq.Context.init();
    defer ctx.deinit();

    const rep = try ctx.socket(.rep);
    defer rep.close();

    while (true) {
        var buf: [128]u8 = undefined;
        const len = try rep.recv(&buf, .{});
        if (std.mem.eql(u8, buf[0..len], "quit")) break;
        try rep.send(buf[0..len], .{});
    }
}
```
