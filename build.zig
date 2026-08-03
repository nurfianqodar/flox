const std = @import("std");
const Header = @import("src/flox/Header.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ================================================
    // library
    // ================================================
    const lib_mod = b.addModule("flox", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/flox.zig"),
    });

    const lib = b.addLibrary(.{
        .name = "flox",
        .root_module = lib_mod,
        .version = .{
            .major = Header.default.version[0],
            .minor = Header.default.version[1],
            .patch = Header.default.version[1],
        },
    });

    b.installArtifact(lib);

    // ================================================
    // exe
    // ================================================

    const exe_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/main.zig"),
    });

    const exe = b.addExecutable(.{
        .name = "flox",
        .root_module = exe_mod,
        .version = .{
            .major = Header.default.version[0],
            .minor = Header.default.version[1],
            .patch = Header.default.version[1],
        },
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "run flox executable");
    const run_exe = b.addRunArtifact(exe);
    run_step.dependOn(&run_exe.step);
    run_step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_exe.addArgs(args);
    }

    // ================================================
    // tests
    // ================================================

    const lib_test = b.addTest(.{
        .name = "lib-test",
        .root_module = lib.root_module,
    });

    const test_step = b.step("test", "run unit test");
    const run_test = b.addRunArtifact(lib_test);
    test_step.dependOn(&run_test.step);
    test_step.dependOn(b.getInstallStep());
}
