const std = @import("std");

const encryptor = @import("flox/encryptor.zig");
const decryptor = @import("flox/decryptor.zig");

pub const Cipher = @import("flox/Cipher.zig");

pub const encryptStream = encryptor.stream;
pub const decryptStream = decryptor.stream;

pub const version = @import("flox/Header.zig").default.version;
pub const version_string = @import("flox/Header.zig").version_string;

pub const utils = @import("flox/utils.zig");
