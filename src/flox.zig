const std = @import("std");

const encryptor = @import("flox/encryptor.zig");
const decryptor = @import("flox/decryptor.zig");

pub const Cipher = @import("flox/Cipher.zig");

pub const encryptStream = encryptor.stream;
pub const decryptStream = decryptor.stream;

pub const utils = @import("flox/utils.zig");
