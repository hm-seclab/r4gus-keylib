const std = @import("std");
const fido = @import("../../main.zig");
const cbor = @import("zbor");

/// Credential ID
id: []const u8,

/// User information
user: fido.common.User,

/// Information about the relying party
rp: fido.common.RelyingParty,

/// Number of signatures issued using the given credential
sign_count: u64,

/// Signature algorithm to use for the credential
alg: cbor.cose.Algorithm,

/// Private key
private_key: []const u8 = undefined,

policy: fido.ctap.extensions.CredentialCreationPolicy = .userVerificationOptional,

/// Belongs to hmac secret
cred_random_with_uv: [32]u8 = undefined,

/// Belongs to hmac secret
cred_random_without_uv: [32]u8 = undefined,

/// Epoch time stamp this credential was created
created: i64,

/// Is this credential discoverable or not
///
/// This is kind of stupid but authenticatorMakeCredential
/// docs state, that you're not allowed to create a discoverable
/// credential if not explicitely requested. The docs also state
/// that you're allowed to keep (some) state, e.g., store the key.
discoverable: bool = false,

/// The optional field is part of the extension proposed by A-WAYF and
/// stores the identifier of a federation entity.
fedEntity: ?[]const u8 = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.id);
    self.user.deinit(allocator);
    self.rp.deinit(allocator);
    allocator.free(self.private_key);
}

pub fn desc(_: void, lhs: @This(), rhs: @This()) bool {
    return lhs.created > rhs.created;
}
