const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

/// The sub command currently being requested
subCommand: SubCommand,
/// Map of sub command parameters
subCommandParams: ?SubCommandParams = null,
/// PIN/UV protocol version chosen by the platform
pinUvAuthProtocol: ?fido.ctap.pinuv.common.PinProtocol = null,
/// First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken
pinUvAuthParam: ?[]const u8 = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self.subCommandParams) |subCommandParams| {
        subCommandParams.deinit(allocator);
    }

    if (self.pinUvAuthParam) |puap| {
        allocator.free(puap);
    }
}

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
    _ = options;

    try cbor.stringify(self, .{
        .field_settings = &.{
            .{ .name = "subCommand", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "subCommandParams", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "3", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
        },
        .from_callback = true,
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_callback = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "subCommand", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "subCommandParams", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "3", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
        },
    });
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

/// List of sub commands for credential management
pub const SubCommand = enum(u8) {
    /// get credentials metadata information
    getCredsMetadata = 0x01,
    enumerateRPsBegin = 0x02,
    enumerateRPsGetNextRP = 0x03,
    enumerateCredentialsBegin = 0x04,
    enumerateCredentialsGetNextCredential = 0x05,
    deleteCredential = 0x06,
    updateUserInformation = 0x07,
};

pub const SubCommandParams = struct {
    /// RP ID SHA-256 hash
    rpIDHash: ?[32]u8 = null,
    /// Credential identifier
    credentialID: ?fido.common.PublicKeyCredentialDescriptor = null,
    /// User Entity
    user: ?fido.common.User = null,

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        if (self.credentialID) |credId| {
            credId.deinit(allocator);
        }

        if (self.user) |user| {
            user.deinit(allocator);
        }
    }

    pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
        _ = options;

        try cbor.stringify(self, .{
            .field_settings = &.{
                .{ .name = "rpIDHash", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "credentialID", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "user", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            },
            .from_callback = true,
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .allocator = options.allocator,
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "rpIDHash", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "credentialID", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "user", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            },
        });
    }
};
