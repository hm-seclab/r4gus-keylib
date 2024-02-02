//! Representation of a FIDO2 authenticator

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

const Allocator = std.mem.Allocator;

const Callbacks = fido.ctap.authenticator.callbacks.Callbacks;
const Ctap2CommandMapping = fido.ctap.authenticator.callbacks.Ctap2CommandMapping;
const Data = fido.ctap.authenticator.callbacks.Data;
const DataIterator = fido.ctap.authenticator.callbacks.DataIterator;
const Error = fido.ctap.authenticator.callbacks.Error;
const Settings = fido.ctap.authenticator.Settings;
const PinUvAuth = fido.ctap.pinuv.PinUvAuth;
const SigAlg = fido.ctap.crypto.SigAlg;
const AttestationType = fido.common.AttestationType;
const PublicKeyCredentialParameters = fido.common.PublicKeyCredentialParameters;

const Response = fido.ctap.authenticator.Response;
const StatusCodes = fido.ctap.StatusCodes;
const Commands = fido.ctap.commands.Commands;

pub const Auth = struct {
    const Self = @This();

    /// Callbacks provided by the underlying platform
    callbacks: Callbacks,

    /// Offer users the option to "override" certain functions related
    /// to CTAP2 commands. This has (at least) two advantages:
    /// 1. Users can use their own functions, e.g. they only need a specific
    ///    want to experiment, want a updated version of a callback.
    /// 2. We dont need to provide the full spec but only the basics.
    ///    Users can then add what they need.
    commands: []const Ctap2CommandMapping = &.{
        .{ .cmd = 0x01, .cb = fido.ctap.commands.authenticator.authenticatorMakeCredential },
        .{ .cmd = 0x02, .cb = fido.ctap.commands.authenticator.authenticatorGetAssertion },
        .{ .cmd = 0x04, .cb = fido.ctap.commands.authenticator.authenticatorGetInfo },
        .{ .cmd = 0x06, .cb = fido.ctap.commands.authenticator.authenticatorClientPin },
        .{ .cmd = 0x0b, .cb = fido.ctap.commands.authenticator.authenticatorSelection },
    },

    /// Authenticator settings that represent the authenticators capabilities
    settings: Settings,

    /// Pin uv auth protocol
    token: PinUvAuth,

    /// A list of signature algorithms
    ///
    /// This list should match the algorithms defined within the settings.
    algorithms: []const fido.ctap.crypto.SigAlg,

    attestation: AttestationType = .Self,

    /// Determines if the authenticator should use a constant signature counter.
    ///
    /// A Relying Party stores the signature counter of the most recent authenticatorGetAssertion operation.
    /// In subsequent authenticatorGetAssertion operations, the Relying Party compares the stored signature
    /// counter value with the new signCount value returned in the assertion’s authenticator data.
    ///
    /// * `false` - The signature counter is never incremented (stays always 0). This can be used for shared
    /// resident keys (passkeys) where "clone detection" is not required.
    /// * `true` - Increment the signature counter for each successful signature creation.
    constSignCount: bool = false,

    allocator: Allocator,

    /// Cryptographic secure (P)RNG
    random: std.rand.Random,

    milliTimestamp: *const fn () i64,

    /// A DataSet can be used by any command to keep sate beyond a
    /// single request. The data must be stored in binary form, e.g.
    /// by serializing it to cbor.
    data_set: ?DataSet = null,

    pub const DataSet = struct {
        start: i64,
        tout_ms: i64 = 15_000, // 15s default
        key: []const u8,
        // Depending on how much memory you have you should be carefull!
        value: []const u8,
    };

    pub fn default(callbacks: Callbacks, allocator: Allocator) @This() {
        return .{
            .callbacks = callbacks,
            .settings = .{
                .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
                .extensions = &.{.credProtect},
                .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
                .options = .{
                    .credMgmt = false,
                    .rk = true,
                    .uv = if (callbacks.uv) |_| true else null,
                    // This is a platform authenticator even if we use usb for ipc
                    .plat = true,
                    // We don't support client pin
                    .clientPin = null,
                    .pinUvAuthToken = true,
                    .alwaysUv = false,
                },
                .pinUvAuthProtocols = &.{.V2},
                .transports = &.{.usb},
                .algorithms = &.{.{ .alg = .Es256 }},
                .firmwareVersion = 0xcafe,
                .remainingDiscoverableCredentials = 100,
            },
            .token = PinUvAuth.v2(std.crypto.random),
            .algorithms = &.{
                fido.ctap.crypto.algorithms.Es256,
            },
            .allocator = allocator,
            .milliTimestamp = std.time.milliTimestamp,
            .random = std.crypto.random,
        };
    }

    pub fn init(self: *@This()) !void {
        // Check that settings are available and if not, create them
        const meta = self.loadSettings() catch |e| blk: {
            if (e == error.NoData) {
                std.log.info("Auth.init: no settings found", .{});
            } else {
                std.log.err("Auth.init: malformed settings", .{});
            }

            std.log.info("Auth.init: generating new settings...", .{});
            var meta = fido.ctap.authenticator.Meta{};
            self.writeSettings(meta) catch {
                std.log.err("Auth.init: unable to persist settings", .{});
                return error.InitFail;
            };

            std.log.info("Auth.init: new settings persisted", .{});
            break :blk meta;
        };
        _ = meta;

        // Initialize piNUv
        self.token.initialize();
    }

    /// Try to load settings
    pub fn loadSettings(self: *@This()) !fido.ctap.authenticator.Meta {
        const id: [:0]const u8 = "Settings";
        const rp: [:0]const u8 = "Root";
        var iter = DataIterator{
            .allocator = self.allocator,
        };
        defer iter.deinit();

        if (self.callbacks.read(id, rp, &iter.d) != Error.SUCCESS) {
            return error.NoData;
        }

        if (iter.next()) |s| {
            // Turn data hex string into a byte slice
            var buffer: [256]u8 = .{0} ** 256;
            const slice = try std.fmt.hexToBytes(&buffer, s);

            return try cbor.parse(
                fido.ctap.authenticator.Meta,
                try cbor.DataItem.new(slice),
                .{},
            );
        } else {
            return error.NoData;
        }
    }

    // Load the credential with the given id
    pub fn loadCredential(self: *@This(), id: []const u8) !fido.ctap.authenticator.Credential {
        const idZ: [:0]const u8 = try self.allocator.dupeZ(u8, id);
        defer self.allocator.free(idZ);
        var iter = DataIterator{
            .allocator = self.allocator,
        };
        defer iter.deinit();

        if (self.callbacks.read(idZ, null, &iter.d) != Error.SUCCESS) {
            return error.NoData;
        }

        if (iter.next()) |s| {
            // Turn data hex string into a byte slice
            var buffer: [1024]u8 = .{0} ** 256;
            const slice = try std.fmt.hexToBytes(&buffer, s);

            return try cbor.parse(
                fido.ctap.authenticator.Credential,
                try cbor.DataItem.new(slice),
                .{ .allocator = self.allocator },
            );
        } else {
            return error.NoData;
        }
    }

    /// Load all credentials associated with the given relying party id
    pub fn loadCredentials(self: *@This(), rpId: ?[]const u8) ![]fido.ctap.authenticator.Credential {
        const rpIdZ: ?[:0]const u8 = if (rpId) |rpId_| try self.allocator.dupeZ(u8, rpId_) else null;
        if (rpIdZ != null) {
            defer self.allocator.free(rpIdZ.?);
        }
        var iter = DataIterator{
            .allocator = self.allocator,
        };
        defer iter.deinit();

        if (self.callbacks.read(null, if (rpIdZ != null) rpIdZ.? else null, &iter.d) != Error.SUCCESS) {
            return error.NoData;
        }

        var arr = std.ArrayList(fido.ctap.authenticator.Credential).init(self.allocator);
        errdefer arr.deinit();

        while (iter.next()) |s| {
            //std.log.err("{s}", .{s});
            // Turn data hex string into a byte slice
            var buffer: [1024]u8 = .{0} ** 256;
            const slice = std.fmt.hexToBytes(&buffer, s) catch continue;

            try arr.append(cbor.parse(
                fido.ctap.authenticator.Credential,
                cbor.DataItem.new(slice) catch continue,
                .{ .allocator = self.allocator },
            ) catch continue);
        }

        if (arr.items.len == 0) {
            return error.NoData;
        } else {
            return try arr.toOwnedSlice();
        }
    }

    /// Write settings back into permanent storage
    pub fn writeSettings(self: *@This(), meta: fido.ctap.authenticator.Meta) !void {
        try self.writeCredential("Settings", "Root", meta);
    }

    pub fn writeCredential(self: *@This(), id: []const u8, rpId: []const u8, entry: anytype) !void {
        const _id = try self.allocator.dupeZ(u8, id);
        defer self.allocator.free(_id);
        const _rpId = try self.allocator.dupeZ(u8, rpId);
        defer self.allocator.free(_rpId);

        var str = std.ArrayList(u8).init(self.allocator);
        defer str.deinit();

        try cbor.stringify(entry, .{}, str.writer());

        // Covert the data into a hex string
        var str2 = std.ArrayList(u8).init(self.allocator);
        defer str2.deinit();
        try str2.writer().print("{s}\x00", .{std.fmt.fmtSliceHexLower(str.items)});

        if (self.callbacks.write(_id, _rpId, str2.items.ptr) != Error.SUCCESS) {
            return error.Write;
        }
    }

    pub fn handle(
        self: *@This(),
        out: *[fido.ctap.transports.ctaphid.authenticator.MAX_DATA_SIZE]u8,
        request: []const u8,
    ) []const u8 {
        // Buffer for the response message
        var res = std.ArrayList(u8).init(self.allocator);
        defer res.deinit();
        var response = res.writer();
        response.writeByte(0x00) catch {
            std.log.err("Auth.handle: unable to initialize response", .{});
            out[0] = @intFromEnum(StatusCodes.ctap1_err_other);
            return out[0..1];
        };

        // Decode the command of the given message
        if (request.len < 1) {
            out[0] = @intFromEnum(StatusCodes.ctap1_err_invalid_length);
            return out[0..1];
        }
        const cmd = request[0];

        // Updates (and possibly invalidates) an existing pinUvAuth token. This has to
        // be done before handling any request.
        self.token.pinUvAuthTokenUsageTimerObserver(self.milliTimestamp());

        // Check if data_set is invalid
        if (self.data_set != null) {
            if (self.milliTimestamp() - self.data_set.?.start > self.data_set.?.tout_ms) {
                self.allocator.free(self.data_set.?.key);
                self.allocator.free(self.data_set.?.value);
                self.data_set = null;
            }
        }

        if (request.len > 1) {
            std.log.info("request({d}): {s}", .{ cmd, std.fmt.fmtSliceHexLower(request[1..]) });
        }

        for (self.commands) |command| {
            if (command.cmd == cmd) {
                const status = command.cb(
                    self,
                    request[1..],
                    &res,
                );

                out[0] = @intFromEnum(status);
                if (status != .ctap1_err_success) {
                    return out[0..1];
                }

                break;
            }
        } else {
            std.log.err("invalid command: {d}", .{cmd});
            out[0] = @intFromEnum(StatusCodes.ctap2_err_not_allowed);
            return out[0..1];
        }

        std.mem.copy(u8, out[0..res.items.len], res.items);
        return out[0..res.items.len];
    }

    /// Given a set of credential parameters, select the first algorithm that is also supported by the authenticator.
    pub fn selectSignatureAlgorithm(self: *@This(), params: []const PublicKeyCredentialParameters) ?SigAlg {
        for (params) |param| {
            for (self.algorithms) |alg| {
                if (param.alg == alg.alg) {
                    return alg;
                }
            }
        }
        return null;
    }

    /// Returns true if the authenticator supports (built in) user verification
    pub fn uvSupported(self: *@This()) bool {
        return self.settings.options.uv != null and
            self.settings.options.uv.? and
            self.callbacks.uv != null;
    }

    pub fn clientPinSupported(self: *@This()) ?bool {
        _ = self;
        // We dont support clientPin (for now). The rational for this is
        // that the focus of this library shifted towards platform authenticators
        // which can implement builtin user verification (even passwords if
        // they like).
        return null;
    }

    /// Returns true if the authenticator is protected by some form of user verification
    pub fn isProtected(self: *@This()) bool {
        return self.uvSupported() or if (self.clientPinSupported()) |cp| cp else false;
    }

    /// Returns true if the authenticator supports resident keys/ discoverable credentials/ passkey
    pub fn rkSupported(self: *@This()) bool {
        return self.settings.options.rk;
    }

    /// Returns true if always uv is enables, false otherwise
    pub fn alwaysUv(self: *@This()) !bool {
        const settings = self.loadSettings() catch |e| {
            std.log.err("Auth.alwaysUv: unable to load settings ({any})", .{e});
            return e;
        };

        return settings.always_uv;
    }

    /// Returns true if the authenticator doesn't require some form of user verification
    pub fn makeCredUvNotRqd(self: *@This()) bool {
        return self.settings.options.makeCredUvNotRqd;
    }

    pub fn noMcGaPermissionsWithClientPin(self: *@This()) bool {
        return self.settings.options.noMcGaPermissionsWithClientPin;
    }
};
