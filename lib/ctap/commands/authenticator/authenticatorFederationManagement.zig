const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

pub fn authenticatorFederationManagement(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.ArrayList(u8),
) fido.ctap.StatusCodes {
    _ = out;

    const State = struct {
        var credentials: ?std.ArrayList(fido.ctap.authenticator.Credential) = null;
    };

    var di = cbor.DataItem.new(request) catch {
        return .ctap2_err_invalid_cbor;
    };
    const fmp = cbor.parse(fido.ctap.request.FederationManagement, di, .{
        .allocator = auth.allocator,
    }) catch {
        std.log.err("unable to map request to `FederationManagement` data type", .{});
        return .ctap2_err_invalid_cbor;
    };
    defer fmp.deinit(auth.allocator);

    switch (fmp.subCommand) {
        .enumerateIdPBegin => {
            // TODO: optionally validate pinUvAuthParam

            //State.credentials = std.ArrayList(fido.ctap.authenticator.Credential).fromOwnedSlice(
            //    auth.allocator,
            //    auth.loadCredentials(gap.rpId) catch {
            //        std.log.err("getAssertion: unable to fetch credentials", .{});
            //        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
            //    },
            //);
        },
        .enumerateIdPsGetNextIdP => {
            if (State.credentials == null) {
                // If credentials is null we know that this call is invalid.
                return .ctap2_err_no_idps;
            }
        },
    }

    // Locate all credentials that are eligible for retrieval.
    //var credentials = std.ArrayList(fido.ctap.authenticator.Credential).fromOwnedSlice(

    return fido.ctap.StatusCodes.ctap1_err_success;
}
