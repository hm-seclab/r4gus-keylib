//! Attestation statement is a specific type of signed data object, containing statements
//! about a public key credential itself and the authenticator that created it. It
//! contains an attestation signature created using the key of the attesting authority
//! (except for the case of self attestation, when it is created using the credential
//! private key)

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../main.zig");

pub const AttestationStatement = union(fido.common.AttestationStatementFormatIdentifiers) {
    /// This is a WebAuthn optimized attestation statement format. It uses a very compact
    /// but still extensible encoding method. It is implementable by authenticators with
    /// limited resources (e.g., secure elements).
    @"packed": struct { // basic, self, AttCA
        /// A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        /// to generate the attestation signature.
        alg: cbor.cose.Algorithm,
        /// A byte string containing the attestation signature.
        sig: []const u8,
        // The elements of this array contain attestnCert and its certificate chain (if any),
        // each encoded in X.509 format. The attestation certificate attestnCert MUST be
        // the first element in the array.
        //TODO: x5c: ?[]const Cert = null,
    },
    tpm: struct {}, // TODO: implement
    @"android-key": struct {}, // TODO: implement
    @"android-safetynet": struct {}, // TODO: implement
    @"fido-u2f": struct {}, // TODO: implement
    apple: struct {}, // TODO: implement
    /// The none attestation statement format is used to replace any authenticator-provided
    /// attestation statement when a WebAuthn Relying Party indicates it does not wish to
    /// receive attestation information, see § 5.4.7 Attestation Conveyance Preference
    /// Enumeration (enum AttestationConveyancePreference).
    none: struct {}, // no attestation

    pub fn deinit(self: *const @This(), a: std.mem.Allocator) void {
        switch (self.*) {
            .@"packed" => |x| {
                a.free(x.sig);
            },
            else => {},
        }
    }
};
