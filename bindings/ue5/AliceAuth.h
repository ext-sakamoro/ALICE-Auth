// ALICE-Auth UE5 C++ Bindings
// Ed25519 ZKP authentication via C-ABI FFI
//
// Author: Moroya Sakamoto
// License: AGPL-3.0
//
// Usage:
//   1. Build alice-auth as cdylib: cargo build --release --features "ffi,nizk"
//   2. Copy libalice_auth.dylib/.so/.dll to ThirdParty/AliceAuth/
//   3. Add this header to your module's Public/ directory.
//   4. Link the library in your Build.cs.

#pragma once

#include <cstdint>
#include <cstring>
#include <utility>

// ============================================================================
// C-ABI declarations
// ============================================================================

extern "C"
{
    // --- Core Identity ---
    void* aa_new();
    void  aa_id(const void* h, uint8_t* o);
    void  aa_sign(const void* h, const uint8_t* c, uint8_t* o);
    int32_t aa_verify(const uint8_t* pk, const uint8_t* m, size_t ml, const uint8_t* s);
    void  aa_free(void* h);

    // --- Endorsement ---
    void  aa_endorse(const void* h, const uint8_t* target, uint64_t now_ms, uint64_t ttl_ms, uint8_t* o);
    int32_t aa_verify_endorsement(const uint8_t* data, uint64_t now_ms);

    // --- RotatingIdentity ---
    void* aa_rotating_new();
    int32_t aa_rotating_rotate(void* h, uint64_t now_ms, uint8_t* o);
    void  aa_rotating_id(const void* h, uint8_t* o);
    int32_t aa_rotating_verify(const void* h, const uint8_t* pk, const uint8_t* m, size_t ml, const uint8_t* s);
    uint32_t aa_rotating_generation_count(const void* h);
    void  aa_rotating_free(void* h);

    // --- AuthToken ---
    void  aa_token_create(uint64_t now_ms, uint64_t ttl_ms, uint8_t* o);
    int32_t aa_token_is_expired(const uint8_t* data, uint64_t now_ms);

    // --- RevocationList ---
    void* aa_revlist_new();
    void  aa_revlist_revoke(void* h, const uint8_t* token, uint64_t now_ms);
    int32_t aa_revlist_is_revoked(const void* h, const uint8_t* token);
    uint32_t aa_revlist_auto_purge(void* h, uint64_t now_ms, uint64_t ttl_ms);
    void  aa_revlist_free(void* h);

    // --- PolicyEngine (RBAC) ---
    void* aa_policy_new();
    void  aa_policy_assign(void* h, const uint8_t* id, uint8_t mask);
    int32_t aa_policy_check(const void* h, const uint8_t* id, uint8_t perm);
    void  aa_policy_free(void* h);

    // --- NIZK (requires ffi+nizk features) ---
    int32_t aa_nizk_prove(const void* h, const uint8_t* m, size_t ml, uint8_t* o);
    int32_t aa_nizk_verify(const uint8_t* pk, const uint8_t* m, size_t ml, const uint8_t* proof);

    // --- Crypto (requires ffi+crypto features) ---
    void* aa_derive_child(const void* h, uint32_t index);
    void  aa_derive_session_key(const uint8_t* id_a, const uint8_t* id_b,
                                const uint8_t* secret, size_t secret_len, uint8_t* o);
}

namespace AliceAuth
{

// ============================================================================
// FAliceIdentity (RAII, move-only)
// ============================================================================

/// Ed25519 identity. Secret key stays in Rust memory.
class FAliceIdentity
{
    void* Handle = nullptr;

public:
    /// Generate a new random Ed25519 identity.
    FAliceIdentity()
        : Handle(aa_new())
    {
    }

    /// Wrap an existing handle (takes ownership).
    explicit FAliceIdentity(void* InHandle)
        : Handle(InHandle)
    {
    }

    ~FAliceIdentity()
    {
        if (Handle) { aa_free(Handle); Handle = nullptr; }
    }

    // Move-only
    FAliceIdentity(const FAliceIdentity&) = delete;
    FAliceIdentity& operator=(const FAliceIdentity&) = delete;

    FAliceIdentity(FAliceIdentity&& Other) noexcept
        : Handle(Other.Handle) { Other.Handle = nullptr; }

    FAliceIdentity& operator=(FAliceIdentity&& Other) noexcept
    {
        if (this != &Other)
        {
            if (Handle) aa_free(Handle);
            Handle = Other.Handle;
            Other.Handle = nullptr;
        }
        return *this;
    }

    bool IsValid() const { return Handle != nullptr; }
    const void* GetHandle() const { return Handle; }

    /// Get the 32-byte public identity.
    void GetId(uint8_t OutId[32]) const
    {
        if (Handle) aa_id(Handle, OutId);
    }

    /// Sign a 32-byte challenge. Writes 64-byte signature to OutSig.
    void Sign(const uint8_t Challenge[32], uint8_t OutSig[64]) const
    {
        if (Handle) aa_sign(Handle, Challenge, OutSig);
    }

    /// Verify an Ed25519 signature over a message.
    static bool Verify(const uint8_t PublicKey[32], const uint8_t* Message, size_t MessageLen,
                       const uint8_t Signature[64])
    {
        return aa_verify(PublicKey, Message, MessageLen, Signature) != 0;
    }
};

// ============================================================================
// FAliceEndorsement
// ============================================================================

/// Trust chain endorsement with expiry.
struct FAliceEndorsement
{
    /// Endorse a target identity. Writes 176 bytes to OutData.
    static void Endorse(const FAliceIdentity& Signer, const uint8_t TargetId[32],
                        uint64_t NowMs, uint64_t TtlMs, uint8_t OutData[176])
    {
        aa_endorse(Signer.GetHandle(), TargetId, NowMs, TtlMs, OutData);
    }

    /// Verify an endorsement (176 bytes). Returns true if valid and not expired.
    static bool Verify(const uint8_t* Data, uint64_t NowMs)
    {
        return aa_verify_endorsement(Data, NowMs) != 0;
    }
};

// ============================================================================
// FAliceRotatingIdentity (RAII, move-only)
// ============================================================================

/// Identity with N-generation key rotation.
class FAliceRotatingIdentity
{
    void* Handle = nullptr;

public:
    FAliceRotatingIdentity()
        : Handle(aa_rotating_new())
    {
    }

    ~FAliceRotatingIdentity()
    {
        if (Handle) { aa_rotating_free(Handle); Handle = nullptr; }
    }

    FAliceRotatingIdentity(const FAliceRotatingIdentity&) = delete;
    FAliceRotatingIdentity& operator=(const FAliceRotatingIdentity&) = delete;

    FAliceRotatingIdentity(FAliceRotatingIdentity&& Other) noexcept
        : Handle(Other.Handle) { Other.Handle = nullptr; }

    FAliceRotatingIdentity& operator=(FAliceRotatingIdentity&& Other) noexcept
    {
        if (this != &Other)
        {
            if (Handle) aa_rotating_free(Handle);
            Handle = Other.Handle;
            Other.Handle = nullptr;
        }
        return *this;
    }

    bool IsValid() const { return Handle != nullptr; }

    /// Rotate to a new keypair. Writes the new 32-byte public ID to OutId.
    bool Rotate(uint64_t NowMs, uint8_t OutId[32])
    {
        return Handle && aa_rotating_rotate(Handle, NowMs, OutId) != 0;
    }

    /// Get the current 32-byte public ID.
    void CurrentId(uint8_t OutId[32]) const
    {
        if (Handle) aa_rotating_id(Handle, OutId);
    }

    /// Verify a signature against any key (current + all previous).
    bool VerifyAny(const uint8_t PublicKey[32], const uint8_t* Message, size_t MessageLen,
                   const uint8_t Signature[64]) const
    {
        if (!Handle) return false;
        return aa_rotating_verify(Handle, PublicKey, Message, MessageLen, Signature) != 0;
    }

    /// Number of retained previous generations.
    uint32_t GenerationCount() const
    {
        return Handle ? aa_rotating_generation_count(Handle) : 0;
    }
};

// ============================================================================
// FAliceAuthToken
// ============================================================================

/// Structured authentication token (17 bytes).
struct FAliceAuthToken
{
    /// Create a token. Writes 17 bytes to OutToken.
    static void Create(uint64_t NowMs, uint64_t TtlMs, uint8_t OutToken[17])
    {
        aa_token_create(NowMs, TtlMs, OutToken);
    }

    /// Check if a token is expired.
    static bool IsExpired(const uint8_t TokenData[17], uint64_t NowMs)
    {
        return aa_token_is_expired(TokenData, NowMs) != 0;
    }
};

// ============================================================================
// FAliceRevocationList (RAII, move-only)
// ============================================================================

/// Session token revocation list with constant-time checks.
class FAliceRevocationList
{
    void* Handle = nullptr;

public:
    FAliceRevocationList()
        : Handle(aa_revlist_new())
    {
    }

    ~FAliceRevocationList()
    {
        if (Handle) { aa_revlist_free(Handle); Handle = nullptr; }
    }

    FAliceRevocationList(const FAliceRevocationList&) = delete;
    FAliceRevocationList& operator=(const FAliceRevocationList&) = delete;

    FAliceRevocationList(FAliceRevocationList&& Other) noexcept
        : Handle(Other.Handle) { Other.Handle = nullptr; }

    FAliceRevocationList& operator=(FAliceRevocationList&& Other) noexcept
    {
        if (this != &Other)
        {
            if (Handle) aa_revlist_free(Handle);
            Handle = Other.Handle;
            Other.Handle = nullptr;
        }
        return *this;
    }

    bool IsValid() const { return Handle != nullptr; }

    /// Revoke a 16-byte session token.
    void Revoke(const uint8_t Token[16], uint64_t NowMs)
    {
        if (Handle) aa_revlist_revoke(Handle, Token, NowMs);
    }

    /// Check if a token is revoked (constant-time).
    bool IsRevoked(const uint8_t Token[16]) const
    {
        return Handle && aa_revlist_is_revoked(Handle, Token) != 0;
    }

    /// Purge tokens revoked more than TtlMs ago. Returns count purged.
    uint32_t AutoPurge(uint64_t NowMs, uint64_t TtlMs)
    {
        return Handle ? aa_revlist_auto_purge(Handle, NowMs, TtlMs) : 0;
    }
};

// ============================================================================
// FAlicePolicyEngine (RAII, move-only, RBAC)
// ============================================================================

/// Role-based access control engine.
class FAlicePolicyEngine
{
    void* Handle = nullptr;

public:
    /// Permission flags (bit index).
    enum EPermission : uint8_t
    {
        Read    = 0,
        Write   = 1,
        Admin   = 2,
        Execute = 3,
    };

    FAlicePolicyEngine()
        : Handle(aa_policy_new())
    {
    }

    ~FAlicePolicyEngine()
    {
        if (Handle) { aa_policy_free(Handle); Handle = nullptr; }
    }

    FAlicePolicyEngine(const FAlicePolicyEngine&) = delete;
    FAlicePolicyEngine& operator=(const FAlicePolicyEngine&) = delete;

    FAlicePolicyEngine(FAlicePolicyEngine&& Other) noexcept
        : Handle(Other.Handle) { Other.Handle = nullptr; }

    FAlicePolicyEngine& operator=(FAlicePolicyEngine&& Other) noexcept
    {
        if (this != &Other)
        {
            if (Handle) aa_policy_free(Handle);
            Handle = Other.Handle;
            Other.Handle = nullptr;
        }
        return *this;
    }

    bool IsValid() const { return Handle != nullptr; }

    /// Assign a role mask to an identity.
    void Assign(const uint8_t Id[32], uint8_t Mask)
    {
        if (Handle) aa_policy_assign(Handle, Id, Mask);
    }

    /// Check if an identity has a permission.
    bool Check(const uint8_t Id[32], EPermission Perm) const
    {
        return Handle && aa_policy_check(Handle, Id, static_cast<uint8_t>(Perm)) != 0;
    }
};

// ============================================================================
// FAliceNizk (Schnorr NIZK — requires ffi+nizk features)
// ============================================================================

/// Schnorr NIZK zero-knowledge proof.
struct FAliceNizk
{
    /// Generate a NIZK proof. Writes 64 bytes (R || s) to OutProof.
    /// Returns true on success.
    static bool Prove(const FAliceIdentity& Identity, const uint8_t* Message, size_t MessageLen,
                      uint8_t OutProof[64])
    {
        return aa_nizk_prove(Identity.GetHandle(), Message, MessageLen, OutProof) != 0;
    }

    /// Verify a NIZK proof. Returns true if valid.
    static bool Verify(const uint8_t PublicKey[32], const uint8_t* Message, size_t MessageLen,
                       const uint8_t Proof[64])
    {
        return aa_nizk_verify(PublicKey, Message, MessageLen, Proof) != 0;
    }
};

// ============================================================================
// FAliceCrypto (HD derivation — requires ffi+crypto features)
// ============================================================================

/// Cryptographic utilities: HD key derivation, session keys.
struct FAliceCrypto
{
    /// Derive a child identity from parent + index.
    static FAliceIdentity DeriveChild(const FAliceIdentity& Parent, uint32_t Index)
    {
        return FAliceIdentity(aa_derive_child(Parent.GetHandle(), Index));
    }

    /// Derive a 32-byte session key from two IDs and a shared secret.
    static void DeriveSessionKey(const uint8_t IdA[32], const uint8_t IdB[32],
                                 const uint8_t* Secret, size_t SecretLen,
                                 uint8_t OutKey[32])
    {
        aa_derive_session_key(IdA, IdB, Secret, SecretLen, OutKey);
    }
};

} // namespace AliceAuth
