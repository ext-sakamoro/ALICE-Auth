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
    int32_t aa_sign(const void* h, const uint8_t* c, uint8_t* o);
    int32_t aa_verify(const uint8_t* pk, const uint8_t* m, size_t ml, const uint8_t* s);
    void  aa_free(void* h);

    // --- Endorsement ---
    // 0 = written, -1 = null argument, -2 = now_ms + ttl_ms exceeds u64::MAX (o untouched)
    int32_t aa_endorse(const void* h, const uint8_t* target, uint64_t now_ms, uint64_t ttl_ms, uint8_t* o);
    int32_t aa_verify_endorsement(const uint8_t* data, uint64_t now_ms);

    // --- RotatingIdentity ---
    void* aa_rotating_new();
    int32_t aa_rotating_rotate(void* h, uint64_t now_ms, uint8_t* o);
    void  aa_rotating_id(const void* h, uint8_t* o);
    int32_t aa_rotating_verify(const void* h, const uint8_t* pk, const uint8_t* m, size_t ml, const uint8_t* s);
    uint32_t aa_rotating_generation_count(const void* h);
    void  aa_rotating_free(void* h);

    // --- AuthToken ---
    // 0 = written, -1 = null output, -2 = now_ms + ttl_ms exceeds u64::MAX (o untouched)
    int32_t aa_token_create(uint64_t now_ms, uint64_t ttl_ms, uint8_t* o);
    int32_t aa_token_is_expired(const uint8_t* data, uint64_t now_ms);

    // --- RevocationList ---
    void* aa_revlist_new();
    void* aa_revlist_new_with_capacity(uint32_t capacity);
    // 0 = revoked, -1 = null argument, -2 = list full (token NOT revoked)
    int32_t aa_revlist_revoke(void* h, const uint8_t* token, uint64_t now_ms);
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

    // --- Player (id, key chain, grants, revocations) ---
    // Every int32_t is 0 on success or a negative GrantError code (-1 null, -2 length,
    // -3 version, -4 signature, -5 wrong game, -6 not yet valid, -7 expired, -8 revoked,
    // -9 empty window, -10 wrong key, -11 overflow, -12 full, -13 chain); outputs are
    // written only on success and aa_last_error describes a refusal.
    void* aa_from_seed(const uint8_t* seed);
    int32_t aa_player_id_from_genesis(const uint8_t* genesis, uint8_t* out);
    int32_t aa_rotation_link_issue(const void* old_key, const uint8_t* player, uint32_t seq,
                                   const uint8_t* new_key, uint64_t issued_ms, uint8_t* out);
    int32_t aa_player_chain_resolve(const uint8_t* genesis, const uint8_t* links, size_t n_links,
                                    uint8_t* out_player, uint8_t* out_key, uint64_t* out_since_ms);
    int32_t aa_grant_issue(const void* game, const uint8_t* player, const uint8_t* player_key,
                           uint64_t scope, uint64_t now_ms, uint64_t ttl_ms,
                           const uint8_t* nonce, uint8_t* out);
    int32_t aa_grant_verify(const uint8_t* grant, size_t grant_len, const uint8_t* expected_game,
                            const uint8_t* head_player, const uint8_t* head_key,
                            uint64_t head_since_ms, uint64_t now_ms, const void* revoked,
                            uint8_t* out_player, uint64_t* out_scope, uint64_t* out_expires_ms);
    int32_t aa_revocation_issue(const void* game, const uint8_t* grant, size_t grant_len,
                                uint64_t revoked_ms, uint8_t* out);
    void* aa_revset_new(size_t capacity);
    int32_t aa_revset_add(void* set, const uint8_t* rev, size_t rev_len);
    int32_t aa_revset_contains(const void* set, const uint8_t* game, const uint8_t* nonce);
    int64_t aa_revset_purge(void* set, uint64_t now_ms);
    int64_t aa_revset_len(const void* set);
    void  aa_revset_free(void* set);
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

    /// Sign a 32-byte challenge. Writes the 64-byte signature to OutSig and returns
    /// true; returns false (OutSig untouched) without a handle or when the challenge
    /// starts with the reserved prefix "alice-auth/".
    [[nodiscard]] bool Sign(const uint8_t Challenge[32], uint8_t OutSig[64]) const
    {
        return Handle && aa_sign(Handle, Challenge, OutSig) == 0;
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
    /// Endorse a target identity. Writes 176 bytes to OutData and returns true;
    /// returns false (OutData untouched) when NowMs + TtlMs exceeds u64::MAX or the
    /// target starts with the reserved prefix "alice-auth/".
    [[nodiscard]] static bool Endorse(const FAliceIdentity& Signer, const uint8_t TargetId[32],
                                      uint64_t NowMs, uint64_t TtlMs, uint8_t OutData[176])
    {
        return aa_endorse(Signer.GetHandle(), TargetId, NowMs, TtlMs, OutData) == 0;
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

    /// True when PublicKey is the current key or a retained previous key and
    /// Signature is that key's valid signature of Message.
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
    /// Create a token. Writes 17 bytes to OutToken and returns true; returns false
    /// (OutToken untouched) when NowMs + TtlMs exceeds u64::MAX.
    [[nodiscard]] static bool Create(uint64_t NowMs, uint64_t TtlMs, uint8_t OutToken[17])
    {
        return aa_token_create(NowMs, TtlMs, OutToken) == 0;
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

    /// A list holding at most Capacity entries (at least 1).
    explicit FAliceRevocationList(uint32_t Capacity)
        : Handle(aa_revlist_new_with_capacity(Capacity))
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

    /// Revoke a 16-byte session token. Returns false when the token was NOT
    /// revoked (the list is full, or the handle is invalid); the token is then
    /// still accepted, and aa_last_error describes why.
    [[nodiscard]] bool Revoke(const uint8_t Token[16], uint64_t NowMs)
    {
        return Handle && aa_revlist_revoke(Handle, Token, NowMs) == 0;
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

// ============================================================================
// Player: id, key chain, grants, revocations
// ============================================================================

constexpr size_t AA_ROTATION_LINK_LEN = 173;
constexpr size_t AA_GRANT_LEN = 201;
constexpr size_t AA_REVOCATION_LEN = 129;

/// An identity restored from its 32-byte seed. The seed is the secret key: take it from a
/// secure random source (or from where it was stored) and keep it like a key. The
/// returned identity is invalid (IsValid() == false) when Seed is null.
inline FAliceIdentity IdentityFromSeed(const uint8_t Seed[32])
{
    return FAliceIdentity(aa_from_seed(Seed));
}

/// The revocations a verifier knows, with a fixed capacity (RAII, move-only).
class FAliceRevocationSet
{
    void* Handle = nullptr;

public:
    /// A set holding at most Capacity revocations (invalid when Capacity is 0).
    explicit FAliceRevocationSet(size_t Capacity)
        : Handle(aa_revset_new(Capacity))
    {
    }

    ~FAliceRevocationSet()
    {
        if (Handle) { aa_revset_free(Handle); Handle = nullptr; }
    }

    FAliceRevocationSet(const FAliceRevocationSet&) = delete;
    FAliceRevocationSet& operator=(const FAliceRevocationSet&) = delete;

    FAliceRevocationSet(FAliceRevocationSet&& Other) noexcept
        : Handle(Other.Handle) { Other.Handle = nullptr; }

    FAliceRevocationSet& operator=(FAliceRevocationSet&& Other) noexcept
    {
        if (this != &Other)
        {
            if (Handle) aa_revset_free(Handle);
            Handle = Other.Handle;
            Other.Handle = nullptr;
        }
        return *this;
    }

    bool IsValid() const { return Handle != nullptr; }
    const void* GetHandle() const { return Handle; }

    /// Add a revocation (AA_REVOCATION_LEN bytes). 0 when it is held. -12 (full) means it
    /// was NOT stored and the grant is still accepted: treat it as an emergency (a larger
    /// set, or stop accepting that game's grants), not as a retry.
    [[nodiscard]] int32_t Add(const uint8_t* Revocation, size_t Len)
    {
        return aa_revset_add(Handle, Revocation, Len);
    }

    /// True when the grant Nonce of Game is revoked (an invalid set reads as revoked).
    bool Contains(const uint8_t Game[32], const uint8_t Nonce[16]) const
    {
        return aa_revset_contains(Handle, Game, Nonce) != 0;
    }

    /// Drop the revocations of grants expired at NowMs; the number dropped (-1 if invalid).
    int64_t Purge(uint64_t NowMs) { return aa_revset_purge(Handle, NowMs); }

    /// The number of revocations held (-1 if invalid).
    int64_t Num() const { return aa_revset_len(Handle); }
};

/// A game's grants to players (thin wrappers; each returns 0 or a GrantError code).
struct FAlicePlayer
{
    static int32_t IdFromGenesis(const uint8_t Genesis[32], uint8_t OutPlayer[32])
    {
        return aa_player_id_from_genesis(Genesis, OutPlayer);
    }

    static int32_t IssueRotationLink(const FAliceIdentity& OldKey, const uint8_t Player[32],
                                     uint32_t Seq, const uint8_t NewKey[32], uint64_t IssuedMs,
                                     uint8_t OutLink[AA_ROTATION_LINK_LEN])
    {
        return aa_rotation_link_issue(OldKey.GetHandle(), Player, Seq, NewKey, IssuedMs, OutLink);
    }

    /// Links: NumLinks links of AA_ROTATION_LINK_LEN bytes each, back to back.
    static int32_t ResolveChain(const uint8_t Genesis[32], const uint8_t* Links, size_t NumLinks,
                                uint8_t OutPlayer[32], uint8_t OutKey[32], uint64_t& OutSinceMs)
    {
        return aa_player_chain_resolve(Genesis, Links, NumLinks, OutPlayer, OutKey, &OutSinceMs);
    }

    static int32_t IssueGrant(const FAliceIdentity& Game, const uint8_t Player[32],
                              const uint8_t PlayerKey[32], uint64_t Scope, uint64_t NowMs,
                              uint64_t TtlMs, const uint8_t Nonce[16],
                              uint8_t OutGrant[AA_GRANT_LEN])
    {
        return aa_grant_issue(Game.GetHandle(), Player, PlayerKey, Scope, NowMs, TtlMs, Nonce,
                              OutGrant);
    }

    /// 0 when the grant is valid for ExpectedGame at NowMs (the window excludes its expiry).
    static int32_t VerifyGrant(const uint8_t* Grant, size_t GrantLen,
                               const uint8_t ExpectedGame[32], const uint8_t HeadPlayer[32],
                               const uint8_t HeadKey[32], uint64_t HeadSinceMs, uint64_t NowMs,
                               const FAliceRevocationSet& Revoked, uint8_t OutPlayer[32],
                               uint64_t& OutScope, uint64_t& OutExpiresMs)
    {
        return aa_grant_verify(Grant, GrantLen, ExpectedGame, HeadPlayer, HeadKey, HeadSinceMs,
                               NowMs, Revoked.GetHandle(), OutPlayer, &OutScope, &OutExpiresMs);
    }

    static int32_t IssueRevocation(const FAliceIdentity& Game, const uint8_t* Grant,
                                   size_t GrantLen, uint64_t RevokedMs,
                                   uint8_t OutRevocation[AA_REVOCATION_LEN])
    {
        return aa_revocation_issue(Game.GetHandle(), Grant, GrantLen, RevokedMs, OutRevocation);
    }
};

} // namespace AliceAuth
