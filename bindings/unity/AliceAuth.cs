// ALICE-Auth Unity C# Bindings
// Ed25519 ZKP authentication via P/Invoke (C-ABI FFI)
//
// Author: Moroya Sakamoto
// License: AGPL-3.0
//
// Usage:
//   1. Build alice-auth as cdylib: cargo build --release --features "ffi,nizk"
//   2. Copy libalice_auth.dylib/.so/.dll to Assets/Plugins/
//   3. Use AliceIdentity, AliceNizk, etc. in your scripts.

using System;
using System.Runtime.InteropServices;

namespace Alice.Auth
{
    // ========================================================================
    // Native P/Invoke declarations (42 of the 45 C-ABI functions: all but aa_last_error, aa_clear_last_error and aa_free_error_string)
    // ========================================================================

    internal static class Native
    {
        const string Lib = "alice_auth";

        // --- Core Identity ---
        [DllImport(Lib)] internal static extern IntPtr aa_new();
        [DllImport(Lib)] internal static extern void aa_id(IntPtr h, byte[] o);
        [DllImport(Lib)] internal static extern int aa_sign(IntPtr h, byte[] c, byte[] o);
        [DllImport(Lib)] internal static extern int aa_verify(byte[] pk, byte[] m, UIntPtr ml, byte[] s);
        [DllImport(Lib)] internal static extern void aa_free(IntPtr h);

        // --- Endorsement ---
        // 0 = written, -1 = null argument, -2 = now_ms + ttl_ms exceeds u64::MAX (o untouched)
        [DllImport(Lib)] internal static extern int aa_endorse(IntPtr h, byte[] target, ulong now_ms, ulong ttl_ms, byte[] o);
        [DllImport(Lib)] internal static extern int aa_verify_endorsement(byte[] data, ulong now_ms);

        // --- RotatingIdentity ---
        [DllImport(Lib)] internal static extern IntPtr aa_rotating_new();
        [DllImport(Lib)] internal static extern int aa_rotating_rotate(IntPtr h, ulong now_ms, byte[] o);
        [DllImport(Lib)] internal static extern void aa_rotating_id(IntPtr h, byte[] o);
        [DllImport(Lib)] internal static extern int aa_rotating_verify(IntPtr h, byte[] pk, byte[] m, UIntPtr ml, byte[] s);
        [DllImport(Lib)] internal static extern uint aa_rotating_generation_count(IntPtr h);
        [DllImport(Lib)] internal static extern void aa_rotating_free(IntPtr h);

        // --- AuthToken ---
        // 0 = written, -1 = null output, -2 = now_ms + ttl_ms exceeds u64::MAX (o untouched)
        [DllImport(Lib)] internal static extern int aa_token_create(ulong now_ms, ulong ttl_ms, byte[] o);
        [DllImport(Lib)] internal static extern int aa_token_is_expired(byte[] data, ulong now_ms);

        // --- RevocationList ---
        [DllImport(Lib)] internal static extern IntPtr aa_revlist_new();
        [DllImport(Lib)] internal static extern IntPtr aa_revlist_new_with_capacity(uint capacity);
        // 0 = revoked, -1 = null argument, -2 = list full (token NOT revoked)
        [DllImport(Lib)] internal static extern int aa_revlist_revoke(IntPtr h, byte[] token, ulong now_ms);
        [DllImport(Lib)] internal static extern int aa_revlist_is_revoked(IntPtr h, byte[] token);
        [DllImport(Lib)] internal static extern uint aa_revlist_auto_purge(IntPtr h, ulong now_ms, ulong ttl_ms);
        [DllImport(Lib)] internal static extern void aa_revlist_free(IntPtr h);

        // --- PolicyEngine (RBAC) ---
        [DllImport(Lib)] internal static extern IntPtr aa_policy_new();
        [DllImport(Lib)] internal static extern void aa_policy_assign(IntPtr h, byte[] id, byte mask);
        [DllImport(Lib)] internal static extern int aa_policy_check(IntPtr h, byte[] id, byte perm);
        [DllImport(Lib)] internal static extern void aa_policy_free(IntPtr h);

        // --- NIZK (requires ffi+nizk features) ---
        [DllImport(Lib)] internal static extern int aa_nizk_prove(IntPtr h, byte[] m, UIntPtr ml, byte[] o);
        [DllImport(Lib)] internal static extern int aa_nizk_verify(byte[] pk, byte[] m, UIntPtr ml, byte[] proof);

        // --- Crypto (requires ffi+crypto features) ---
        [DllImport(Lib)] internal static extern IntPtr aa_derive_child(IntPtr h, uint index);
        [DllImport(Lib)] internal static extern void aa_derive_session_key(byte[] id_a, byte[] id_b, byte[] secret, UIntPtr secret_len, byte[] o);

        // --- Player (id, key chain, grants, revocations) ---
        // 0 = success, otherwise a negative AliceGrantResult; outputs are written only on success
        [DllImport(Lib)] internal static extern IntPtr aa_from_seed(byte[] seed);
        [DllImport(Lib)] internal static extern int aa_player_id_from_genesis(byte[] genesis, byte[] o);
        [DllImport(Lib)] internal static extern int aa_rotation_link_issue(IntPtr old_key, byte[] player, uint seq, byte[] new_key, ulong issued_ms, byte[] o);
        [DllImport(Lib)] internal static extern int aa_player_chain_resolve(byte[] genesis, byte[] links, UIntPtr n_links, byte[] out_player, byte[] out_key, out ulong out_since_ms);
        [DllImport(Lib)] internal static extern int aa_grant_issue(IntPtr game, byte[] player, byte[] player_key, ulong scope, ulong now_ms, ulong ttl_ms, byte[] nonce, byte[] o);
        [DllImport(Lib)] internal static extern int aa_grant_verify(byte[] grant, UIntPtr grant_len, byte[] expected_game, byte[] head_player, byte[] head_key, ulong head_since_ms, ulong now_ms, IntPtr revoked, byte[] out_player, out ulong out_scope, out ulong out_expires_ms);
        [DllImport(Lib)] internal static extern int aa_revocation_issue(IntPtr game, byte[] grant, UIntPtr grant_len, ulong revoked_ms, byte[] o);
        [DllImport(Lib)] internal static extern IntPtr aa_revset_new(UIntPtr capacity);
        [DllImport(Lib)] internal static extern int aa_revset_add(IntPtr set, byte[] rev, UIntPtr rev_len);
        [DllImport(Lib)] internal static extern int aa_revset_contains(IntPtr set, byte[] game, byte[] nonce);
        [DllImport(Lib)] internal static extern long aa_revset_purge(IntPtr set, ulong now_ms);
        [DllImport(Lib)] internal static extern long aa_revset_len(IntPtr set);
        [DllImport(Lib)] internal static extern void aa_revset_free(IntPtr set);
    }

    // ========================================================================
    // AliceIdentity (IDisposable, opaque handle)
    // ========================================================================

    /// <summary>
    /// Ed25519 identity. Secret key stays in Rust memory.
    /// </summary>
    public sealed class AliceIdentity : IDisposable
    {
        internal IntPtr handle;

        /// <summary>Generate a new random Ed25519 identity.</summary>
        public AliceIdentity()
        {
            handle = Native.aa_new();
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("ALICE-Auth: keygen failed (RNG error)");
        }

        internal AliceIdentity(IntPtr ptr)
        {
            handle = ptr;
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("ALICE-Auth: null handle");
        }

        /// <summary>Restore an identity from its 32-byte seed. The seed is the secret key:
        /// take it from a secure random source (or from where it was stored) and keep it
        /// like a key.</summary>
        public static AliceIdentity FromSeed(byte[] seed)
        {
            if (seed == null || seed.Length != 32)
                throw new ArgumentException("seed must be 32 bytes");
            return new AliceIdentity(Native.aa_from_seed(seed));
        }

        /// <summary>Get the 32-byte public identity.</summary>
        public byte[] Id()
        {
            var o = new byte[32];
            Native.aa_id(handle, o);
            return o;
        }

        /// <summary>Sign a 32-byte challenge. Returns 64-byte signature.</summary>
        public byte[] Sign(byte[] challenge)
        {
            if (challenge == null || challenge.Length != 32)
                throw new ArgumentException("challenge must be 32 bytes");
            var o = new byte[64];
            int rc = Native.aa_sign(handle, challenge, o);
            if (rc == -2)
                throw new ArgumentException("challenge starts with the reserved prefix alice-auth/", nameof(challenge));
            if (rc != 0)
                throw new InvalidOperationException("ALICE-Auth: sign failed");
            return o;
        }

        /// <summary>Verify an Ed25519 signature over a message.</summary>
        public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            if (publicKey == null || publicKey.Length != 32) return false;
            if (message == null) return false;
            if (signature == null || signature.Length != 64) return false;
            return Native.aa_verify(publicKey, message, (UIntPtr)message.Length, signature) != 0;
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero)
            {
                Native.aa_free(handle);
                handle = IntPtr.Zero;
            }
        }

        ~AliceIdentity() => Dispose();
    }

    // ========================================================================
    // AliceEndorsement
    // ========================================================================

    /// <summary>Trust chain endorsement with expiry.</summary>
    public static class AliceEndorsement
    {
        /// <summary>
        /// Endorse a target identity. Returns 176-byte endorsement.
        /// Layout: endorser(32) || endorsed(32) || sig(64) || issued_ms(8) || expires_ms(8) || pad(32)
        /// </summary>
        public static byte[] Endorse(AliceIdentity signer, byte[] targetId, ulong nowMs, ulong ttlMs)
        {
            if (targetId == null || targetId.Length != 32)
                throw new ArgumentException("targetId must be 32 bytes");
            var o = new byte[176];
            int rc = Native.aa_endorse(signer.handle, targetId, nowMs, ttlMs, o);
            if (rc == -2)
                throw new ArgumentOutOfRangeException(nameof(ttlMs), "nowMs + ttlMs exceeds u64::MAX");
            if (rc == -3)
                throw new ArgumentException("targetId starts with the reserved prefix alice-auth/", nameof(targetId));
            if (rc != 0)
                throw new InvalidOperationException("ALICE-Auth: endorse failed");
            return o;
        }

        /// <summary>Verify an endorsement (144 bytes minimum). Returns true if valid and not expired.</summary>
        public static bool Verify(byte[] endorsementData, ulong nowMs)
        {
            if (endorsementData == null || endorsementData.Length < 144) return false;
            return Native.aa_verify_endorsement(endorsementData, nowMs) != 0;
        }
    }

    // ========================================================================
    // AliceRotatingIdentity (IDisposable)
    // ========================================================================

    /// <summary>Identity with N-generation key rotation.</summary>
    public sealed class AliceRotatingIdentity : IDisposable
    {
        IntPtr handle;

        public AliceRotatingIdentity()
        {
            handle = Native.aa_rotating_new();
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("ALICE-Auth: rotating keygen failed");
        }

        /// <summary>Rotate to a new keypair. Returns the new 32-byte public ID.</summary>
        public byte[] Rotate(ulong nowMs)
        {
            var o = new byte[32];
            if (Native.aa_rotating_rotate(handle, nowMs, o) == 0)
                throw new InvalidOperationException("ALICE-Auth: rotation failed");
            return o;
        }

        /// <summary>Get the current 32-byte public ID.</summary>
        public byte[] CurrentId()
        {
            var o = new byte[32];
            Native.aa_rotating_id(handle, o);
            return o;
        }

        /// <summary>True when publicKey is the current key or a retained previous key and signature is that key's valid signature of message.</summary>
        public bool VerifyAny(byte[] publicKey, byte[] message, byte[] signature)
        {
            if (publicKey == null || publicKey.Length != 32) return false;
            if (message == null) return false;
            if (signature == null || signature.Length != 64) return false;
            return Native.aa_rotating_verify(handle, publicKey, message, (UIntPtr)message.Length, signature) != 0;
        }

        /// <summary>Number of retained previous generations.</summary>
        public uint GenerationCount => Native.aa_rotating_generation_count(handle);

        public void Dispose()
        {
            if (handle != IntPtr.Zero)
            {
                Native.aa_rotating_free(handle);
                handle = IntPtr.Zero;
            }
        }

        ~AliceRotatingIdentity() => Dispose();
    }

    // ========================================================================
    // AliceAuthToken
    // ========================================================================

    /// <summary>Structured authentication token (17 bytes).</summary>
    public static class AliceAuthToken
    {
        /// <summary>Create a token. Returns 17 bytes.</summary>
        public static byte[] Create(ulong nowMs, ulong ttlMs)
        {
            var o = new byte[17];
            int rc = Native.aa_token_create(nowMs, ttlMs, o);
            if (rc == -2)
                throw new ArgumentOutOfRangeException(nameof(ttlMs), "nowMs + ttlMs exceeds u64::MAX");
            if (rc != 0)
                throw new InvalidOperationException("ALICE-Auth: token create failed");
            return o;
        }

        /// <summary>Check if a token is expired.</summary>
        public static bool IsExpired(byte[] tokenData, ulong nowMs)
        {
            if (tokenData == null || tokenData.Length < 17) return true;
            return Native.aa_token_is_expired(tokenData, nowMs) != 0;
        }
    }

    // ========================================================================
    // AliceRevocationList (IDisposable)
    // ========================================================================

    /// <summary>Session token revocation list with constant-time checks.</summary>
    public sealed class AliceRevocationList : IDisposable
    {
        IntPtr handle;

        public AliceRevocationList()
        {
            handle = Native.aa_revlist_new();
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("ALICE-Auth: revlist alloc failed");
        }

        /// <summary>A list holding at most capacity entries (at least 1).</summary>
        public AliceRevocationList(uint capacity)
        {
            handle = Native.aa_revlist_new_with_capacity(capacity);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("ALICE-Auth: revlist alloc failed");
        }

        /// <summary>Revoke a 16-byte session token. Throws when the list is
        /// full: the token is then NOT revoked and no earlier entry is dropped.</summary>
        public void Revoke(byte[] token, ulong nowMs)
        {
            if (token == null || token.Length != 16)
                throw new ArgumentException("token must be 16 bytes");
            int rc = Native.aa_revlist_revoke(handle, token, nowMs);
            if (rc == -2)
                throw new InvalidOperationException("ALICE-Auth: revocation list is full; the token was not revoked");
            if (rc != 0)
                throw new InvalidOperationException("ALICE-Auth: revoke failed; the token was not revoked");
        }

        /// <summary>Check if a token is revoked (constant-time).</summary>
        public bool IsRevoked(byte[] token)
        {
            if (token == null || token.Length != 16) return false;
            return Native.aa_revlist_is_revoked(handle, token) != 0;
        }

        /// <summary>Purge tokens revoked more than ttlMs ago. Returns count purged.</summary>
        public uint AutoPurge(ulong nowMs, ulong ttlMs) => Native.aa_revlist_auto_purge(handle, nowMs, ttlMs);

        public void Dispose()
        {
            if (handle != IntPtr.Zero)
            {
                Native.aa_revlist_free(handle);
                handle = IntPtr.Zero;
            }
        }

        ~AliceRevocationList() => Dispose();
    }

    // ========================================================================
    // AlicePolicyEngine (IDisposable, RBAC)
    // ========================================================================

    /// <summary>Role-based access control engine.</summary>
    public sealed class AlicePolicyEngine : IDisposable
    {
        IntPtr handle;

        /// <summary>Permission flags (bit index).</summary>
        public const byte Read = 0;
        public const byte Write = 1;
        public const byte Admin = 2;
        public const byte Execute = 3;

        public AlicePolicyEngine()
        {
            handle = Native.aa_policy_new();
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("ALICE-Auth: policy alloc failed");
        }

        /// <summary>Assign a role mask to an identity.</summary>
        public void Assign(byte[] id, byte mask)
        {
            if (id == null || id.Length != 32)
                throw new ArgumentException("id must be 32 bytes");
            Native.aa_policy_assign(handle, id, mask);
        }

        /// <summary>Check if an identity has a permission (0=Read,1=Write,2=Admin,3=Execute).</summary>
        public bool Check(byte[] id, byte permission)
        {
            if (id == null || id.Length != 32) return false;
            return Native.aa_policy_check(handle, id, permission) != 0;
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero)
            {
                Native.aa_policy_free(handle);
                handle = IntPtr.Zero;
            }
        }

        ~AlicePolicyEngine() => Dispose();
    }

    // ========================================================================
    // AliceNizk (Schnorr NIZK — requires ffi+nizk features)
    // ========================================================================

    /// <summary>Schnorr NIZK zero-knowledge proof.</summary>
    public static class AliceNizk
    {
        /// <summary>Generate a NIZK proof. Returns 64 bytes (R || s).</summary>
        public static byte[] Prove(AliceIdentity identity, byte[] message)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            var o = new byte[64];
            if (Native.aa_nizk_prove(identity.handle, message, (UIntPtr)message.Length, o) == 0)
                throw new InvalidOperationException("ALICE-Auth: NIZK prove failed");
            return o;
        }

        /// <summary>Verify a NIZK proof. Returns true if valid.</summary>
        public static bool Verify(byte[] publicKey, byte[] message, byte[] proof)
        {
            if (publicKey == null || publicKey.Length != 32) return false;
            if (message == null) return false;
            if (proof == null || proof.Length != 64) return false;
            return Native.aa_nizk_verify(publicKey, message, (UIntPtr)message.Length, proof) != 0;
        }
    }

    // ========================================================================
    // AliceCrypto (HD derivation — requires ffi+crypto features)
    // ========================================================================

    /// <summary>Cryptographic utilities: HD key derivation, session keys.</summary>
    public static class AliceCrypto
    {
        /// <summary>Derive a child identity from parent + index.</summary>
        public static AliceIdentity DeriveChild(AliceIdentity parent, uint index)
        {
            var ptr = Native.aa_derive_child(parent.handle, index);
            return new AliceIdentity(ptr);
        }

        /// <summary>Derive a 32-byte session key from two IDs and a shared secret.</summary>
        public static byte[] DeriveSessionKey(byte[] idA, byte[] idB, byte[] sharedSecret)
        {
            if (idA == null || idA.Length != 32) throw new ArgumentException("idA must be 32 bytes");
            if (idB == null || idB.Length != 32) throw new ArgumentException("idB must be 32 bytes");
            if (sharedSecret == null) throw new ArgumentNullException(nameof(sharedSecret));
            var o = new byte[32];
            Native.aa_derive_session_key(idA, idB, sharedSecret, (UIntPtr)sharedSecret.Length, o);
            return o;
        }
    }

    // ========================================================================
    // Player: id, key chain, grants, revocations
    // ========================================================================

    /// <summary>The result codes of the player functions (0 = success).</summary>
    public enum AliceGrantResult
    {
        Ok = 0,
        Null = -1,
        Length = -2,
        Version = -3,
        Signature = -4,
        WrongGame = -5,
        NotYetValid = -6,
        Expired = -7,
        Revoked = -8,
        Times = -9,
        WrongKey = -10,
        Overflow = -11,
        Full = -12,
        Chain = -13,
        Rng = -14,
    }

    /// <summary>A player function refused its input.</summary>
    public sealed class AliceGrantException : InvalidOperationException
    {
        public AliceGrantResult Result { get; }

        public AliceGrantException(string what, int code)
            : base("ALICE-Auth: " + what + " refused (" + (AliceGrantResult)code + ")")
        {
            Result = (AliceGrantResult)code;
        }
    }

    /// <summary>The revocations a verifier knows, with a fixed capacity.</summary>
    public sealed class AliceRevocationSet : IDisposable
    {
        internal IntPtr handle;

        /// <summary>A set holding at most capacity revocations (capacity &gt;= 1).</summary>
        public AliceRevocationSet(ulong capacity)
        {
            handle = Native.aa_revset_new((UIntPtr)capacity);
            if (handle == IntPtr.Zero)
                throw new ArgumentException("ALICE-Auth: a revocation set needs a capacity of at least 1");
        }

        /// <summary>Add a revocation (129 bytes) after checking its signature. Throws when it
        /// is not held. Full means the revocation was NOT stored and the grant is still
        /// accepted: treat it as an emergency (a larger set, or stop accepting that game's
        /// grants), not as a retry.</summary>
        public void Add(byte[] revocation)
        {
            if (revocation == null)
                throw new ArgumentNullException(nameof(revocation));
            int rc = Native.aa_revset_add(handle, revocation, (UIntPtr)revocation.Length);
            if (rc != 0)
                throw new AliceGrantException("revocation add", rc);
        }

        /// <summary>True when the grant nonce (16 bytes) of game (32 bytes) is revoked.</summary>
        public bool Contains(byte[] game, byte[] nonce)
        {
            if (game == null || game.Length != 32 || nonce == null || nonce.Length != 16)
                return true;
            return Native.aa_revset_contains(handle, game, nonce) != 0;
        }

        /// <summary>Drop the revocations of grants expired at nowMs; the number dropped.</summary>
        public long Purge(ulong nowMs) => Native.aa_revset_purge(handle, nowMs);

        /// <summary>The number of revocations held.</summary>
        public long Count => Native.aa_revset_len(handle);

        public void Dispose()
        {
            if (handle != IntPtr.Zero)
            {
                Native.aa_revset_free(handle);
                handle = IntPtr.Zero;
            }
        }

        ~AliceRevocationSet() => Dispose();
    }

    /// <summary>A player's id and key chain, and a game's grants and revocations.</summary>
    public static class AlicePlayer
    {
        public const int RotationLinkLength = 173;
        public const int GrantLength = 201;
        public const int RevocationLength = 129;

        static void Need(byte[] b, int n, string name)
        {
            if (b == null || b.Length != n)
                throw new ArgumentException(name + " must be " + n + " bytes");
        }

        /// <summary>The 32-byte player id of the first key genesis.</summary>
        public static byte[] IdFromGenesis(byte[] genesis)
        {
            Need(genesis, 32, "genesis");
            var o = new byte[32];
            int rc = Native.aa_player_id_from_genesis(genesis, o);
            if (rc != 0) throw new AliceGrantException("player id", rc);
            return o;
        }

        /// <summary>A rotation link from oldKey's key to newKey at issuedMs.</summary>
        public static byte[] IssueRotationLink(AliceIdentity oldKey, byte[] player, uint seq, byte[] newKey, ulong issuedMs)
        {
            Need(player, 32, "player");
            Need(newKey, 32, "newKey");
            var o = new byte[RotationLinkLength];
            int rc = Native.aa_rotation_link_issue(oldKey.handle, player, seq, newKey, issuedMs, o);
            if (rc != 0) throw new AliceGrantException("rotation link", rc);
            return o;
        }

        /// <summary>Check links (back to back, 173 bytes each) from genesis; the player, the
        /// current key and the time it became current, or the refusal.</summary>
        public static AliceGrantResult ResolveChain(byte[] genesis, byte[] links, out byte[] player, out byte[] key, out ulong sinceMs)
        {
            Need(genesis, 32, "genesis");
            links = links ?? new byte[0];
            if (links.Length % RotationLinkLength != 0)
            {
                player = null; key = null; sinceMs = 0;
                return AliceGrantResult.Length;
            }
            var p = new byte[32];
            var k = new byte[32];
            int rc = Native.aa_player_chain_resolve(genesis, links, (UIntPtr)(links.Length / RotationLinkLength), p, k, out sinceMs);
            player = rc == 0 ? p : null;
            key = rc == 0 ? k : null;
            return (AliceGrantResult)rc;
        }

        /// <summary>A grant from game to player under playerKey, valid nowMs &lt;= t &lt; nowMs + ttlMs.</summary>
        public static byte[] IssueGrant(AliceIdentity game, byte[] player, byte[] playerKey, ulong scope, ulong nowMs, ulong ttlMs, byte[] nonce)
        {
            Need(player, 32, "player");
            Need(playerKey, 32, "playerKey");
            Need(nonce, 16, "nonce");
            var o = new byte[GrantLength];
            int rc = Native.aa_grant_issue(game.handle, player, playerKey, scope, nowMs, ttlMs, nonce, o);
            if (rc != 0) throw new AliceGrantException("grant issue", rc);
            return o;
        }

        /// <summary>Check a grant for expectedGame at nowMs against the chain end and the
        /// revocations. Ok, or the first check that failed (the expiry itself is outside
        /// the window).</summary>
        public static AliceGrantResult VerifyGrant(byte[] grant, byte[] expectedGame, byte[] headPlayer, byte[] headKey, ulong headSinceMs, ulong nowMs, AliceRevocationSet revoked, out byte[] player, out ulong scope, out ulong expiresMs)
        {
            Need(expectedGame, 32, "expectedGame");
            Need(headPlayer, 32, "headPlayer");
            Need(headKey, 32, "headKey");
            if (grant == null) throw new ArgumentNullException(nameof(grant));
            var p = new byte[32];
            int rc = Native.aa_grant_verify(grant, (UIntPtr)grant.Length, expectedGame, headPlayer, headKey, headSinceMs, nowMs, revoked.handle, p, out scope, out expiresMs);
            player = rc == 0 ? p : null;
            return (AliceGrantResult)rc;
        }

        /// <summary>The revocation of grant by game (the game that issued it).</summary>
        public static byte[] IssueRevocation(AliceIdentity game, byte[] grant, ulong revokedMs)
        {
            if (grant == null) throw new ArgumentNullException(nameof(grant));
            var o = new byte[RevocationLength];
            int rc = Native.aa_revocation_issue(game.handle, grant, (UIntPtr)grant.Length, revokedMs, o);
            if (rc != 0) throw new AliceGrantException("revocation issue", rc);
            return o;
        }
    }
}
