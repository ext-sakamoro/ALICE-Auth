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
    // Native P/Invoke declarations (all 28 C-ABI functions)
    // ========================================================================

    internal static class Native
    {
        const string Lib = "alice_auth";

        // --- Core Identity ---
        [DllImport(Lib)] internal static extern IntPtr aa_new();
        [DllImport(Lib)] internal static extern void aa_id(IntPtr h, byte[] o);
        [DllImport(Lib)] internal static extern void aa_sign(IntPtr h, byte[] c, byte[] o);
        [DllImport(Lib)] internal static extern int aa_verify(byte[] pk, byte[] m, UIntPtr ml, byte[] s);
        [DllImport(Lib)] internal static extern void aa_free(IntPtr h);

        // --- Endorsement ---
        [DllImport(Lib)] internal static extern void aa_endorse(IntPtr h, byte[] target, ulong now_ms, ulong ttl_ms, byte[] o);
        [DllImport(Lib)] internal static extern int aa_verify_endorsement(byte[] data, ulong now_ms);

        // --- RotatingIdentity ---
        [DllImport(Lib)] internal static extern IntPtr aa_rotating_new();
        [DllImport(Lib)] internal static extern int aa_rotating_rotate(IntPtr h, ulong now_ms, byte[] o);
        [DllImport(Lib)] internal static extern void aa_rotating_id(IntPtr h, byte[] o);
        [DllImport(Lib)] internal static extern int aa_rotating_verify(IntPtr h, byte[] pk, byte[] m, UIntPtr ml, byte[] s);
        [DllImport(Lib)] internal static extern uint aa_rotating_generation_count(IntPtr h);
        [DllImport(Lib)] internal static extern void aa_rotating_free(IntPtr h);

        // --- AuthToken ---
        [DllImport(Lib)] internal static extern void aa_token_create(ulong now_ms, ulong ttl_ms, byte[] o);
        [DllImport(Lib)] internal static extern int aa_token_is_expired(byte[] data, ulong now_ms);

        // --- RevocationList ---
        [DllImport(Lib)] internal static extern IntPtr aa_revlist_new();
        [DllImport(Lib)] internal static extern void aa_revlist_revoke(IntPtr h, byte[] token, ulong now_ms);
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
            Native.aa_sign(handle, challenge, o);
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
            Native.aa_endorse(signer.handle, targetId, nowMs, ttlMs, o);
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

        /// <summary>Verify a signature against any key (current + all previous).</summary>
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
            Native.aa_token_create(nowMs, ttlMs, o);
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

        /// <summary>Revoke a 16-byte session token.</summary>
        public void Revoke(byte[] token, ulong nowMs)
        {
            if (token == null || token.Length != 16)
                throw new ArgumentException("token must be 16 bytes");
            Native.aa_revlist_revoke(handle, token, nowMs);
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
}
