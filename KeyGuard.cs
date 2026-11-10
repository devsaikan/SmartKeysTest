using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SmartKeysTest
{

    public enum KeyMode { Stealth, Visible }

    [Flags]
    public enum KeyFlags : byte { None = 0, Canary = 1 }

    public readonly record struct KeyInfo(uint TenantId, uint KeyId,
        DateTimeOffset Expires, byte Version, KeyFlags Flags)
    {
        public bool IsCanary => (Flags & KeyFlags.Canary) != 0;
    }

    public sealed class KeyGuard
    {
        // Ours, not sk_live_. dont step on stripe
        const string Prefix = "srp_live_"; 
        // One aes block. do not grow this, see note below
        const int PlainLen = 16;
        // Half the hmac is plenty
        const int TagLen = 16;            
        const int BodyLen = PlainLen + TagLen;

        // Keyed by version so i can rotate without nuking old keys. old pairs stay loaded
        readonly Dictionary<byte, (byte[] Enc, byte[] Mac)> _secrets;
        readonly byte _ver;

        public KeyGuard(Dictionary<byte, (byte[] Enc, byte[] Mac)> secrets, byte version)
        {
            _secrets = secrets;
            _ver = version; // what the new keys get stamped with
        }

        public string Issue(KeyMode mode, uint tenantId, uint keyId,
            DateTimeOffset expires, KeyFlags flags = KeyFlags.None)
        {
            var (enc, mac) = _secrets[_ver];

            // Pack the identity into 16 bytes. this is the whole secret delicious sauce
            Span<byte> plain = stackalloc byte[PlainLen];
            Put(plain, 0, tenantId);
            Put(plain, 4, keyId);
            // Good till 2106, fine?
            Put(plain, 8, (uint)expires.ToUnixTimeSeconds());
            plain[12] = _ver;
            plain[13] = (byte)flags;
            // Random tail so no two keys can collide
            RandomNumberGenerator.Fill(plain.Slice(14, 2));

            // Encrypt the block. now its noise to anyone without enc
            using var aes = Aes.Create();
            aes.Key = enc;
            Span<byte> cipher = stackalloc byte[PlainLen];
            // single block, ecb is fine here
            aes.EncryptEcb(plain, cipher, PaddingMode.None); 

            // Sign the cipher. this is the part only i can produce
            Span<byte> sig = stackalloc byte[32];
            HMACSHA256.HashData(mac, cipher, sig);

            Span<byte> body = stackalloc byte[BodyLen];
            cipher.CopyTo(body);
            // Keep first 16 bytes of the mac
            sig[..TagLen].CopyTo(body[PlainLen..]); 

            // stealth = looks like a sha256 hash. visible = prefix so dlp can grab it
            return mode == KeyMode.Stealth
                ? Convert.ToHexString(body).ToLowerInvariant()
                : $"{Prefix}{ToBase62(body)}_{Crc(body)}";
        }

        public bool TryVerify(string key, out KeyInfo info)
        {
            info = default;
            byte[] body;

            if (key.StartsWith(Prefix, StringComparison.Ordinal))
            {
                // Visible key. Strip prefix, drop the crc on the end, decode the middle
                int cut = key.LastIndexOf('_');
                if (cut <= Prefix.Length) return false;
                try { body = FromBase62(key[Prefix.Length..cut], BodyLen); }
                catch { return false; }
            }
            else if (key.Length == BodyLen * 2 && IsHex(key))
            {
                // Stealth key. just the raw hex
                try { body = Convert.FromHexString(key); }
                catch { return false; }
            }
            else return false; // not even shaped like ours? Bail

            var cipher = body.AsSpan(0, PlainLen);
            var tag = body.AsSpan(PlainLen, TagLen);

            // Try every secret version we know. usually one or two
            foreach (var (ver, s) in _secrets)
            {
                Span<byte> sig = stackalloc byte[32];
                HMACSHA256.HashData(s.Mac, cipher, sig);

                // constant time. plain == lets someone time their way to the signature or a hard pass
                if (!CryptographicOperations.FixedTimeEquals(tag, sig[..TagLen]))
                    continue;

                using var aes = Aes.Create();
                aes.Key = s.Enc;
                Span<byte> plain = stackalloc byte[PlainLen];
                aes.DecryptEcb(cipher, plain, PaddingMode.None);
                // Sig matched but version byte disagrees, skip it
                if (plain[12] != ver) continue; 

                info = new KeyInfo(Get(plain, 0), Get(plain, 4),
                    DateTimeOffset.FromUnixTimeSeconds(Get(plain, 8)),
                    plain[12], (KeyFlags)plain[13]);
                return true; // this one is ours, we know exactly who
            }
            return false;
        }

        // Point this at a repo, logs, tickets, whatever. pulls candidates, keeps the real ones
        public IEnumerable<(string Token, KeyInfo Info)> Hunt(string text)
        {
            var rx = new System.Text.RegularExpressions.Regex(
                @"\b[0-9a-f]{64}\b|srp_live_[0-9A-Za-z]+_[0-9a-f]{2}\b");
            foreach (System.Text.RegularExpressions.Match m in rx.Matches(text))
                if (TryVerify(m.Value, out var info))
                    yield return (m.Value, info); // survived the hmac, so its really ours
        }

        // uint in, 4 bytes big endian. keeps the layout the same everywhere
        static void Put(Span<byte> b, int i, uint v)
        {
            b[i] = (byte)(v >> 24); b[i + 1] = (byte)(v >> 16);
            b[i + 2] = (byte)(v >> 8); b[i + 3] = (byte)v;
        }

        static uint Get(ReadOnlySpan<byte> b, int i)
            => (uint)(b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3]);

        // Lowercase hex only. a real stealth key is never uppercase, so reject early
        static bool IsHex(string s)
        {
            foreach (char c in s)
                if (!Uri.IsHexDigit(c) || char.IsUpper(c)) return false;
            return true;
        }

        // Not Google :)
        const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        // base62 so the visible key is clean alphanumerics, no + / = to mangle a double click
        static string ToBase62(ReadOnlySpan<byte> data)
        {
            var n = new BigInteger(data, true, true);
            var sb = new StringBuilder();
            while (n > 0) { n = BigInteger.DivRem(n, 62, out var r); sb.Insert(0, Alphabet[(int)r]); }
            return sb.Length == 0 ? "0" : sb.ToString();
        }

        static byte[] FromBase62(string s, int len)
        {
            BigInteger n = 0;
            foreach (char c in s)
            {
                int d = Alphabet.IndexOf(c);
                if (d < 0) throw new FormatException(); // Junk char, not ours
                n = n * 62 + d;
            }
            var raw = n.ToByteArray(true, true);
            if (raw.Length > len) throw new FormatException();
            var padded = new byte[len];
            raw.CopyTo(padded, len - raw.Length); // Left pad, big ints drop leading zeros
            return padded;
        }

        // crc32 table, built once. this is just the typo-catcher, not security
        static readonly uint[] Table = Build();

        static uint[] Build()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++)
                    c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
                t[i] = c;
            }
            return t;
        }

        // One byte of crc on the end. enough to kill fat finger typos, widen it if you want fewer
        static string Crc(ReadOnlySpan<byte> data)
        {
            uint c = 0xFFFFFFFF;
            foreach (byte b in data) c = Table[(c ^ b) & 0xFF] ^ (c >> 8);
            return ((c ^ 0xFFFFFFFF) & 0xFF).ToString("x2");
        }
    }
}
