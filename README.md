# KeyGuard (Smart Keys for MCP Hunting)

Self-verifying API keys for MCP servers. A key looks like random noise to anyone without the secrets, but the issuing server can recognize its own keys, read who they belong to, and spot them in a leak. No database lookup to validate.

## The idea

Every key carries 16 bytes of identity (tenant, key id, expiry, version, and two random bytes) encrypted as a single AES block, followed by a 16-byte HMAC signature over that block. Two secrets do two jobs:

- `enc` hides what is inside the key
- `mac` proves the key was issued by you

Neither secret ever leaves the server, and nothing about either one is in the key itself.

## Two modes, same body

- **Stealth**: 64 hex characters, indistinguishable from a SHA-256 hash. No prefix. Use it for keys that only travel between your own services. If it leaks, it hides in the crowd of hashes already in your logs and repos, and your own hunter is what finds it.
- **Visible**: your prefix, Base62 body, and a one-byte public checksum. Use it for keys you hand to customers and partners, so GitHub push protection, DLP, and egress proxies can catch it with one pattern. The prefix can be faked, so the signature is still the only real proof.

## Running the demo

The sample in `Program.cs` derives its secrets from a string so the thing runs out of the box. That is for the demo only. In production, load real random bytes from a vault (commented block below).

```csharp
//// Version 1
// const byte KeyV1 = 1;
//// HSM or Vault
// byte[] enc = await vault.GetSecretAsync("keyguard/v1/enc");
// byte[] mac = await vault.GetSecretAsync("keyguard/v1/mac");
// var secrets = new Dictionary<byte, (byte[] Enc, byte[] Mac)> { [KeyV1] = (enc, mac) };
// var kg = new KeyGuard(secrets, version: KeyV1);

// Master secret. This should be in a vault, not derived from a string.
var secrets = new Dictionary<byte, (byte[], byte[])>
{
    [1] = (SHA256.HashData("enc-v1"u8.ToArray()), SHA256.HashData("mac-v1"u8.ToArray())),
};
var kg = new KeyGuard(secrets, 1);
var exp = DateTimeOffset.UtcNow.AddDays(90);

string stealth = kg.Issue(KeyMode.Stealth, 1024, 7, exp);
string visible = kg.Issue(KeyMode.Visible, 1024, 8, exp);
string canary  = kg.Issue(KeyMode.Stealth, 4096, 1, exp, KeyFlags.Canary);

kg.TryVerify(stealth, out var i1);
```


## Hunting leaks

```csharp
foreach (var (token, info) in kg.Hunt(textFromARepoOrLog))
    Console.WriteLine($"HUNT    : tenant={info.TenantId} key={info.KeyId} canary={info.IsCanary} >> revoke");
```

`Hunt` pulls every string shaped like a key out of any text, tests each one against the secret, and returns only the real hits.

## Canary keys

Issue a key with `KeyFlags.Canary` and plant it where only a snoop would find it (a `.env` file, an MCP config, a document in your RAG corpus). Nobody legitimate ever uses it, so if it ever shows up in a scan or an incoming request, you have been breached, and the key id tells you which spot it came from.

## Rotation

Keys are keyed by a version byte. To rotate, add a new pair and point the server at it:

```csharp
var secrets = new Dictionary<byte, (byte[], byte[])>
{
    [1] = (oldEnc, oldMac), // stays loaded so old keys still verify
    [2] = (newEnc, newMac),
};
var kg = new KeyGuard(secrets, 2);
```

Old keys keep verifying until they expire. Nothing breaks.

## Notes:

- The 16 bytes are encrypted as a single AES block with no IV. That is safe only because the two random bytes keep every block unique. If you grow the payload past 16 bytes, switch to AES-GCM with a random nonce.
- Verification uses a constant-time compare. A plain `==` that bails on the first wrong byte lets an attacker time their way to a valid signature.
- The checksum on the visible key is one byte, enough to catch typos. Widen it to a full CRC32 if you want fewer false positives at the DLP layer.
- The signature proves a key was issued, not that it is still valid. Keep a small in-memory revocation list.
- Keep the master secrets in an HSM or key vault, never in source.
- Check my LinkedIn post for additional details.

## License

MIT
