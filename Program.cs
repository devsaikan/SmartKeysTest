using System.Security.Cryptography;
using System.Text;

namespace SmartKeysTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //// Version 1
            // const byte KeyV1 = 1;
            //// HSM or Vault
            // byte[] enc = await vault.GetSecretAsync("keyguard/v1/enc"); 
            // byte[] mac = await vault.GetSecretAsync("keyguard/v1/mac"); 

            // var secrets = new Dictionary<byte, (byte[] Enc, byte[] Mac)> { [KeyV1] = (enc, mac) };
            // var kg = new KeyGuard(secrets, version: KeyV1);

            // Master secret - This should be in a vault!!!!
            var secrets = new Dictionary<byte, (byte[], byte[])>
            {
                [1] = (SHA256.HashData("enc-v1"u8.ToArray()), SHA256.HashData("mac-v1"u8.ToArray())),
            };

            var kg = new KeyGuard(secrets, 1);
            var exp = DateTimeOffset.UtcNow.AddDays(90);

            // This is a key issued in stealth mode. It’s the 16-byte encrypted block plus the 16-byte signature,
            // written out as 64 hex characters. No prefix, no label. It looks identical to a SHA-256 hash,
            // so it hides in any repo or log that’s full of hashes. Nobody looking at it can tell it’s a key,
            // let alone whose it is. That’s the costume.
            string stealth = kg.Issue(KeyMode.Stealth, 1024, 7, exp);

            // Same key material, different wrapper. It starts with prefix srp_live_,
            // the body is Base62 instead of hex, and the _a2 on the end is the public checksum (like a UPC or FedEx or UPS Tracking Number).
            // The prefix and fixed shape are what enable DLP, egress proxies and repo push protection
            // catch it with a simple pattern. Those are the decorations out front: everyone can see
            // it’s one of yours, but they still can’t read who it belongs to, because the inside is encrypted.
            string visible = kg.Issue(KeyMode.Visible, 1024, 8, exp);

            // From the outside the canary looks exactly like any other key, total noise, no tell.
            // But when your own verifier opens it up, it sees the flag and knows this one was a plant.
            // That’s the canary=True you saw in the hunt output.
            string canary = kg.Issue(KeyMode.Stealth, 4096, 1, exp, KeyFlags.Canary);

            Console.WriteLine($"stealth : {stealth}");
            Console.WriteLine($"visible : {visible}");

            kg.TryVerify(stealth, out var i1);
            Console.WriteLine($"verify  : tenant={i1.TenantId} key={i1.KeyId} expires={i1.Expires:yyyy-MM-dd}");

            var bad = (stealth[0] == 'a' ? 'b' : 'a') + stealth[1..];
            Console.WriteLine($"tamper  : {(kg.TryVerify(bad, out _) ? "accepted (bad!)" : "rejected")}");

            var hay = new StringBuilder();
            for (int n = 0; n < 6; n++) hay.AppendLine(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant());
            hay.AppendLine($"token = \"{canary}\"   # oops, committed");
            for (int n = 0; n < 6; n++) hay.AppendLine(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant());
            foreach (var (tok, info) in kg.Hunt(hay.ToString()))
                Console.WriteLine($"HUNT    : tenant={info.TenantId} key={info.KeyId} canary={info.IsCanary} >> revoke");
        }
    }
}
