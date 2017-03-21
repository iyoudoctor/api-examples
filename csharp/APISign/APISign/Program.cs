using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Jose;

namespace APISign
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Invalid arguments.");
                Console.WriteLine("Usage: appID path secret");
                Environment.Exit(1);
            }
            var appID = args[0];
            var path = args[1];
            var secret = args[2];
            var time = DateTime.UtcNow; // Use UTC time
            // Generate signature
            var sign = GenerateToken(appID, path, time, Encoding.Default.GetBytes(secret));
            Console.WriteLine("Generate Time: {0}", time);
            Console.WriteLine("Signature: {0}", sign);
        }

        static string GenerateToken(string appID, string path, DateTime time, byte[] hashKey)
        {
            var payload = new Dictionary<string, object>()
            {
                {"appID", appID },
                {"path", path },
                {"utctime", time.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK") }
            };
            return JWT.Encode(payload, hashKey, JwsAlgorithm.HS256);
        }
    }
}
