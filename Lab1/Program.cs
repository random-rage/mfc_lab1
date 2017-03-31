using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Org.BouncyCastle.Math;

namespace Lab1
{
    class Program
    {
        const int E = 65537;
        const int KEY_SIZE = 2048;
        const int CERTAINTY = 200;
        const int SEED = 1635901897;

        const string SAMPLE = "This is example text";
        const string PUBLIC_KEY =   "06F1A4EDF328C5E44AD32D5AA33FB7EF10B9A0FEE3AC1D3BA8E2FACD97643A43";
        const string PRIVATE_KEY =  "BDB440EBF1A77CFA014A9CD753F3F6335B1BCDD8ABE30049F10C44243BF3B6C8";

        static void Main(string[] args)
        {
            Parallel.For(1, 17, new Action<int>((i) =>
            {
                Console.WriteLine("<Self> test {0}: {1}", i,
                    (SelfTest(E, KEY_SIZE, CERTAINTY, false) ? "passed" : "failed"));

                Console.WriteLine("(Origin) test {0}: {1}", i,
                    (OriginTest(E, KEY_SIZE, CERTAINTY)) ? "passed" : "failed");

                Console.WriteLine("[Backdoor] test {0}: {1}", i,
                    (BackdoorTest(E, KEY_SIZE, CERTAINTY, PUBLIC_KEY, PRIVATE_KEY)) ? "passed" : "failed");
            }));

            Console.WriteLine("Done!");
            Console.ReadKey();
        }

        static bool SelfTest(int e, int keyLen, int certainty, bool optimize)
        {
            Rsa rsa = new Rsa(BigInteger.ValueOf(e), keyLen, certainty, new Random(), optimize);
            byte[] result, bytes = Encoding.ASCII.GetBytes(SAMPLE);

            BigInteger enc = rsa.Encrypt(new BigInteger(1, bytes));
            try
            {
                result = rsa.Decrypt(enc).ToByteArray();
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
            return Encoding.ASCII.GetString(result) == SAMPLE;
        }

        static bool OriginTest(int e, int keyLen, int certainty)
        {
            Rsa testRsa = new Rsa(BigInteger.ValueOf(e), keyLen, certainty, new Random(), true);
            RSACryptoServiceProvider origin = new RSACryptoServiceProvider();

            RSAParameters originParams = new RSAParameters();
            Rsa.RsaParams testParams = testRsa.Params;

            originParams.D = testParams.d.ToByteArrayUnsigned();
            originParams.Exponent = testParams.e.ToByteArrayUnsigned();
            originParams.P = testParams.p.ToByteArrayUnsigned();
            originParams.Q = testParams.q.ToByteArrayUnsigned();
            originParams.Modulus = testParams.n.ToByteArrayUnsigned();
            originParams.DP = testParams.dP.ToByteArrayUnsigned();
            originParams.DQ = testParams.dQ.ToByteArrayUnsigned();
            originParams.InverseQ = testParams.qInv.ToByteArrayUnsigned();

            try
            {
                origin.ImportParameters(originParams);
            }
            catch (CryptographicException)
            {
                return false;
            }

            byte[] testBytes = Encoding.ASCII.GetBytes(SAMPLE);
            BigInteger src = new BigInteger(1, testBytes);

            byte[] originEnc = origin.Encrypt(testBytes, false);
            BigInteger testEnc = testRsa.Encrypt(src);

            byte[] originDec = origin.Decrypt(originEnc, false);
            BigInteger testDec = testRsa.Decrypt(testEnc);

            return Encoding.ASCII.GetString(testDec.ToByteArray()) == 
                   Encoding.ASCII.GetString(originDec);
        }

        static bool BackdoorTest(int e, int keyLen, int certainty, string pubKey, string privKey)
        {
            Rsa backdoored = RsaBackdoor.Inject(BigInteger.ValueOf(e), keyLen, certainty, StrToBytes(pubKey));
            Rsa recovered = RsaBackdoor.Extract(BigInteger.ValueOf(e), backdoored.Params.n, certainty, StrToBytes(privKey));

            byte[] result, bytes = Encoding.ASCII.GetBytes(SAMPLE);
            BigInteger enc = backdoored.Encrypt(new BigInteger(1, bytes));
            try
            {
                result = recovered.Decrypt(enc).ToByteArray();
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
            return Encoding.ASCII.GetString(result) == SAMPLE;
        }

        static void SpeedTest(int e, int keyLen, int certainty, int seed, bool optimize)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(SAMPLE);
            BigInteger var = new BigInteger(bytes);
            Console.WriteLine("<Speed> test: keyLen = {0}, optimize = {1}", keyLen, optimize);

            DateTime start = DateTime.Now;
            Rsa rsa = new Rsa(BigInteger.ValueOf(e), keyLen, certainty, new Random(seed), optimize);
            BigInteger enc = rsa.Encrypt(var);
            var = rsa.Decrypt(enc);
            TimeSpan timeSpan = DateTime.Now - start;
            
            Console.WriteLine("Time: {0}", timeSpan.TotalMilliseconds);
            GC.Collect();
        }

        static void BackdoorSpeedTest(int e, int keyLen, int certainty, string pubKey)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(SAMPLE);
            BigInteger var = new BigInteger(bytes);
            Console.WriteLine("[Backdoor] <Speed> test: keyLen = {0}", keyLen);

            DateTime start = DateTime.Now;
            Rsa backdoored = RsaBackdoor.Inject(BigInteger.ValueOf(e), keyLen, certainty, StrToBytes(pubKey));
            BigInteger enc = backdoored.Encrypt(var);
            var = backdoored.Decrypt(enc);
            TimeSpan timeSpan = DateTime.Now - start;

            Console.WriteLine("Time: {0}", timeSpan.TotalMilliseconds);
            GC.Collect();
        }

        static byte[] StrToBytes(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
