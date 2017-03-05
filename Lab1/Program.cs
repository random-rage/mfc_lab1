using System;
using System.Collections.Generic;
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
        const int CERTAINTY = 2000;

        const string SAMPLE = "This is example text";
        const string PUBLIC_KEY =   "06F1A4EDF328C5E44AD32D5AA33FB7EF10B9A0FEE3AC1D3BA8E2FACD97643A43";
        const string PRIVATE_KEY =  "BDB440EBF1A77CFA014A9CD753F3F6335B1BCDD8ABE30049F10C44243BF3B6C8";

        static void Main(string[] args)
        {
            int i = 0;
            /*try
            {
                Parallel.For(1, 17, new Action<int>((i) =>
                {*/
                    Console.WriteLine("<Self> test {0}: {1}", i,
                        (SelfTest(E, KEY_SIZE, CERTAINTY, false) ? "passed" : "failed"));

                    Console.WriteLine("(Origin) test {0}: {1}", i,
                        (OriginTest(E, KEY_SIZE, CERTAINTY)) ? "passed" : "failed");

                    Console.WriteLine("[Backdoor] test {0}: {1}", i,
                        (BackdoorTest(E, KEY_SIZE, CERTAINTY, PUBLIC_KEY, PRIVATE_KEY)) ? "passed" : "failed");
                /*}));
            }
            catch (AggregateException ex)
            {
                throw ex.InnerException;
            }*/
            Console.WriteLine("Done!");
            Console.ReadKey();
        }

        static bool OriginTest(int e, int keyLen, int certainty)
        {
            Rsa testRsa = new Rsa(e, keyLen, certainty, new Random(), true);
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

        static bool SelfTest(int e, int keyLen, int certainty, bool optimize)
        {
            Rsa rsa = new Rsa(e, keyLen, certainty, new Random(), optimize);
            byte[] bytes = Encoding.ASCII.GetBytes(SAMPLE);

            BigInteger enc = rsa.Encrypt(new BigInteger(1, bytes));
            byte[] result = rsa.Decrypt(enc).ToByteArray();

            return Encoding.ASCII.GetString(result) == SAMPLE;
        }

        static bool BackdoorTest(int e, int keyLen, int certainty, string pubKey, string privKey)
        {
            Rsa backdoored = RsaBackdoor.Inject(E, KEY_SIZE, CERTAINTY, StringToByteArray(pubKey));

            byte[] bytes = Encoding.ASCII.GetBytes(SAMPLE);
            BigInteger enc = backdoored.Encrypt(new BigInteger(1, bytes));

            Rsa recovered = RsaBackdoor.Extract(E, backdoored.Params.n, CERTAINTY, StringToByteArray(privKey));
            byte[] result = recovered.Decrypt(enc).ToByteArray();

            return Encoding.ASCII.GetString(result) == SAMPLE;
        }

        static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
