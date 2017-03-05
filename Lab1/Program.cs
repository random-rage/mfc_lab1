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
        const int CERTAINTY = 100;
        const string SAMPLE = "This is example text";

        static void Main(string[] args)
        {
            Parallel.For(1, 17, new Action<int>((i) => {
                Console.WriteLine("SelfTest {0}: {1}", i, (RsaSelfTest(E, KEY_SIZE, CERTAINTY, false) ? "passed" : "failed"));
                Console.WriteLine("Test {0}: {1}", i, (RsaTest(E, KEY_SIZE, CERTAINTY)) ? "passed" : "failed");
            }));
            Console.WriteLine("Done!");
            Console.ReadKey();
        }

        static bool RsaTest(int e, int keyLen, int certainty)
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

        static bool RsaSelfTest(int e, int keyLen, int certainty, bool optimize)
        {
            Rsa rsa = new Rsa(e, keyLen, certainty, new Random(), optimize);
            byte[] bytes = Encoding.ASCII.GetBytes(SAMPLE);

            BigInteger enc = rsa.Encrypt(new BigInteger(1, bytes));
            byte[] result = rsa.Decrypt(enc).ToByteArray();

            return Encoding.ASCII.GetString(result) == SAMPLE;
        }
    }
}
