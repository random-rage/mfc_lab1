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

        static void Main(string[] args)
        {
            Parallel.For(1, 17, new Action<int>((i) => 
                Console.WriteLine("Test {0}: {1}", i, (RsaTest(E, KEY_SIZE, CERTAINTY)) ? "passed" : "failed")
            ));
            Console.WriteLine("Done!");
            Console.ReadKey();
        }

        static bool RsaTest(int e, int keyLen, int certainty)
        {
            Rsa.RsaParams testParams = Rsa.GenerateKeys(e, keyLen, certainty, new Random());
            RSACryptoServiceProvider origin = new RSACryptoServiceProvider();
            RSAParameters originParams = new RSAParameters();

            originParams.D = testParams.d.ToByteArrayUnsigned();
            originParams.Exponent = testParams.e.ToByteArrayUnsigned();
            originParams.P = testParams.p.ToByteArrayUnsigned();
            originParams.Q = testParams.q.ToByteArrayUnsigned();
            originParams.DP = testParams.dP.ToByteArrayUnsigned();
            originParams.DQ = testParams.dQ.ToByteArrayUnsigned();
            originParams.InverseQ = testParams.qInv.ToByteArrayUnsigned();
            originParams.Modulus = testParams.n.ToByteArrayUnsigned();
            try
            {
                origin.ImportParameters(originParams);
            }
            catch (CryptographicException)
            {
                return false;
            }

            byte[] testBytes = Encoding.ASCII.GetBytes("This is example text");
            BigInteger src = new BigInteger(1, testBytes);

            byte[] originEnc = origin.Encrypt(testBytes, false);
            BigInteger testEnc = Rsa.Encrypt(src, testParams);

            byte[] originDec = origin.Decrypt(originEnc, false);
            BigInteger testDec = Rsa.Decrypt(testEnc, testParams);

            return Encoding.ASCII.GetString(testDec.ToByteArray()) == 
                   Encoding.ASCII.GetString(originDec);
        }
    }
}
