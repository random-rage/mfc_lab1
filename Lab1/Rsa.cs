using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace Lab1
{
    class Rsa
    {
        public struct RsaParams
        {
            public BigInteger p, q, 
                              e, d, n, 
                              dP, dQ, qInv;
        }

        public static RsaParams GenerateKeys(int e, int keyLen, int certainty, Random rnd)
        {
            RsaParams res = new RsaParams();
            BigInteger  f = BigInteger.One,     // Значение функции Эйлера от n
                      gcd = BigInteger.Zero;    // НОД(e, f)

            res.e = BigInteger.ValueOf(e);      // Устанавливаем e

            do
            {
                // Генерируем p и q
                res.p = new BigInteger(keyLen / 2, certainty, rnd);
                res.q = new BigInteger(keyLen / 2, certainty, rnd);

                if (res.p.CompareTo(res.q) == 0)             // Если они равны, генерируем заново
                    continue;

                res.n = res.p.Multiply(res.q);  // Вычисляем n = p * q

                // Вычисляем значение функции Эйлера от n
                f = (res.p.Subtract(BigInteger.One)).Multiply(res.q.Subtract(BigInteger.One));

                gcd = f.Gcd(res.e);             // Вычисляем НОД(e, f)
            }
            // Если общих делителей у e и f (кроме 1) нет, завершаем генерацию
            while (gcd.CompareTo(BigInteger.One) != 0);

            res.d = res.e.ModInverse(f);        // Вычисляем d = e^(-1) mod f

            // Вычисляем вспомогательные параметры
            res.dP = res.d.Mod(res.p.Subtract(BigInteger.One));
            res.dQ = res.d.Mod(res.q.Subtract(BigInteger.One));
            res.qInv = res.q.ModInverse(res.p);

            return res;
        }

        public static BigInteger Encrypt(BigInteger m, RsaParams param)
        {
            // Если пришло отрицательное число - кидаем исключение
            if (m.SignValue < 0)
                throw new ArgumentOutOfRangeException("m", "Message must be in range [0..N-1]");

            // Шифруем "число" только при условии, что оно меньше модуля
            if (m.CompareTo(param.n) < 0)
                return m.ModPow(param.e, param.n);
            else
                throw new ArgumentOutOfRangeException("m", "Message must be less than N");
        }

        public static BigInteger Decrypt(BigInteger c, RsaParams param)
        {
            // Если пришло отрицательное число - кидаем исключение
            if (c.SignValue < 0)
                throw new ArgumentOutOfRangeException("c", "Encrypted message must be in range [0..N-1]");

            BigInteger m1 = c.ModPow(param.dP, param.p);                    // c ^ (dP) mod p
            BigInteger m2 = c.ModPow(param.dQ, param.q);                    // c ^ (dQ) mod q
            BigInteger dM;

            if (m1.CompareTo(m2) < 0)                                       // m1 < m2 ?
            {
                BigInteger[] divRem = param.q.DivideAndRemainder(param.p);  // q / p

                if (divRem[1].SignValue != 0)                               // [q / p]
                    divRem[0].Add(BigInteger.One);

                dM = divRem[0].Multiply(param.p);                           // [q / p] * p
                dM = dM.Add(m1);                                            // m1 + [q / p] * p
                dM = dM.Subtract(m2);                                       // (m1 + [q / p] * p) - m2
            }
            else
                dM = m1.Subtract(m2);

            BigInteger h = (param.qInv.Multiply(dM)).Mod(param.p);          // (qInv * dM) mod p

            return (h.Multiply(param.q)).Add(m2);                           // m = hq + m2
        }
    }
}
