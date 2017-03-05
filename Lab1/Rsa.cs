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

        private RsaParams _p;
        private bool _optimize;

        public RsaParams Params
        {
            get { return _p; }
            set { _p = value; }
        }

        public Rsa(bool optimize = true)
        {
            _optimize = optimize;
        }

        public Rsa(int e, int keyLen, int certainty, Random rnd, bool optimize = true)
        {
            _optimize = optimize;
            BigInteger  f = BigInteger.One,     // Значение функции Эйлера от n
                      gcd = BigInteger.Zero;    // НОД(e, f)

            _p.e = BigInteger.ValueOf(e);      // Устанавливаем e

            do
            {
                // Генерируем p и q
                _p.p = new BigInteger(keyLen / 2, certainty, rnd);
                _p.q = new BigInteger(keyLen / 2, certainty, rnd);

                if (_p.p.CompareTo(_p.q) == 0)             // Если они равны, генерируем заново
                    continue;

                _p.n = _p.p.Multiply(_p.q);  // Вычисляем n = p * q

                // Вычисляем значение функции Эйлера от n
                f = (_p.p.Subtract(BigInteger.One)).Multiply(_p.q.Subtract(BigInteger.One));

                gcd = f.Gcd(_p.e);             // Вычисляем НОД(e, f)
            }
            // Если общих делителей у e и f (кроме 1) нет, завершаем генерацию
            while (gcd.CompareTo(BigInteger.One) != 0);

            _p.d = _p.e.ModInverse(f);        // Вычисляем d = e^(-1) mod f

            if (_optimize)
            {
                // Вычисляем вспомогательные параметры
                _p.dP = _p.d.Mod(_p.p.Subtract(BigInteger.One));
                _p.dQ = _p.d.Mod(_p.q.Subtract(BigInteger.One));
                _p.qInv = _p.q.ModInverse(_p.p);
            }
        }

        public BigInteger Encrypt(BigInteger m)
        {
            // Если пришло отрицательное число - кидаем исключение
            if (m.SignValue < 0)
                throw new ArgumentOutOfRangeException("m", "Message must be in range [0..N-1]");

            // Шифруем "число" только при условии, что оно меньше модуля
            if (m.CompareTo(_p.n) < 0)
                return m.ModPow(_p.e, _p.n);
            else
                throw new ArgumentOutOfRangeException("m", "Message must be less than N");
        }

        public BigInteger Decrypt(BigInteger c)
        {
            // Если пришло отрицательное число - кидаем исключение
            if (c.SignValue < 0)
                throw new ArgumentOutOfRangeException("c", "Ciphertext must be in range [0..N-1]");

            // Расшифровываем "число" только при условии, что оно меньше модуля
            if (c.CompareTo(_p.n) >= 0)
                throw new ArgumentOutOfRangeException("c", "Ciphertext must be less than N");

            // Использовать оптимизацию с китайской теоремой об остатках?
            if (_optimize)
            {
                BigInteger m1 = c.ModPow(_p.dP, _p.p);                  // c ^ (dP) mod p
                BigInteger m2 = c.ModPow(_p.dQ, _p.q);                  // c ^ (dQ) mod q
                BigInteger dM;

                if (m1.CompareTo(m2) < 0)                               // m1 < m2 ?
                {
                    BigInteger[] divRem = _p.q.DivideAndRemainder(_p.p);    // q / p

                    if (divRem[1].SignValue != 0)                       // [q / p]
                        divRem[0].Add(BigInteger.One);

                    dM = divRem[0].Multiply(_p.p);                      // [q / p] * p
                    dM = dM.Add(m1);                                    // m1 + [q / p] * p
                    dM = dM.Subtract(m2);                               // (m1 + [q / p] * p) - m2
                }
                else
                    dM = m1.Subtract(m2);

                BigInteger h = (_p.qInv.Multiply(dM)).Mod(_p.p);        // (qInv * dM) mod p

                return (h.Multiply(_p.q)).Add(m2);                      // m = hq + m2
            }
            else
                return c.ModPow(_p.d, _p.n);
        }
    }
}
