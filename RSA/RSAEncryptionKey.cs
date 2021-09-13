using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace RSA
{
    public class RSAEncryptionKey
    {
        public RSAPublicKey PublicKey { get; set; }
        public RSAPrivateKey PrivateKey { get; set; }

        public class RSAPublicKey
        {
            public BigInteger modulus { get; set; }
            public BigInteger exponent { get; set; }
        }

        public class RSAPrivateKey
        {
            public BigInteger exponent { get; set; }
            public BigInteger p { get; set; }

            public BigInteger q { get; set; }
        }

        #region Public Methods

        #region Encrypt/Decrypt Methods

        public byte[] Encrypt(string data, Encoding encoding = null)
        {
            if (encoding == null)
            {
                encoding = Encoding.UTF8;
            }

            return Encrypt(encoding.GetBytes(data));
        }

        public byte[] Encrypt(byte[] data)
        {
            //byte[] encrypted = new byte[data.Length];

            /*
            for (int i = 0; i < data.Length; i++)
            {
                byte dat = (byte)(data[i] % this.PublicKey.modulus);

                for (long j = 1; j <= this.PublicKey.exponent; j++)
                {
                    dat = (byte)((dat * dat) % this.PublicKey.modulus);
                }

                encrypted[i] = dat;
            }
            */
            BigInteger b = new BigInteger(data);
            BigInteger e = BigInteger.ModPow(b, this.PublicKey.exponent, this.PublicKey.modulus);

            return e.ToByteArray();
        }

        public string DecryptAsString(byte[] data, Encoding encoding = null)
        {
            if (encoding == null)
            {
                encoding = Encoding.UTF8;
            }

            return encoding.GetString(Decrypt(data));
        }

        public byte[] Decrypt(byte[] data)
        {
            /*
            byte[] temp = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                byte dat = data[i];

                for (long j = 1; j <= this.PrivateKey.exponent; j++)
                {
                    dat = (byte)((dat * dat) % this.PublicKey.modulus);
                }

                temp[i] = dat;
            }

            return temp;
            */
            BigInteger e = new BigInteger(data);
            BigInteger d = BigInteger.ModPow(e, this.PrivateKey.exponent, this.PublicKey.modulus);

            return d.ToByteArray();
        }

        #endregion       

        #region Static Generate Methods

        public static RSAEncryptionKey Generate(BigInteger p, BigInteger q)
        {
            // Choose e such that 1 < e < ϕ  and gcd(e, ϕ) = 1
            // e is the public key (public exponent)
            long e = ChoosePublicKey(p, q);

            return Generate(p, q, e);
        }

        public static RSAEncryptionKey Generate(BigInteger p, BigInteger q, long e)
        {
            // n = pq
            BigInteger n = p * q;

            // ϕ = (p - 1)(q - 1)
            BigInteger phi = (p - 1) * (q - 1);

            // Compute the secret exponent d
            // 1 < d < ϕ such that ed ≡ 1 mod ϕ
            ExtendedEuclideanGCDResult result = ExtendedEuclideanGCD(e, phi);
            BigInteger d = result.X < 0 ? (result.X + phi) : result.X;

            // Public key is (n, e) and private key is (d, p, q)
            // n = modulus
            // e = public exponent
            // d = secret exponent

            return new RSAEncryptionKey()
            {
                PublicKey = new RSAPublicKey()
                {
                    exponent = e,
                    modulus = n
                },
                PrivateKey = new RSAPrivateKey()
                {
                    p = p,
                    q = q,
                    exponent = d
                }
            };
        }

        public static RSAEncryptionKey Generate(long p, long q)
        {
            // Choose e such that 1 < e < ϕ  and gcd(e, ϕ) = 1
            // e is the public key (public exponent)
            long e = ChoosePublicKey(p, q);

            return Generate(p, q, e);
        }

        public static RSAEncryptionKey Generate(long p, long q, long e)
        {
            // n = pq
            long n = p * q;

            // ϕ = (p - 1)(q - 1)
            long phi = (p - 1) * (q - 1);

            // Compute the secret exponent d
            // 1 < d < ϕ such that ed ≡ 1 mod ϕ
            ExtendedEuclideanGCDResult result = ExtendedEuclideanGCD(e, phi);
            long d = result.X < 0 ? (long)result.X + phi : (long)result.X;

            // Public key is (n, e) and private key is (d, p, q)
            // n = modulus
            // e = public exponent
            // d = secret exponent

            return new RSAEncryptionKey()
            {
                PublicKey = new RSAPublicKey()
                {
                    exponent = e,
                    modulus = n
                },
                PrivateKey = new RSAPrivateKey()
                {
                    p = p,
                    q = q,
                    exponent = d
                }
            };
        }

        #endregion

        #region Euclidean GCD Methods

        /// <summary>
        /// Non-Recursive Implementation of the Extended Euclidean algorithm
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static ExtendedEuclideanGCDResult ExtendedEuclideanGCD(long a, long b)
        {
            // In case b is 0, a is the GCD
            if (b == 0) return new ExtendedEuclideanGCDResult() { GCD = a, X = 1, Y = 0 };
            if (a == 0) return new ExtendedEuclideanGCDResult() { GCD = b, X = 1, Y = 0 };

            long x = 0;
            long previousX = 1;

            long y = 1;
            long previousY = 0;
            long quotient;
            long tempX;
            long tempY;
            long tempA;

            while (b != 0)
            {
                quotient = a / b;

                tempX = x;
                x = previousX - (quotient * x);
                previousX = tempX;

                tempY = y;
                y = previousY - (quotient * y);
                previousY = tempY;

                tempA = a;
                a = b;
                b = tempA % b;
            }

            return new ExtendedEuclideanGCDResult()
            {
                GCD = a,
                X = previousX,
                Y = previousY
            };
        }

        /// <summary>
        /// Non-Recursive Implementation of the Extended Euclidean algorithm
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static ExtendedEuclideanGCDResult ExtendedEuclideanGCD(BigInteger a, BigInteger b)
        {
            // In case b is 0, a is the GCD
            if (b == 0) return new ExtendedEuclideanGCDResult() { GCD = a, X = 1, Y = 0 };
            if (a == 0) return new ExtendedEuclideanGCDResult() { GCD = b, X = 1, Y = 0 };

            BigInteger x = 0;
            BigInteger previousX = 1;

            BigInteger y = 1;
            BigInteger previousY = 0;
            BigInteger quotient;
            BigInteger tempX;
            BigInteger tempY;
            BigInteger tempA;

            while (b != 0)
            {
                quotient = a / b;

                tempX = x;
                x = previousX - (quotient * x);
                previousX = tempX;

                tempY = y;
                y = previousY - (quotient * y);
                previousY = tempY;

                tempA = a;
                a = b;
                b = tempA % b;
            }

            return new ExtendedEuclideanGCDResult()
            {
                GCD = a,
                X = previousX,
                Y = previousY
            };
        }

        #endregion

        public bool Valid()
        {
            return (this.PublicKey.exponent * this.PrivateKey.exponent) % ((this.PrivateKey.q - 1) * (this.PrivateKey.p - 1)) == 1;
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// e must be 2 < e < n for PCKS#1 v2.2
        /// 
        /// </summary>
        /// <param name="phi"></param>
        /// <param name="p"></param>
        /// <param name="q"></param>
        /// <returns></returns>
        private static long ChoosePublicKey(long p, long q)
        {
            long[] standardValues = { 65537, 2737, 257, 17, 5, 3 };
            long n = p * q;
            long phi = (p - 1) * (q - 1);

            for (int i = 0; i < standardValues.Length; i++)
            {
                long val = standardValues[i];
                if (val < phi && IsCoPrime(val, phi))
                {
                    return val;
                }
            }

            return 0;
        }

        /// <summary>
        /// e must be 2 < e < n for PCKS#1 v2.2
        /// 
        /// </summary>
        /// <param name="phi"></param>
        /// <param name="p"></param>
        /// <param name="q"></param>
        /// <returns></returns>
        private static long ChoosePublicKey(BigInteger p, BigInteger q)
        {
            long[] standardValues = { 65537, 257, 17, 5, 3 };
            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            for (int i = 0; i < standardValues.Length; i++)
            {
                long val = standardValues[i];
                if (val < phi && IsCoPrime(val, phi))
                {
                    return val;
                }
            }

            return 0;
        }

        private static bool IsCoPrime(long num, long phi)
        {
            List<long> factors = GetFactors(phi).ToList();
            bool isCoPrime = false;

            if (num % phi != 0)
            {
                bool divisible = false;

                foreach (long factor in factors)
                {
                    if (num % factor == 0)
                    {
                        divisible = true;
                        break;
                    }
                }

                if (divisible == false)
                {
                    isCoPrime = true;
                }
            }

            return isCoPrime;
        }

        private static bool IsCoPrime(long num, BigInteger phi)
        {
            return BigInteger.Remainder(num, phi) != 0 && BigInteger.Remainder(phi, num) != 0;          
        }

        private static IEnumerable<long> GetFactors(long number)
        {
            if (number <= 1) yield break;

            long boundary = (long)Math.Floor((double)(number / 2));

            for (long i = 2; i <= boundary; i++)
            {
                if (number % i == 0)
                {
                    yield return i;
                }
            }
        }

        private static IEnumerable<BigInteger> GetFactors(BigInteger number)
        {
            if (number <= 1) yield break;

            BigInteger boundary = BigInteger.Divide(number, 2); // return quotient

            for (BigInteger i = 2; i <= boundary; i++)
            {
                if (number % i == 0)
                {
                    yield return i;
                }
            }
        }

        #endregion

        public class ExtendedEuclideanGCDResult
        {
            public BigInteger GCD { get; set; }
            public BigInteger X { get; set; }

            public BigInteger Y { get; set; }
        }
    }
}
