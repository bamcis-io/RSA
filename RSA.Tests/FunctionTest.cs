using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Xunit;
using Amazon.Lambda.Core;
using Amazon.Lambda.TestUtilities;
using Amazon.Lambda.APIGatewayEvents;

using RSA;
using System.Numerics;

namespace RSA.Tests
{
    public class FunctionTest
    {
        public FunctionTest()
        {
        }

        [Fact]
        public void TestIsPrimeMethod_5()
        {
            // ARRGANGE
            long num = 5;

            // ACT
            bool isPrime = Function.IsPrime(num);

            // ASSERT
            Assert.True(isPrime);
        }

        [Fact]
        public void TestIsPrimeMethod_21()
        {
            // ARRGANGE
            long num = 21;

            // ACT
            bool isPrime = Function.IsPrime(num);

            // ASSERT
            Assert.False(isPrime);
        }

        [Fact]
        public void TestIsPrimeMethod_101()
        {
            // ARRGANGE
            long num = 101;

            // ACT
            bool isPrime = Function.IsPrime(num);

            // ASSERT
            Assert.True(isPrime);
        }

        [Fact]
        public void TestIsPrimeMethod_121()
        {
            // ARRGANGE
            long num = 121;

            // ACT
            bool isPrime = Function.IsPrime(num);

            // ASSERT
            Assert.False(isPrime);
        }

        [Fact]
        public void TestGenerateRSAKey_7_11_29()
        {
            // ARRGANGE
            long prime1 = 7;
            long prime2 = 11;
            long phi = (prime1 - 1) * (prime2 - 1);
            long e = 29;

            // ACT
            RSAEncryptionKey res = RSAEncryptionKey.Generate(prime1, prime2, e);

            // ASSERT
            Assert.True(res.Valid());
            Assert.Equal(29, res.PrivateKey.exponent);
        }

        [Fact]
        public void TestGenerateRSAKey_11_3_3()
        {
            // ARRGANGE
            long prime1 = 11;
            long prime2 = 3;
            long phi = (prime1 - 1) * (prime2 - 1);
            long e = 3;

            // ACT
            RSAEncryptionKey res = RSAEncryptionKey.Generate(prime1, prime2, e);

            // ASSERT
            Assert.True(res.Valid());
            Assert.Equal(7, res.PrivateKey.exponent);

        }

        [Fact]
        public void TestGenerateRSAKey_17_11_5()
        {
            // ARRGANGE
            long prime1 = 17;
            long prime2 = 11;
            long phi = (prime1 - 1) * (prime2 - 1);
            long e = 3;

            // ACT
            RSAEncryptionKey res = RSAEncryptionKey.Generate(prime1, prime2, e);

            // ASSERT
            Assert.True(res.Valid());
        }


        [Fact]
        public void TestEncryption_419_541()
        {
            // ARRGANGE
            BigInteger prime1 = BigInteger.Parse("169196589893712348000524089774153751374745968316288855312110170763798495642113122299037321202930492809766314459262253152562088572376273410530942205297500747698018863211240563250616209447207950324108617281939743126108253476984088930551584883927967880751666536713807442811260180537771984147641735836334890823467");
            BigInteger prime2 = BigInteger.Parse("146931707709476698572127557419647974935209610506870477211159872489392219460492259796201666507218931439514483641212023594788435277341032934823284659066939727630312960778440844569329365679385318080563580926517662466426634367475136186289863173782246073776396162136062760238745439115172895455523758027382280258303");

            // ACT
            RSAEncryptionKey res = RSAEncryptionKey.Generate(prime1, prime2);
            byte[] encrypted = res.Encrypt("TEST");
            string data = res.DecryptAsString(encrypted);

            // ASSERT
            Assert.Equal("TEST", data);
        }

        [Fact]
        public void TestKeyGenBigInt_17_11_3()
        {
            // ARRANGE
            BigInteger prime1 = 17;
            BigInteger prime2 = 11;
            BigInteger phi = (prime1 - 1) * (prime2 - 1);
            long e = 3;

            // ACT
            RSAEncryptionKey key = RSAEncryptionKey.Generate(prime1, prime2, e);

            // ASSERT
            Assert.True(key.Valid());
        }

        [Fact]
        public void TestGenerateRSAKeyBigInt_7_11_29()
        {
            // ARRGANGE
            BigInteger prime1 = 7;
            BigInteger prime2 = 11;
            BigInteger phi = (prime1 - 1) * (prime2 - 1);
            long e = 29;

            // ACT
            RSAEncryptionKey res = RSAEncryptionKey.Generate(prime1, prime2, e);

            // ASSERT
            Assert.True(res.Valid());
            Assert.Equal(29, res.PrivateKey.exponent);
        }

        [Fact]
        public void TestGenerateRSAKeyBigInt_11_3_3()
        {
            // ARRGANGE
            BigInteger prime1 = 11;
            BigInteger prime2 = 3;
            BigInteger phi = (prime1 - 1) * (prime2 - 1);
            long e = 3;

            // ACT
            RSAEncryptionKey res = RSAEncryptionKey.Generate(prime1, prime2, e);

            // ASSERT
            Assert.True(res.Valid());
            Assert.Equal(7, res.PrivateKey.exponent);

        }

        [Fact]
        public void TestGenerateRSAKeyBigInt_17_11_5()
        {
            // ARRGANGE
            BigInteger prime1 = 17;
            BigInteger prime2 = 11;
            BigInteger phi = (prime1 - 1) * (prime2 - 1);
            long e = 3;

            // ACT
            RSAEncryptionKey res = RSAEncryptionKey.Generate(prime1, prime2, e);

            // ASSERT
            Assert.True(res.Valid());
        }

        [Fact]
        public void TestGCD2()
        {
            // ARRANGE
            long num1 = 1432;
            long num2 = 123211;

            // ACT
            RSAEncryptionKey.ExtendedEuclideanGCDResult result = RSAEncryptionKey.ExtendedEuclideanGCD(num1, num2);

            // ASSERT
            Assert.Equal(1, result.GCD);
            Assert.Equal(-22973, result.X);
            Assert.Equal(267, result.Y);
        }
    }
}
