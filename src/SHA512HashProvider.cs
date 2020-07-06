namespace SshNet.Security.Cryptography
{
    internal class SHA512HashProvider : SHA2HashProviderBase
    {
        private const int DigestSize = 64;

        public SHA512HashProvider()
        {
            InitializeHashValue();
        }

        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <returns>
        /// The size, in bits, of the computed hash code.
        /// </returns>
        public override int HashSize
        {
            get
            {
                return DigestSize * 8;
            }
        }

        /// <summary>
        /// When overridden in a derived class, gets the input block size.
        /// </summary>
        /// <returns>
        /// The input block size.
        /// </returns>
        public override int InputBlockSize
        {
            get
            {
                return DigestSize * 2;
            }
        }

        /// <summary>
        /// When overridden in a derived class, gets the output block size.
        /// </summary>
        /// <returns>
        /// The output block size.
        /// </returns>
        public override int OutputBlockSize
        {
            get
            {
                return DigestSize * 2;
            }
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        public override byte[] HashFinal()
        {
            var output = new byte[DigestSize];

            Finish();

            UInt64_To_BE(H1, output, 0);
            UInt64_To_BE(H2, output, 8);
            UInt64_To_BE(H3, output, 16);
            UInt64_To_BE(H4, output, 24);
            UInt64_To_BE(H5, output, 32);
            UInt64_To_BE(H6, output, 40);
            UInt64_To_BE(H7, output, 48);
            UInt64_To_BE(H8, output, 56);

            return output;
        }

        /// <summary>
        /// Resets <see cref="SHA512HashProvider"/> to its initial state.
        /// </summary>
        public override void Reset()
        {
            base.Reset();

            InitializeHashValue();
        }

        private void InitializeHashValue()
        {
            /*
             * SHA-512 initial hash value
             * The first 64 bits of the fractional parts of the square roots
             * of the first eight prime numbers
             */
            H1 = 0x6a09e667f3bcc908;
            H2 = 0xbb67ae8584caa73b;
            H3 = 0x3c6ef372fe94f82b;
            H4 = 0xa54ff53a5f1d36f1;
            H5 = 0x510e527fade682d1;
            H6 = 0x9b05688c2b3e6c1f;
            H7 = 0x1f83d9abfb41bd6b;
            H8 = 0x5be0cd19137e2179;
        }
    }
}
