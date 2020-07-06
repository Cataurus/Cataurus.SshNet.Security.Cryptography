namespace SshNet.Security.Cryptography
{
    internal class SHA384HashProvider : SHA2HashProviderBase
    {
        private const int DigestSize = 48;

        public SHA384HashProvider()
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

            return output;
        }

        /// <summary>
        /// Resets <see cref="SHA384HashProvider"/> to its initial state.
        /// </summary>
        public override void Reset()
        {
            base.Reset();

            InitializeHashValue();
        }

        private void InitializeHashValue()
        {
            /*
             * SHA-384 initial hash value
             * The first 64 bits of the fractional parts of the square roots
             * of the 9th through 16th prime numbers
             */
            H1 = 0xcbbb9d5dc1059ed8;
            H2 = 0x629a292a367cd507;
            H3 = 0x9159015a3070dd17;
            H4 = 0x152fecd8f70e5939;
            H5 = 0x67332667ffc00b31;
            H6 = 0x8eb44a8768581511;
            H7 = 0xdb0c2e0d64f98fa7;
            H8 = 0x47b5481dbefa4fa4;
        }
    }
}
