namespace SshNet.Security.Cryptography
{
    internal abstract class SHA2HashProviderBase : HashProviderBase
    {
        /// <summary>
        /// Initial hash value 1.
        /// </summary>
        protected ulong H1;

        /// <summary>
        /// Initial hash value 2.
        /// </summary>
        protected ulong H2;

        /// <summary>
        /// Initial hash value 3.
        /// </summary>
        protected ulong H3;

        /// <summary>
        /// Initial hash value 4.
        /// </summary>
        protected ulong H4;

        /// <summary>
        /// Initial hash value 5.
        /// </summary>
        protected ulong H5;

        /// <summary>
        /// Initial hash value 6.
        /// </summary>
        protected ulong H6;

        /// <summary>
        /// Initial hash value 7.
        /// </summary>
        protected ulong H7;

        /// <summary>
        /// Initial hash value 8.
        /// </summary>
        protected ulong H8;

        /// <summary>
        /// The word buffer.
        /// </summary>
        private readonly ulong[] _x;
        private int _offset;
        private readonly byte[] _buffer;
        private int _bufferOffset;
        private long _byteCount1;
        private long _byteCount2;

        /// <summary>
        /// Initializes a new instance of the <see cref="SHA2HashProviderBase" /> class.
        /// </summary>
        protected SHA2HashProviderBase()
        {
            _x = new ulong[80];
            _buffer = new byte[8];
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        public override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            // Fill the current word
            while ((_bufferOffset != 0) && (cbSize > 0))
            {
                Update(array[ibStart]);

                ibStart++;
                cbSize--;
            }

            // Process whole words.
            while (cbSize > _buffer.Length)
            {
                ProcessWord(array, ibStart);

                ibStart += _buffer.Length;
                cbSize -= _buffer.Length;
                _byteCount1 += _buffer.Length;
            }

            // Load in the remainder.
            while (cbSize > 0)
            {
                Update(array[ibStart]);

                ibStart++;
                cbSize--;
            }
        }

        /// <summary>
        /// Resets a <see cref="SHA2HashProviderBase"/> class to its initial state.
        /// </summary>
        public override void Reset()
        {
            _byteCount1 = 0;
            _byteCount2 = 0;

            _bufferOffset = 0;

            // for small arrays (up to 100), Array.Clear is less performant:
            // http://manski.net/2012/12/net-array-clear-vs-arrayx-0-performance/
            for (var i = 0; i < _buffer.Length; i++)
            {
                _buffer[i] = 0;
            }

            _offset = 0;

            // for small arrays (up to 100), Array.Clear is less performant:
            // http://manski.net/2012/12/net-array-clear-vs-arrayx-0-performance/
            for (var i = 0; i < _x.Length; i++)
            {
                _x[i] = 0;
            }
        }

        /// <summary>
        /// Finalizes the hash computation.
        /// </summary>
        protected void Finish()
        {
            AdjustByteCounts();

            var lowBitLength = _byteCount1 << 3;
            var hiBitLength = _byteCount2;

            //
            // add the pad bytes.
            //
            Update(128);

            while (_bufferOffset != 0)
            {
                Update(0);
            }

            ProcessLength(lowBitLength, hiBitLength);

            ProcessBlock();
        }

        private void Update(byte input)
        {
            _buffer[_bufferOffset++] = input;

            if (_bufferOffset == _buffer.Length)
            {
                ProcessWord(_buffer, 0);
                _bufferOffset = 0;
            }

            _byteCount1++;
        }

        private void ProcessWord(byte[] input, int inOff)
        {
            _x[_offset] = BE_To_UInt64(input, inOff);

            if (++_offset == 16)
            {
                ProcessBlock();
            }
        }

        internal void ProcessLength(long lowW, long hiW)
        {
            if (_offset > 14)
            {
                ProcessBlock();
            }

            _x[14] = (ulong)hiW;
            _x[15] = (ulong)lowW;
        }

        private void ProcessBlock()
        {
            AdjustByteCounts();

            //
            // expand 16 word block into 80 word blocks.
            //
            for (var ti = 16; ti <= 79; ++ti)
            {
                _x[ti] = Sigma1(_x[ti - 2]) + _x[ti - 7] + Sigma0(_x[ti - 15]) + _x[ti - 16];
            }

            //
            // set up working variables.
            //
            var a = H1;
            var b = H2;
            var c = H3;
            var d = H4;
            var e = H5;
            var f = H6;
            var g = H7;
            var h = H8;

            var t = 0;
            for (var i = 0; i < 10; i++)
            {
                // t = 8 * i
                h += Sum1(e) + Ch(e, f, g) + K[t] + _x[t++];
                d += h;
                h += Sum0(a) + Maj(a, b, c);

                // t = 8 * i + 1
                g += Sum1(d) + Ch(d, e, f) + K[t] + _x[t++];
                c += g;
                g += Sum0(h) + Maj(h, a, b);

                // t = 8 * i + 2
                f += Sum1(c) + Ch(c, d, e) + K[t] + _x[t++];
                b += f;
                f += Sum0(g) + Maj(g, h, a);

                // t = 8 * i + 3
                e += Sum1(b) + Ch(b, c, d) + K[t] + _x[t++];
                a += e;
                e += Sum0(f) + Maj(f, g, h);

                // t = 8 * i + 4
                d += Sum1(a) + Ch(a, b, c) + K[t] + _x[t++];
                h += d;
                d += Sum0(e) + Maj(e, f, g);

                // t = 8 * i + 5
                c += Sum1(h) + Ch(h, a, b) + K[t] + _x[t++];
                g += c;
                c += Sum0(d) + Maj(d, e, f);

                // t = 8 * i + 6
                b += Sum1(g) + Ch(g, h, a) + K[t] + _x[t++];
                f += b;
                b += Sum0(c) + Maj(c, d, e);

                // t = 8 * i + 7
                a += Sum1(f) + Ch(f, g, h) + K[t] + _x[t++];
                e += a;
                a += Sum0(b) + Maj(b, c, d);
            }

            H1 += a;
            H2 += b;
            H3 += c;
            H4 += d;
            H5 += e;
            H6 += f;
            H7 += g;
            H8 += h;

            //
            // reset the offset and clean out the word buffer.
            //
            _offset = 0;

            // for small arrays (up to 100), Array.Clear is less performant:
            // http://manski.net/2012/12/net-array-clear-vs-arrayx-0-performance/
            for (var i = 0; i < _x.Length; i++)
            {
                _x[i] = 0;
            }
        }

        /// <summary>
        /// Adjust the byte counts so that byteCount2 represents the upper long (less 3 bits) word of the byte count.
        /// </summary>
        private void AdjustByteCounts()
        {
            if (_byteCount1 > 0x1fffffffffffffffL)
            {
                _byteCount2 += (long)((ulong)_byteCount1 >> 61);
                _byteCount1 &= 0x1fffffffffffffffL;
            }
        }

        /* SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */
        private static ulong Ch(ulong x, ulong y, ulong z)
        {
            return (x & y) ^ (~x & z);
        }

        private static ulong Maj(ulong x, ulong y, ulong z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        private static ulong Sum0(ulong x)
        {
            return ((x << 36) | (x >> 28)) ^ ((x << 30) | (x >> 34)) ^ ((x << 25) | (x >> 39));
        }

        private static ulong Sum1(ulong x)
        {
            return ((x << 50) | (x >> 14)) ^ ((x << 46) | (x >> 18)) ^ ((x << 23) | (x >> 41));
        }

        private static ulong Sigma0(ulong x)
        {
            return ((x << 63) | (x >> 1)) ^ ((x << 56) | (x >> 8)) ^ (x >> 7);
        }

        private static ulong Sigma1(ulong x)
        {
            return ((x << 45) | (x >> 19)) ^ ((x << 3) | (x >> 61)) ^ (x >> 6);
        }

        /* SHA-384 and SHA-512 Constants
         * (represent the first 64 bits of the fractional parts of the
         * cube roots of the first sixty-four prime numbers)
         */
        private static readonly ulong[] K =
        {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        private static void UInt32_To_BE(uint n, byte[] bs, int offset)
        {
            bs[offset] = (byte)(n >> 24);
            bs[++offset] = (byte)(n >> 16);
            bs[++offset] = (byte)(n >> 8);
            bs[++offset] = (byte)(n);
        }

        protected static void UInt64_To_BE(ulong n, byte[] bs, int offset)
        {
            UInt32_To_BE((uint)(n >> 32), bs, offset);
            UInt32_To_BE((uint)(n), bs, offset + 4);
        }

        private static ulong BE_To_UInt64(byte[] bs, int offset)
        {
            var hi = BE_To_UInt32(bs, offset);
            var lo = BE_To_UInt32(bs, offset + 4);
            return ((ulong)hi << 32) | lo;
        }

        private static uint BE_To_UInt32(byte[] bs, int offset)
        {
            var n = (uint)bs[offset] << 24;
            n |= (uint)bs[++offset] << 16;
            n |= (uint)bs[++offset] << 8;
            n |= bs[++offset];
            return n;
        }
    }
}
