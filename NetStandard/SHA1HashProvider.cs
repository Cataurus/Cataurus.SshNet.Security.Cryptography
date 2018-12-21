using System;

namespace SshNet.Security.Cryptography
{
    /// <summary>
    /// Implements SHA-1.
    /// </summary>
    /// <remarks>
    /// Based on <c>https://tools.ietf.org/html/rfc3174</c>.
    /// </remarks>
    internal class SHA1HashProvider : HashProviderBase
    {
        /// <summary>
        /// The size of the digest in bytes.
        /// </summary>
        private const int DigestSize = 20;

        /// <summary>
        /// The block size in bytes.
        /// </summary>
        private const int BlockSize = 64;

        /// <summary>
        /// Constant word to be used on index 0 to 19 of the word sequence.
        /// </summary>
        private const uint Y1 = 0x5a827999;

        /// <summary>
        /// Constant word to be used on index 20 to 39 of the word sequence.
        /// </summary>
        private const uint Y2 = 0x6ed9eba1;

        /// <summary>
        /// Constant word to be used on index 40 to 59 of the word sequence.
        /// </summary>
        private const uint Y3 = 0x8f1bbcdc;

        /// <summary>
        /// Constant word to be used on index 60 to 79 of the word sequence.
        /// </summary>
        private const uint Y4 = 0xca62c1d6;

        private uint _h1, _h2, _h3, _h4, _h5;

        /// <summary>
        /// The word sequence.
        /// </summary>
        private readonly uint[] _words;

        /// <summary>
        /// Buffered bytes.
        /// </summary>
        private readonly byte[] _buffer;

        /// <summary>
        /// The number of bytes in the buffer.
        /// </summary>
        private int _bufferByteCount;

        /// <summary>
        /// The number of bytes in the message.
        /// </summary>
        private long _messageByteCount;

        /// <summary>
        /// Initializes a new instance of the <see cref="SHA1"/> class.
        /// </summary>
        public SHA1HashProvider()
        {
            _buffer = new byte[BlockSize];
            _words = new uint[80];

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
        /// Gets the input block size.
        /// </summary>
        /// <returns>
        /// The input block size.
        /// </returns>
        public override int InputBlockSize
        {
            get
            {
                return BlockSize;
            }
        }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        /// <returns>
        /// The output block size.
        /// </returns>
        public override int OutputBlockSize
        {
            get
            {
                return BlockSize;
            }
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        public override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _messageByteCount += cbSize;

            // when there's an incomplete block, then complete and process it
            if (_bufferByteCount > 0 && (cbSize + _bufferByteCount) >= BlockSize)
            {
                var bytesToCopy = BlockSize - _bufferByteCount;
                Buffer.BlockCopy(array, ibStart, _buffer, _bufferByteCount, bytesToCopy);

                // process complete block
                ProcessBlock(_buffer, 0);

                ibStart += bytesToCopy;
                cbSize -= bytesToCopy;

                // we've processed all buffered bytes
                _bufferByteCount = 0;
            }

            // process whole blocks
            while (cbSize >= BlockSize)
            {
                ProcessBlock(array, ibStart);

                ibStart += BlockSize;
                cbSize -= BlockSize;
            }

            // buffer remaining bytes
            if (cbSize > 0)
            {
                Buffer.BlockCopy(array, ibStart, _buffer, _bufferByteCount, cbSize);
                _bufferByteCount += cbSize;
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

            // capture message length in bytes before padding
            var bitLength = (_messageByteCount << 3);

            // total length of the padded message must be a multiple of the block size (64 bytes)
            var paddingLength = BlockSize - (_messageByteCount % BlockSize);

            // ensure padding can contain 64-bit integer representing the message length
            // if necessary another block must be added
            if (paddingLength <= 8)
                paddingLength += BlockSize;

            // construct buffer for holding the padding
            var padding = new byte[paddingLength];

            // the first bit of the padding must be "1", so we use 0x80 as first byte (or 1000 0000 in bits)
            padding[0] = 0x80;

            // add message length to padding buffer as final 8 bytes
            UInt64ToBigEndian((ulong) bitLength, padding, padding.Length - 8);

            // complete block(s)
            HashCore(padding, 0, padding.Length);

            // write hash to digest
            UInt32ToBigEndian(_h1, output, 0);
            UInt32ToBigEndian(_h2, output, 4);
            UInt32ToBigEndian(_h3, output, 8);
            UInt32ToBigEndian(_h4, output, 12);
            UInt32ToBigEndian(_h5, output, 16);

            return output;
        }

        /// <summary>
        /// Resets <see cref="SHA1HashProvider"/> to its initial state.
        /// </summary>
        public override void Reset()
        {
            InitializeHashValue();

            _messageByteCount = 0;

            _bufferByteCount = 0;
            for (var i = 0; i < _buffer.Length; i++)
            {
                _buffer[i] = 0;
            }

            for (var i = 0; i != _words.Length; i++)
            {
                _words[i] = 0;
            }
        }

        private void InitializeHashValue()
        {
            _h1 = 0x67452301;
            _h2 = 0xefcdab89;
            _h3 = 0x98badcfe;
            _h4 = 0x10325476;
            _h5 = 0xc3d2e1f0;
        }

        private static uint F(uint u, uint v, uint w)
        {
            return (u & v) | (~u & w);
        }

        private static uint H(uint u, uint v, uint w)
        {
            return u ^ v ^ w;
        }

        private static uint G(uint u, uint v, uint w)
        {
            return (u & v) | (u & w) | (v & w);
        }

        private void ProcessBlock(byte[] buffer, int offset)
        {
            for (var i = 0; i < 16; i++)
            {
                _words[i] = BigEndianToUInt32(buffer, offset);
                offset += 4;
            }

            //
            // expand 16 word block into 80 word block.
            //
            for (var i = 16; i < 80; i++)
            {
                var t = _words[i - 3] ^ _words[i - 8] ^ _words[i - 14] ^ _words[i - 16];
                _words[i] = t << 1 | t >> 31;
            }

            //
            // set up working variables.
            //
            var a = _h1;
            var b = _h2;
            var c = _h3;
            var d = _h4;
            var e = _h5;

            var idx = 0;

            //
            // round 1
            //

            for (var i = 0; i < 4; i++)
            {
                e += (a << 5 | (a >> 27)) + F(b, c, d) + _words[idx++] + Y1;
                b = b << 30 | (b >> 2);

                d += (e << 5 | (e >> 27)) + F(a, b, c) + _words[idx++] + Y1;
                a = a << 30 | (a >> 2);

                c += (d << 5 | (d >> 27)) + F(e, a, b) + _words[idx++] + Y1;
                e = e << 30 | (e >> 2);

                b += (c << 5 | (c >> 27)) + F(d, e, a) + _words[idx++] + Y1;
                d = d << 30 | (d >> 2);

                a += (b << 5 | (b >> 27)) + F(c, d, e) + _words[idx++] + Y1;
                c = c << 30 | (c >> 2);
            }

            //
            // round 2
            //

            for (var i = 0; i < 4; i++)
            {
                e += (a << 5 | (a >> 27)) + H(b, c, d) + _words[idx++] + Y2;
                b = b << 30 | (b >> 2);

                d += (e << 5 | (e >> 27)) + H(a, b, c) + _words[idx++] + Y2;
                a = a << 30 | (a >> 2);

                c += (d << 5 | (d >> 27)) + H(e, a, b) + _words[idx++] + Y2;
                e = e << 30 | (e >> 2);

                b += (c << 5 | (c >> 27)) + H(d, e, a) + _words[idx++] + Y2;
                d = d << 30 | (d >> 2);

                a += (b << 5 | (b >> 27)) + H(c, d, e) + _words[idx++] + Y2;
                c = c << 30 | (c >> 2);
            }

            //
            // round 3
            //

            for (var i = 0; i < 4; i++)
            {
                e += (a << 5 | (a >> 27)) + G(b, c, d) + _words[idx++] + Y3;
                b = b << 30 | (b >> 2);

                d += (e << 5 | (e >> 27)) + G(a, b, c) + _words[idx++] + Y3;
                a = a << 30 | (a >> 2);

                c += (d << 5 | (d >> 27)) + G(e, a, b) + _words[idx++] + Y3;
                e = e << 30 | (e >> 2);

                b += (c << 5 | (c >> 27)) + G(d, e, a) + _words[idx++] + Y3;
                d = d << 30 | (d >> 2);

                a += (b << 5 | (b >> 27)) + G(c, d, e) + _words[idx++] + Y3;
                c = c << 30 | (c >> 2);
            }

            //
            // round 4
            //

            for (var i = 0; i < 4; i++)
            {
                e += (a << 5 | (a >> 27)) + H(b, c, d) + _words[idx++] + Y4;
                b = b << 30 | (b >> 2);

                d += (e << 5 | (e >> 27)) + H(a, b, c) + _words[idx++] + Y4;
                a = a << 30 | (a >> 2);

                c += (d << 5 | (d >> 27)) + H(e, a, b) + _words[idx++] + Y4;
                e = e << 30 | (e >> 2);

                b += (c << 5 | (c >> 27)) + H(d, e, a) + _words[idx++] + Y4;
                d = d << 30 | (d >> 2);

                a += (b << 5 | (b >> 27)) + H(c, d, e) + _words[idx++] + Y4;
                c = c << 30 | (c >> 2);
            }

            _h1 += a;
            _h2 += b;
            _h3 += c;
            _h4 += d;
            _h5 += e;
        }

        private static uint BigEndianToUInt32(byte[] bs, int off)
        {
            var n = (uint) bs[off] << 24;
            n |= (uint) bs[++off] << 16;
            n |= (uint) bs[++off] << 8;
            n |= bs[++off];

            return n;
        }

        /// <summary>
        /// Populates buffer with big endian number representation.
        /// </summary>
        /// <param name="number">The number to convert.</param>
        /// <param name="buffer">The buffer.</param>
        /// <param name="offset">The buffer offset.</param>
        private static void UInt32ToBigEndian(uint number, byte[] buffer, int offset)
        {
            buffer[offset] = (byte) (number >> 24);
            buffer[offset + 1] = (byte) (number >> 16);
            buffer[offset + 2] = (byte) (number >> 8);
            buffer[offset + 3] = (byte) (number);
        }

        /// <summary>
        /// Populates buffer with big endian number representation.
        /// </summary>
        /// <param name="number">The number to convert.</param>
        /// <param name="buffer">The buffer.</param>
        /// <param name="offset">The buffer offset.</param>
        private static void UInt64ToBigEndian(ulong number, byte[] buffer, int offset)
        {
            UInt32ToBigEndian((uint) (number >> 32), buffer, offset);
            UInt32ToBigEndian((uint) (number), buffer, offset + 4);
        }
    }
}
