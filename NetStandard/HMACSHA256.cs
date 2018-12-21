namespace SshNet.Security.Cryptography
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) by using the <see cref="HMACSHA256"/> hash function.
    /// </summary>
    public class HMACSHA256 : HMAC
    {
        /// <summary>
        /// Initializes a <see cref="HMACSHA256"/> with the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        public HMACSHA256(byte[] key)
            : base(new SHA256HashProvider(), key)
        {
        }

        /// <summary>
        /// Initializes a <see cref="HMACSHA256"/> with the specified key and size of the computed hash code.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="hashSize">The size, in bits, of the computed hash code.</param>
        public HMACSHA256(byte[] key, int hashSize)
            : base(new SHA256HashProvider(), key, hashSize)
        {
        }

        /// <summary>
        /// Gets or sets the block size, in bytes, to use in the hash value.
        /// </summary>
        /// <value>
        /// The block size to use in the hash value. For <see cref="HMACSHA256"/> this is 64 bytes.
        /// </value>
        protected override int BlockSize
        {
            get { return 64; }
        }
    }
}
