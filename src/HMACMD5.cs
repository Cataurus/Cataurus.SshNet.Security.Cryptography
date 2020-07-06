namespace SshNet.Security.Cryptography
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) by using the MD5 hash function.
    /// </summary>
    public class HMACMD5 : HMAC
    {
        /// <summary>
        /// Initializes a <see cref="HMACMD5"/> with the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        public HMACMD5(byte[] key)
            : base(new MD5HashProvider(), key)
        {
        }

        /// <summary>
        /// Initializes a <see cref="HMACMD5"/> with the specified key and size of the computed hash code.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="hashSize">The size, in bits, of the computed hash code.</param>
        public HMACMD5(byte[] key, int hashSize)
            : base(new MD5HashProvider(), key, hashSize)
        {
        }

        /// <summary>
        /// Gets or sets the block size, in bytes, to use in the hash value.
        /// </summary>
        /// <value>
        /// The block size to use in the hash value. For <see cref="HMACMD5"/> this is 64 bytes.
        /// </value>
        protected override int BlockSize
        {
            get { return 64; }
        }
    }
}
