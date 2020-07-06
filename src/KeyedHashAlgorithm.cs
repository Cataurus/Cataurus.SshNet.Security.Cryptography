// TODO Remove this class, and add a dependency to the System.Security.Cryptography.Primitives
// TODO package once this package is available from http://nuget.org with support for UAP 10.0.

#if !FEATURE_CRYPTO_HASHALGORITHM

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    /// <summary>
    /// Represents the abstract class from which all implementations of keyed
    /// hash algorithms must derive.
    /// </summary>
    public abstract class KeyedHashAlgorithm : HashAlgorithm
    {
        /// <summary>
        /// Gets or sets the key to use in the hash algorithm.
        /// </summary>
        /// <value>
        /// The key to use in the hash algorithm.
        /// </value>
        public virtual byte[] Key
        {
            get { return (byte[]) _key.Clone(); }

            set
            {
                _key = (byte[]) value.Clone();
            }
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="KeyedHashAlgorithm"/> and
        /// optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            // For keyed hash algorithms, we always want to zero out the key value
            if (disposing)
            {
                if (_key != null)
                {
                    Array.Clear(_key, 0, _key.Length);
                }
                _key = null;
            }
            base.Dispose(disposing);
        }

        private byte[] _key;
    }
}
#endif // !FEATURE_CRYPTO_KEYEDHASHALGORITHM

