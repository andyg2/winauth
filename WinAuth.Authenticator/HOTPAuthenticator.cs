﻿/*
 * Copyright (C) 2015 Colin Mackie.
 * This software is distributed under the terms of the GNU General Public License.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace WinAuth
{
    /// <summary>
    /// Class that implements a standard counter based HOTP RFC 4226 Authenticator
    /// </summary>
    public class HOTPAuthenticator : Authenticator
    {
        #region Authenticator data

        /// <summary>
        /// Counter for authenticator input
        /// </summary>
        public long Counter { get; set; }

        #endregion

        /// <summary>
        /// Create a new Authenticator object optionally with a specified number of digits
        /// </summary>
        public HOTPAuthenticator() : base(DEFAULT_CODE_DIGITS) { }

        /// <summary>
        /// Create a new Authenticator object optionally with a specified number of digits
        /// </summary>
        public HOTPAuthenticator(int digits) : base(digits) { }

        /// <summary>
        /// Get/set the combined secret data value
        /// </summary>
        public override string SecretData
        {
            get =>
                // this is the key |  serial | deviceid
                base.SecretData
                    + "|" + Counter.ToString();
            set
            {
                // extract key + counter
                if (!string.IsNullOrEmpty(value))
                {
                    var parts = value.Split('|');
                    base.SecretData = value;
                    Counter = parts.Length > 1 ? long.Parse(parts[1]) : 0;
                }
                else
                {
                    Counter = 0;
                }
            }
        }

        /// <summary>
        /// Set the private key for the authenticator
        /// </summary>
        /// <param name="b32key">base32 encoded key</param>
        public void Enroll(string b32key, long counter = 0)
        {
            SecretKey = Base32.GetInstance().Decode(b32key);
            Counter = counter;
        }

        /// <summary>
        /// Synchronise this authenticator
        /// </summary>
        public override void Sync() { }

        /// <summary>
        /// Calculate the current code for the authenticator.
        /// </summary>
        /// <returns>authenticator code</returns>
        protected override string CalculateCode(bool sync = false, long counter = -1)
        {
            if (sync)
            {
                if (counter == -1)
                {
                    throw new ArgumentException("counter must be >= 0");
                }

                // set as previous because we increment
                Counter = counter - 1;
            }

            var hmac = new HMac(new Sha1Digest());
            hmac.Init(new KeyParameter(SecretKey));

            // increment counter
            Counter++;

            var codeIntervalArray = BitConverter.GetBytes(Counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(codeIntervalArray);
            }
            hmac.BlockUpdate(codeIntervalArray, 0, codeIntervalArray.Length);

            var mac = new byte[hmac.GetMacSize()];
            hmac.DoFinal(mac, 0);

            // the last 4 bits of the mac say where the code starts (e.g. if last 4 bit are 1100, we start at byte 12)
            var start = mac[19] & 0x0f;

            // extract those 4 bytes
            var bytes = new byte[4];
            Array.Copy(mac, start, bytes, 0, 4);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            var fullcode = BitConverter.ToUInt32(bytes, 0) & 0x7fffffff;

            // we use the last 8 digits of this code in radix 10
            var codemask = (uint)Math.Pow(10, CodeDigits);
            var format = new string('0', CodeDigits);
            var code = (fullcode % codemask).ToString(format);

            return code;
        }
    }
}
