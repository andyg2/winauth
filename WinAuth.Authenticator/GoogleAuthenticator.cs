﻿/*
 * Copyright (C) 2011 Colin Mackie.
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
using System.Net;

namespace WinAuth
{
    /// <summary>
    /// Class that implements Google's authenticator
    /// </summary>
    public class GoogleAuthenticator : Authenticator
    {
        /// <summary>
        /// Number of digits in code
        /// </summary>
        private const int CODE_DIGITS = 6;

        /// <summary>
        /// Number of minutes to ignore syncing if network error
        /// </summary>
        private const int SYNC_ERROR_MINUTES = 5;

        /// <summary>
        /// URL used to sync time
        /// </summary>
        private const string TIME_SYNC_URL = "https://www.google.com";

        /// <summary>
        /// Time of last Sync error
        /// </summary>
        private static DateTime _lastSyncError = DateTime.MinValue;

        #region Authenticator data

        public string Serial => Base32.GetInstance().Encode(SecretKey);

        #endregion

        /// <summary>
        /// Create a new Authenticator object
        /// </summary>
        public GoogleAuthenticator() : base(CODE_DIGITS) { }

        /// <summary>
        /// Enroll the authenticator with the server.
        public void Enroll(string b32key)
        {
            SecretKey = Base32.GetInstance().Decode(b32key);
            Sync();
        }

        /// <summary>
        /// Synchronise this authenticator's time with Google. We update our data record with the difference from our UTC time.
        /// </summary>
        public override void Sync()
        {
            // check if data is protected
            if (SecretKey == null && EncryptedData != null)
            {
                throw new EncryptedSecretDataException();
            }

            // don't retry for 5 minutes
            if (_lastSyncError >= DateTime.Now.AddMinutes(0 - SYNC_ERROR_MINUTES))
            {
                return;
            }

            try
            {
                // we use the Header response field from a request to www.google.come
                var request = WebRequest.CreateHttp(TIME_SYNC_URL);
                request.Method = "GET";
                request.ContentType = "text/html";
                request.Timeout = 5000;
                // get response
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    // OK?
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        throw new ApplicationException(string.Format("{0}: {1}", (int)response.StatusCode, response.StatusDescription));
                    }

                    var headerdate = response.Headers["Date"];
                    if (!string.IsNullOrEmpty(headerdate))
                    {
                        if (DateTime.TryParse(headerdate, out var dt))
                        {
                            // get as ms since epoch
                            var dtms = Convert.ToInt64((dt.ToUniversalTime() - new DateTime(1970, 1, 1)).TotalMilliseconds);

                            // get the difference between the server time and our current time
                            var serverTimeDiff = dtms - CurrentTime;

                            // update the Data object
                            ServerTimeDiff = serverTimeDiff;
                            LastServerTime = DateTime.Now.Ticks;
                        }
                    }

                    // clear any sync error
                    _lastSyncError = DateTime.MinValue;
                }
            }
            catch (WebException)
            {
                // don't retry for a while after error
                _lastSyncError = DateTime.Now;

                // set to zero to force reset
                ServerTimeDiff = 0;
            }
        }
    }
}
