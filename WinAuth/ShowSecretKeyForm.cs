/*
 * Copyright (C) 2013 Colin Mackie.
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
using System.Text.RegularExpressions;

using ZXing;

namespace WinAuth
{
    /// <summary>
    /// Form display initialization confirmation.
    /// </summary>
    public partial class ShowSecretKeyForm : ResourceForm
    {
        /// <summary>
        /// Current authenticator
        /// </summary>
        public WinAuthAuthenticator CurrentAuthenticator { get; set; }

        /// <summary>
        /// Create a new form
        /// </summary>
        public ShowSecretKeyForm()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Click OK button to close form
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void BtnOK_Click(object sender, EventArgs e) => Close();

        /// <summary>
        /// Form loaded event
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ShowSecretKeyForm_Load(object sender, EventArgs e)
        {
            secretKeyField.SecretMode = true;

            var key = Base32.GetInstance().Encode(CurrentAuthenticator.AuthenticatorData.SecretKey);
            secretKeyField.Text = Regex.Replace(key, ".{3}", "$0 ").Trim();

            //var type = CurrentAuthenticator.AuthenticatorData is HOTPAuthenticator ? "hotp" : "totp";
            //var counter = CurrentAuthenticator.AuthenticatorData is HOTPAuthenticator hotpAuthenticator ? hotpAuthenticator.Counter : 0;
            //var issuer = CurrentAuthenticator.AuthenticatorData.Issuer;

            //var url = "otpauth://" + type + "/" + WinAuthHelper.HtmlEncode(CurrentAuthenticator.Name)
            //    + "?secret=" + key
            //    + "&digits=" + CurrentAuthenticator.AuthenticatorData.CodeDigits
            //    + (counter != 0 ? "&counter=" + counter : string.Empty)
            //    + (string.IsNullOrEmpty(issuer) ? string.Empty : "&issuer=" + WinAuthHelper.HtmlEncode(issuer));
            var url = CurrentAuthenticator.ToUrl(true);

            var writer = new BarcodeWriter
            {
                Format = BarcodeFormat.QR_CODE,
                Options = new ZXing.Common.EncodingOptions { Width = qrImage.Width, Height = qrImage.Height }
            };
            qrImage.Image = writer.Write(url);
        }

        /// <summary>
        /// Toggle the secret mode to allow copy
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void AllowCopyCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            secretKeyField.SecretMode = !allowCopyCheckBox.Checked;

            var key = Base32.GetInstance().Encode(CurrentAuthenticator.AuthenticatorData.SecretKey);
            secretKeyField.Text = secretKeyField.SecretMode ? Regex.Replace(key, ".{3}", "$0 ").Trim() : key;
        }
    }
}
