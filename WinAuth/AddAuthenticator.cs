/*
 * Copyright (C) 2010 Colin Mackie.
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
using System.Drawing;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using System.Windows.Forms;

using WinAuth.Resources;

using ZXing;

namespace WinAuth
{
    /// <summary>
    /// Form class for create a new Battle.net authenticator
    /// </summary>
    public partial class AddAuthenticator : ResourceForm
    {
        /// <summary>
        /// HOTP string
        /// </summary>
        private const string HOTP = "hotp";

        /// <summary>
        /// TOTP string
        /// </summary>
        private const string TOTP = "totp";

        /// <summary>
        /// Form instantiation
        /// </summary>
        public AddAuthenticator()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Current authenticator
        /// </summary>
        public WinAuthAuthenticator Authenticator { get; set; }

        /// <summary>
        /// If we have already warned about sync error
        /// </summary>
        private bool SyncErrorWarned;

        #region Form Events

        /// <summary>
        /// Load the form
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void AddAuthenticator_Load(object sender, EventArgs e)
        {
            nameField.Text = Authenticator.Name;
            codeField.SecretMode = true;
            hashField.Items.Clear();
            hashField.Items.AddRange(Enum.GetNames(typeof(Authenticator.HMACTypes)));
            hashField.SelectedIndex = 0;
            intervalField.Text = WinAuth.Authenticator.DEFAULT_PERIOD.ToString();
            digitsField.Text = WinAuth.Authenticator.DEFAULT_CODE_DIGITS.ToString();
        }

        /// <summary>
        /// Timer tick to show code
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Timer_Tick(object sender, EventArgs e)
        {
            if (Authenticator.AuthenticatorData != null && !(Authenticator.AuthenticatorData is HOTPAuthenticator) && codeProgress.Visible)
            {
                var time = (int)(Authenticator.AuthenticatorData.ServerTime / 1000L) % Authenticator.AuthenticatorData.Period;
                codeProgress.Value = time + 1;
                if (time == 0)
                {
                    codeField.Text = Authenticator.AuthenticatorData.CurrentCode;
                }
            }
        }

        /// <summary>
        /// Handle cancel button with warning
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CancelButton_Click(object sender, EventArgs e)
        {
            if (Authenticator.AuthenticatorData != null)
            {
                var result = WinAuthForm.ConfirmDialog(Owner,
                    "WARNING: Your authenticator has not been saved." + Environment.NewLine + Environment.NewLine
                    + "If you have added this authenticator to your online account, you will not be able to login in the future, and you need to click YES to save it." + Environment.NewLine + Environment.NewLine
                    + "Do you want to save this authenticator?", MessageBoxButtons.YesNoCancel);
                if (result == DialogResult.Yes)
                {
                    DialogResult = DialogResult.OK;
                    return;
                }
                else if (result == DialogResult.Cancel)
                {
                    DialogResult = DialogResult.None;
                    return;
                }
            }
        }

        /// <summary>
        /// Click the OK button to verify and add the authenticator
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OkButton_Click(object sender, EventArgs e)
        {
            var privatekey = secretCodeField.Text.Trim();
            if (privatekey.Length == 0)
            {
                WinAuthForm.ErrorDialog(Owner, "Please enter the Secret Code");
                DialogResult = DialogResult.None;
                return;
            }
            var first = Authenticator.AuthenticatorData == null;
            if (!VerifyAuthenticator(privatekey))
            {
                DialogResult = DialogResult.None;
                return;
            }
            if (first)
            {
                DialogResult = DialogResult.None;
                return;
            }

            // if this is a htop we reduce the counter because we are going to immediate get the code and increment
            if (Authenticator.AuthenticatorData is HOTPAuthenticator hotpAuthenticator)
            {
                hotpAuthenticator.Counter--;
            }
        }

        /// <summary>
        /// Click verify button to load and check code
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void VerifyButton_Click(object sender, EventArgs e)
        {
            var privatekey = secretCodeField.Text.Trim();
            if (privatekey.Length == 0)
            {
                WinAuthForm.ErrorDialog(Owner, "Please enter the Secret Code");
                return;
            }
            VerifyAuthenticator(privatekey);
        }

        /// <summary>
        /// Select the time-based authenticator
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void TimeBasedRadio_CheckedChanged(object sender, EventArgs e)
        {
            counterBasedRadio.Checked = !timeBasedRadio.Checked;
            if (timeBasedRadio.Checked)
            {
                timeBasedPanel.Visible = true;
                counterBasedPanel.Visible = false;
            }
        }

        /// <summary>
        /// Select the counter-based authenticator
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CounterBasedRadio_CheckedChanged(object sender, EventArgs e)
        {
            timeBasedRadio.Checked = !counterBasedRadio.Checked;
            if (counterBasedRadio.Checked)
            {
                counterBasedPanel.Visible = true;
                timeBasedPanel.Visible = false;
            }
        }

        /// <summary>
        /// Leave the secret field
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SecretCodeField_Leave(object sender, EventArgs e) => DecodeSecretCode();

        #endregion

        #region Private methods

        /// <summary>
        /// Decode the secret field
        /// </summary>
        private void DecodeSecretCode()
        {
            Match match;

            if (Regex.IsMatch(secretCodeField.Text, "https?://.*") && Uri.TryCreate(secretCodeField.Text, UriKind.Absolute, out var uri))
            {
                try
                {
                    var request = WebRequest.CreateHttp(uri);
                    request.AllowAutoRedirect = true;
                    request.Timeout = 20000;
                    request.UserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)";
                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                        if (response.StatusCode == HttpStatusCode.OK && response.ContentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                        {
                            using (var bitmap = (Bitmap)Image.FromStream(response.GetResponseStream()))
                            {
                                var reader = new BarcodeReader();
                                var result = reader.Decode(bitmap);
                                if (result != null && !string.IsNullOrEmpty(result.Text))
                                {
                                    secretCodeField.Text = HttpUtility.UrlDecode(result.Text);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    WinAuthForm.ErrorDialog(Owner, "Cannot load QR code image from " + secretCodeField.Text, ex);
                    return;
                }
            }

            match = Regex.Match(secretCodeField.Text, @"otpauth://([^/]+)/([^?]+)\?(.*)", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                var authtype = match.Groups[1].Value.ToLower();
                var label = match.Groups[2].Value;

                if (authtype == HOTP)
                {
                    counterBasedRadio.Checked = true;
                }
                else if (authtype == TOTP)
                {
                    timeBasedRadio.Checked = true;
                    counterField.Text = string.Empty;
                }

                var qs = WinAuthHelper.ParseQueryString(match.Groups[3].Value);
                if (qs["counter"] != null)
                {
                    if (long.TryParse(qs["counter"], out var counter))
                    {
                        counterField.Text = counter.ToString();
                    }
                }

                var issuer = qs["issuer"];
                if (!string.IsNullOrEmpty(issuer))
                {
                    label = issuer + (string.IsNullOrEmpty(label) ? string.Empty : " (" + label + ")");
                }
                nameField.Text = label;

                if (int.TryParse(qs["period"], out var period) && period > 0)
                {
                    intervalField.Text = period.ToString();
                }

                if (int.TryParse(qs["digits"], out var digits) && digits > 0)
                {
                    digitsField.Text = digits.ToString();
                }

                if (Enum.TryParse<Authenticator.HMACTypes>(qs["algorithm"], true, out var hmac))
                {
                    hashField.SelectedItem = hmac.ToString();
                }
            }
        }

        /// <summary>
        /// Check if a filename is valid and such a file exists
        /// </summary>
        /// <param name="filename">filename to check</param>
        /// <returns>true if valid and exists</returns>
        private bool IsValidFile(string filename)
        {
            try
            {
                // check path is valid
                new FileInfo(filename);
                return File.Exists(filename);
            }
            catch (Exception) { }

            return false;
        }


        /// <summary>
        /// Verify and create the authenticator if needed
        /// </summary>
        /// <returns>true is successful</returns>
        private bool VerifyAuthenticator(string privatekey)
        {
            if (string.IsNullOrEmpty(privatekey))
            {
                return false;
            }

            Authenticator.Name = nameField.Text;

            if (string.IsNullOrEmpty(digitsField.Text) || !int.TryParse(digitsField.Text, out var digits) || digits <= 0)
            {
                return false;
            }

            Enum.TryParse<Authenticator.HMACTypes>((string)hashField.SelectedItem, out var hmac);

            var authtype = timeBasedRadio.Checked ? TOTP : HOTP;

            if (string.IsNullOrEmpty(intervalField.Text) || !int.TryParse(intervalField.Text, out var period) || period <= 0)
            {
                return false;
            }

            long counter = 0;

            // if this is a URL, pull it down
            Match match;
            if (Regex.IsMatch(privatekey, "https?://.*") && Uri.TryCreate(privatekey, UriKind.Absolute, out var uri))
            {
                try
                {
                    var request = WebRequest.CreateHttp(uri);
                    request.AllowAutoRedirect = true;
                    request.Timeout = 20000;
                    request.UserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)";
                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                        if (response.StatusCode == HttpStatusCode.OK && response.ContentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                        {
                            using (var bitmap = (Bitmap)Image.FromStream(response.GetResponseStream()))
                            {
                                var reader = new BarcodeReader();
                                var result = reader.Decode(bitmap);
                                if (result != null)
                                {
                                    privatekey = HttpUtility.UrlDecode(result.Text);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    WinAuthForm.ErrorDialog(Owner, "Cannot load QR code image from " + privatekey, ex);
                    return false;
                }
            }
            else if ((match = Regex.Match(privatekey, @"data:image/([^;]+);base64,(.*)", RegexOptions.IgnoreCase)).Success)
            {
                var imageB64Content = match.Groups[2].Value;
                var imagedata = Convert.FromBase64String(imageB64Content);
                using (var ms = new MemoryStream(imagedata))
                {
                    using (var bitmap = (Bitmap)Image.FromStream(ms))
                    {
                        var reader = new BarcodeReader();
                        var result = reader.Decode(bitmap);
                        if (result != null)
                        {
                            privatekey = HttpUtility.UrlDecode(result.Text);
                        }
                    }
                }
            }
            else if (IsValidFile(privatekey))
            {
                // assume this is the image file
                using (var bitmap = (Bitmap)Image.FromFile(privatekey))
                {
                    var reader = new BarcodeReader();
                    var result = reader.Decode(bitmap);
                    if (result != null)
                    {
                        privatekey = result.Text;
                    }
                }
            }

            string issuer = null;
            string serial = null;

            // check for otpauth://, e.g. "otpauth://totp/dc3bf64c-2fd4-40fe-a8cf-83315945f08b@blockchain.info?secret=IHZJDKAEEC774BMUK3GX6SA"
            match = Regex.Match(privatekey, @"otpauth://([^/]+)/([^?]+)\?(.*)", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                authtype = match.Groups[1].Value.ToLower();
                var label = match.Groups[2].Value;
                var p = label.IndexOf(":");
                if (p != -1)
                {
                    label = label.Substring(p + 1);
                }

                var qs = WinAuthHelper.ParseQueryString(match.Groups[3].Value);
                privatekey = qs["secret"] ?? privatekey;
                if (int.TryParse(qs["digits"], out var querydigits) && querydigits != 0)
                {
                    digits = querydigits;
                }
                if (qs["counter"] != null)
                {
                    long.TryParse(qs["counter"], out counter);
                }
                issuer = qs["issuer"];
                if (!string.IsNullOrEmpty(issuer))
                {
                    label = issuer + (string.IsNullOrEmpty(label) ? string.Empty : " (" + label + ")");
                }
                serial = qs["serial"];
                if (!string.IsNullOrEmpty(label))
                {
                    Authenticator.Name = nameField.Text = label;
                }
                var periods = qs["period"];
                if (!string.IsNullOrEmpty(periods))
                {
                    int.TryParse(periods, out period);
                }
                if (qs["algorithm"] != null)
                {
                    if (Enum.TryParse(qs["algorithm"], true, out hmac))
                    {
                        hashField.SelectedItem = hmac.ToString();
                    }
                }
            }

            // just get the hex chars
            privatekey = Regex.Replace(privatekey, @"[^0-9a-z]", "", RegexOptions.IgnoreCase);
            if (privatekey.Length == 0)
            {
                WinAuthForm.ErrorDialog(Owner, "The secret code is not valid");
                return false;
            }

            try
            {
                Authenticator auth;
                if (authtype == TOTP)
                {
                    if (string.Compare(issuer, "BattleNet", true) == 0)
                    {
                        if (string.IsNullOrEmpty(serial))
                        {
                            throw new ApplicationException("Battle.net Authenticator does not have a serial");
                        }
                        serial = serial.ToUpper();
                        if (!Regex.IsMatch(serial, @"^[A-Z]{2}-?[\d]{4}-?[\d]{4}-?[\d]{4}$"))
                        {
                            throw new ApplicationException("Invalid serial for Battle.net Authenticator");
                        }
                        auth = new BattleNetAuthenticator();
                        ((BattleNetAuthenticator)auth).SecretKey = Base32.GetInstance().Decode(privatekey);
                        ((BattleNetAuthenticator)auth).Serial = serial;

                        issuer = string.Empty;
                    }
                    else if (issuer == "Steam")
                    {
                        auth = new SteamAuthenticator();
                        ((SteamAuthenticator)auth).SecretKey = Base32.GetInstance().Decode(privatekey);
                        ((SteamAuthenticator)auth).Serial = string.Empty;
                        ((SteamAuthenticator)auth).DeviceId = string.Empty;
                        //((SteamAuthenticator)auth).RevocationCode = string.Empty;
                        ((SteamAuthenticator)auth).SteamData = string.Empty;

                        Authenticator.Skin = null;

                        issuer = string.Empty;
                    }
                    else
                    {
                        auth = new GoogleAuthenticator();
                        ((GoogleAuthenticator)auth).Enroll(privatekey);
                    }
                    timer.Enabled = true;
                    codeProgress.Visible = true;
                    timeBasedRadio.Checked = true;
                }
                else if (authtype == HOTP)
                {
                    auth = new HOTPAuthenticator();
                    if (counterField.Text.Trim().Length != 0)
                    {
                        long.TryParse(counterField.Text.Trim(), out counter);
                    }
                    ((HOTPAuthenticator)auth).Enroll(privatekey, counter); // start with the next code
                    timer.Enabled = false;
                    codeProgress.Visible = false;
                    counterBasedRadio.Checked = true;
                }
                else
                {
                    WinAuthForm.ErrorDialog(Owner, "Only TOTP or HOTP authenticators are supported");
                    return false;
                }
                auth.HMACType = hmac;
                auth.CodeDigits = digits;
                auth.Period = period;
                Authenticator.AuthenticatorData = auth;

                codeField.SpaceOut = digits > 5 ? digits / 2 : 0;

                //var key = Base32.GetInstance().Encode(Authenticator.AuthenticatorData.SecretKey);
                codeField.Text = auth.CurrentCode;

                codeProgress.Maximum = period;

                if (!(auth is HOTPAuthenticator) && auth.ServerTimeDiff == 0L && !SyncErrorWarned)
                {
                    SyncErrorWarned = true;
                    MessageBox.Show(this, string.Format(strings.AuthenticatorSyncError, "Google"), WinAuthMain.APPLICATION_TITLE, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception irre)
            {
                WinAuthForm.ErrorDialog(Owner, "Unable to create the authenticator. The secret code is probably invalid.", irre);
                return false;
            }

            return true;
        }


        private void SecretCodeField_dragdrop(object sender, DragEventArgs e)
        {
            var files = (string[])e.Data.GetData(DataFormats.FileDrop);
            secretCodeField.Text = files[0];
        }

        private void SecretCodeField_DragEnter(object sender, DragEventArgs e) => e.Effect = DragDropEffects.Copy;

        private Color initialColor;

        private void DragPanel_DragEnter(object sender, DragEventArgs e)
        {
            e.Effect = DragDropEffects.Copy;
            initialColor = (sender as Panel).BackColor;
            (sender as Panel).BackColor = Color.LightGreen;
        }

        private void DragImagePanel_DragLeave(object sender, EventArgs e) => (sender as Panel).BackColor = initialColor;

        private void DragPanel_DragDrop(object sender, DragEventArgs e)
        {
            var files = (string[])e.Data.GetData(DataFormats.FileDrop);
            var filePath = files[0];
            var ext = Path.GetExtension(filePath);
            var imageArray = File.ReadAllBytes(filePath);
            var base64ImageRepresentation = Convert.ToBase64String(imageArray);
            secretCodeField.Text = @"data:image/" + ext + ";base64," + base64ImageRepresentation;
            VerifyButton_Click(null, null);
        }

        #endregion
    }
}
