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
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Windows.Forms;
using System.Xml;
using WinAuth.Resources;

namespace WinAuth
{
    public interface IWinAuthAuthenticatorChangedListener
    {
        void OnWinAuthAuthenticatorChanged(WinAuthAuthenticator sender, WinAuthAuthenticatorChangedEventArgs e);
    }

    /// <summary>
    /// Wrapper for real authenticator data used to save to file with other application information
    /// </summary>
    public class WinAuthAuthenticator : ICloneable
    {
        /// <summary>
        /// Event handler fired when property is changed
        /// </summary>
        public event WinAuthAuthenticatorChangedHandler OnWinAuthAuthenticatorChanged;

        /// <summary>
        /// Unique Id of authenticator saved in config
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// Index for authenticator when in sorted list
        /// </summary>
        public int Index { get; set; }

        /// <summary>
        /// Actual authenticator data
        /// </summary>
        public Authenticator AuthenticatorData { get; set; }

        /// <summary>
        /// When this authenticator was created
        /// </summary>
        public DateTime Created { get; set; }

        private string _name;
        private string _skin;
        private bool _autoRefresh;
        private bool _allowCopy;
        private bool _copyOnCode;
        private bool _hideSerial;
        private HotKey _hotkey;

        /// <summary>
        /// Create the authenticator wrapper
        /// </summary>
        public WinAuthAuthenticator()
        {
            Id = Guid.NewGuid();
            Created = DateTime.Now;
            _autoRefresh = true;
        }

        /// <summary>
        /// Clone this authenticator
        /// </summary>
        /// <returns></returns>
        public object Clone()
        {
            var clone = MemberwiseClone() as WinAuthAuthenticator;

            clone.Id = Guid.NewGuid();
            clone.OnWinAuthAuthenticatorChanged = null;
            clone.AuthenticatorData = AuthenticatorData != null ? AuthenticatorData.Clone() as Authenticator : null;

            return clone;
        }

        /// <summary>
        /// Mark this authenticator as having changed
        /// </summary>
        public void MarkChanged() => OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs());

        /// <summary>
        /// Get/set the name of this authenticator
        /// </summary>
        public string Name
        {
            get => _name;
            set
            {
                _name = value;
                OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs("Name"));
            }
        }

        /// <summary>
        /// Set the skin for the authenticator (used for Icon)
        /// </summary>
        public string Skin
        {
            get => _skin;
            set
            {
                _skin = value;
                OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs("Skin"));
            }
        }

        /// <summary>
        /// Get/set auto refresh flag
        /// </summary>
        public bool AutoRefresh
        {
            get
            {
                if (AuthenticatorData != null && AuthenticatorData is HOTPAuthenticator)
                {
                    return false;
                }
                else
                {
                    return _autoRefresh;
                }
            }
            set
            {
                // HTOP must always be false
                if (AuthenticatorData != null && AuthenticatorData is HOTPAuthenticator)
                {
                    _autoRefresh = false;
                }
                else
                {
                    _autoRefresh = value;
                }
                OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs("AutoRefresh"));
            }
        }

        /// <summary>
        /// Get/set allow copy flag
        /// </summary>
        public bool AllowCopy
        {
            get => _allowCopy;
            set
            {
                _allowCopy = value;
                OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs("AllowCopy"));
            }
        }

        /// <summary>
        /// Get/set auto copy flag
        /// </summary>
        public bool CopyOnCode
        {
            get => _copyOnCode;
            set
            {
                _copyOnCode = value;
                OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs("CopyOnCode"));
            }
        }

        /// <summary>
        /// Get/set hide serial flag
        /// </summary>
        public bool HideSerial
        {
            get => _hideSerial;
            set
            {
                _hideSerial = value;
                OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs("HideSerial"));
            }
        }

        /// <summary>
        /// Get/set the ketkey
        /// </summary>
        public HotKey HotKey
        {
            get =>
                //if (this.AuthenticatorData != null && _hotkey != null)
                //{
                //	_hotkey.Advanced = this.AuthenticatorData.Script;
                //}
                _hotkey;
            set
            {
                _hotkey = value;
                //if (this.AuthenticatorData != null && _hotkey != null)
                //{
                //	AuthenticatorData.Script = _hotkey.Advanced;
                //}
                OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs("HotKey"));
            }
        }

        //public HoyKeySequence AutoLogin
        //{
        //	get
        //	{
        //		string script = this.AuthenticatorData.Script;
        //		if (string.IsNullOrEmpty(script))
        //		{
        //			return null;
        //		}

        //		HoyKeySequence hks = new HoyKeySequence();
        //		using (XmlReader xr = XmlReader.Create(new StringReader(script)))
        //		{
        //			hks.ReadXml(xr);
        //		}
        //		return hks;
        //	}
        //	set
        //	{
        //		StringBuilder script = new StringBuilder();
        //		if (value != null)
        //		{
        //			using (XmlWriter xw = XmlWriter.Create(script))
        //			{
        //				value.WriteXmlString(xw);
        //			}
        //		}
        //		this.AuthenticatorData.Script = (script.Length != 0 ? script.ToString() : null);

        //		if (OnWinAuthAuthenticatorChanged != null)
        //		{
        //			OnWinAuthAuthenticatorChanged(this, new WinAuthAuthenticatorChangedEventArgs());
        //		}
        //	}
        //}

        public Bitmap Icon
        {
            get
            {
                if (!string.IsNullOrEmpty(Skin))
                {
                    Stream stream;
                    if (Skin.StartsWith("base64:"))
                    {
                        var bytes = Convert.FromBase64String(Skin.Substring(7));
                        stream = new MemoryStream(bytes, 0, bytes.Length);
                    }
                    else
                    {
                        stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("WinAuth.Resources." + Skin);
                    }
                    if (stream != null)
                    {
                        return new Bitmap(stream);
                    }
                }

                if (AuthenticatorData == null)
                {
                    return null;
                }

                return new Bitmap(Assembly.GetExecutingAssembly().GetManifestResourceStream("WinAuth.Resources." + AuthenticatorData.GetType().Name + "Icon.png"));
            }
            set
            {
                if (value == null)
                {
                    Skin = null;
                    return;
                }

                using (var ms = new MemoryStream())
                {
                    value.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                    Skin = "base64:" + Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public string CurrentCode
        {
            get
            {
                if (AuthenticatorData == null)
                {
                    return null;
                }

                var code = AuthenticatorData.CurrentCode;

                if (AuthenticatorData is HOTPAuthenticator)
                {
                    OnWinAuthAuthenticatorChanged?.Invoke(this, new WinAuthAuthenticatorChangedEventArgs("HOTP", AuthenticatorData));
                }

                return code;
            }
        }

        /// <summary>
        /// Sync the current authenticator's time with its server
        /// </summary>
        public void Sync()
        {
            if (AuthenticatorData != null)
            {
                try
                {
                    AuthenticatorData.Sync();
                }
                catch (EncryptedSecretDataException)
                {
                    // reset lastsync to force sync on next decryption
                }
            }
        }

        /// <summary>
        /// Copy the current code to the clipboard
        /// </summary>
        public void CopyCodeToClipboard(Form form, string code = null, bool showError = false)
        {
            if (code == null)
            {
                code = CurrentCode;
            }

            var clipRetry = false;
            do
            {
                var failed = false;
                // check if the clipboard is locked
                var hWnd = WinAPI.GetOpenClipboardWindow();
                if (hWnd != IntPtr.Zero)
                {
                    var len = WinAPI.GetWindowTextLength(hWnd);
                    if (len == 0)
                    {
                        WinAuthMain.LogException(new ApplicationException("Clipboard in use by another process"));
                    }
                    else
                    {
                        var sb = new StringBuilder(len + 1);
                        WinAPI.GetWindowText(hWnd, sb, sb.Capacity);
                        WinAuthMain.LogException(new ApplicationException("Clipboard in use by '" + sb.ToString() + "'"));
                    }

                    failed = true;
                }
                else
                {
                    // Issue#170: can still get error copying even though it works, so just increase retries and ignore error
                    try
                    {
                        Clipboard.Clear();

                        // add delay for clip error
                        System.Threading.Thread.Sleep(100);

                        Clipboard.SetDataObject(code, true, 4, 250);
                    }
                    catch (ExternalException)
                    {
                    }
                }

                if (failed && showError)
                {
                    // only show an error the first time
                    clipRetry = MessageBox.Show(form, strings.ClipboardInUse,
                        WinAuthMain.APPLICATION_NAME,
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
                }
            }
            while (clipRetry);
        }

        public bool ReadXml(XmlReader reader, string password)
        {
            var changed = false;

            if (Guid.TryParse(reader.GetAttribute("id"), out var id))
            {
                Id = id;
            }
            var authenticatorType = reader.GetAttribute("type");
            if (!string.IsNullOrEmpty(authenticatorType))
            {
                var type = typeof(Authenticator).Assembly.GetType(authenticatorType, false, true);
                AuthenticatorData = Activator.CreateInstance(type) as Authenticator;
            }

            //string encrypted = reader.GetAttribute("encrypted");
            //if (!string.IsNullOrEmpty(encrypted))
            //{
            //	// read the encrypted text from the node
            //	string data = reader.ReadElementContentAsString();
            //	// decrypt
            //	Authenticator.PasswordTypes passwordType;
            //	data = Authenticator.DecryptSequence(data, encrypted, password, out passwordType);

            //	using (MemoryStream ms = new MemoryStream(Authenticator.StringToByteArray(data)))
            //	{
            //		reader = XmlReader.Create(ms);
            //		ReadXml(reader, password);
            //	}
            //	this.PasswordType = passwordType;
            //	this.Password = password;

            //	return;
            //}

            reader.MoveToContent();

            if (reader.IsEmptyElement)
            {
                reader.Read();
                return changed;
            }

            reader.Read();
            while (!reader.EOF)
            {
                if (reader.IsStartElement())
                {
                    switch (reader.Name)
                    {
                        case "name":
                            Name = reader.ReadElementContentAsString();
                            break;

                        case "created":
                            var t = reader.ReadElementContentAsLong();
                            t += Convert.ToInt64(new TimeSpan(new DateTime(1970, 1, 1).Ticks).TotalMilliseconds);
                            t *= TimeSpan.TicksPerMillisecond;
                            Created = new DateTime(t).ToLocalTime();
                            break;

                        case "autorefresh":
                            _autoRefresh = reader.ReadElementContentAsBoolean();
                            break;

                        case "allowcopy":
                            _allowCopy = reader.ReadElementContentAsBoolean();
                            break;

                        case "copyoncode":
                            _copyOnCode = reader.ReadElementContentAsBoolean();
                            break;

                        case "hideserial":
                            _hideSerial = reader.ReadElementContentAsBoolean();
                            break;

                        case "skin":
                            _skin = reader.ReadElementContentAsString();
                            break;

                        case "hotkey":
                            _hotkey = new WinAuth.HotKey();
                            _hotkey.ReadXml(reader);
                            break;

                        case "authenticatordata":
                            try
                            {
                                // we don't pass the password as they are locked till clicked
                                changed = AuthenticatorData.ReadXml(reader) || changed;
                            }
                            catch (EncryptedSecretDataException)
                            {
                                // no action needed
                            }
                            catch (BadPasswordException)
                            {
                                // no action needed
                            }
                            break;

                        // v2
                        case "authenticator":
                            AuthenticatorData = Authenticator.ReadXmlv2(reader, password);
                            break;
                        // v2
                        case "autologin":
                            var hks = new HoyKeySequence();
                            hks.ReadXml(reader, password);
                            break;
                        // v2
                        case "servertimediff":
                            AuthenticatorData.ServerTimeDiff = reader.ReadElementContentAsLong();
                            break;


                        default:
                            reader.Skip();
                            break;
                    }
                }
                else
                {
                    reader.Read();
                    break;
                }
            }

            return changed;
        }

        /// <summary>
        /// Write the data as xml into an XmlWriter
        /// </summary>
        /// <param name="writer">XmlWriter to write config</param>
        public void WriteXmlString(XmlWriter writer)
        {
            writer.WriteStartElement(typeof(WinAuthAuthenticator).Name);
            writer.WriteAttributeString("id", Id.ToString());
            if (AuthenticatorData != null)
            {
                writer.WriteAttributeString("type", AuthenticatorData.GetType().FullName);
            }

            //if (this.PasswordType != Authenticator.PasswordTypes.None)
            //{
            //	string data;

            //	using (MemoryStream ms = new MemoryStream())
            //	{
            //		XmlWriterSettings settings = new XmlWriterSettings();
            //		settings.Indent = true;
            //		settings.Encoding = Encoding.UTF8;
            //		using (XmlWriter encryptedwriter = XmlWriter.Create(ms, settings))
            //		{
            //			Authenticator.PasswordTypes savedpasswordType = PasswordType;
            //			PasswordType = Authenticator.PasswordTypes.None;
            //			WriteXmlString(encryptedwriter);
            //			PasswordType = savedpasswordType;
            //		}
            //		//data = Encoding.UTF8.GetString(ms.ToArray());
            //		data = Authenticator.ByteArrayToString(ms.ToArray());
            //	}

            //	string encryptedTypes;
            //	data = Authenticator.EncryptSequence(data, PasswordType, Password, out encryptedTypes);
            //	writer.WriteAttributeString("encrypted", encryptedTypes);
            //	writer.WriteString(data);
            //	writer.WriteEndElement();

            //	return;
            //}

            writer.WriteStartElement("name");
            writer.WriteValue(Name ?? string.Empty);
            writer.WriteEndElement();

            writer.WriteStartElement("created");
            writer.WriteValue(Convert.ToInt64((Created.ToUniversalTime() - new DateTime(1970, 1, 1)).TotalMilliseconds));
            writer.WriteEndElement();

            writer.WriteStartElement("autorefresh");
            writer.WriteValue(AutoRefresh);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("allowcopy");
            writer.WriteValue(AllowCopy);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("copyoncode");
            writer.WriteValue(CopyOnCode);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("hideserial");
            writer.WriteValue(HideSerial);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("skin");
            writer.WriteValue(Skin ?? string.Empty);
            writer.WriteEndElement();
            //
            if (HotKey != null)
            {
                HotKey.WriteXmlString(writer);
            }

            // save the authenticator to the config file
            if (AuthenticatorData != null)
            {
                AuthenticatorData.WriteToWriter(writer);

                // save script with password and generated salt
                //if (this.AutoLogin != null)
                //{
                //	this.AutoLogin.WriteXmlString(writer, this.AuthenticatorData.PasswordType, this.AuthenticatorData.Password);
                //}
            }

            writer.WriteEndElement();
        }

        /// <summary>
        /// Create a KeyUriFormat compatible URL
        /// See https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
        /// </summary>
        /// <returns>string</returns>
        public virtual string ToUrl(bool compat = false)
        {
            var type = "totp";
            var extraparams = string.Empty;

            Match match;
            var issuer = AuthenticatorData.Issuer;
            var label = Name;
            if (string.IsNullOrEmpty(issuer) && (match = Regex.Match(label, @"^([^\(]+)\s+\((.*?)\)(.*)")).Success)
            {
                issuer = match.Groups[1].Value;
                label = match.Groups[2].Value + match.Groups[3].Value;
            }
            if (!string.IsNullOrEmpty(issuer) && (match = Regex.Match(label, @"^" + issuer + @"\s+\((.*?)\)(.*)")).Success)
            {
                label = match.Groups[1].Value + match.Groups[2].Value;
            }
            if (!string.IsNullOrEmpty(issuer))
            {
                extraparams += "&issuer=" + HttpUtility.UrlEncode(issuer);
            }

            if (AuthenticatorData.HMACType != Authenticator.DEFAULT_HMAC_TYPE)
            {
                extraparams += "&algorithm=" + AuthenticatorData.HMACType.ToString();
            }

            if (AuthenticatorData is BattleNetAuthenticator battleNetAuthenticator)
            {
                extraparams += "&serial=" + HttpUtility.UrlEncode(battleNetAuthenticator.Serial.Replace("-", ""));
            }
            else if (AuthenticatorData is SteamAuthenticator steamAuthenticator)
            {
                if (!compat)
                {
                    extraparams += "&deviceid=" + HttpUtility.UrlEncode(steamAuthenticator.DeviceId);
                    extraparams += "&data=" + HttpUtility.UrlEncode(steamAuthenticator.SteamData);
                }
            }
            else if (AuthenticatorData is HOTPAuthenticator hotpAuthenticator)
            {
                type = "hotp";
                extraparams += "&counter=" + hotpAuthenticator.Counter;
            }

            var secret = HttpUtility.UrlEncode(Base32.getInstance().Encode(AuthenticatorData.SecretKey));

            // add the skin
            if (!string.IsNullOrEmpty(Skin) && !compat)
            {
                if (Skin.StartsWith("base64:"))
                {
                    var bytes = Convert.FromBase64String(Skin.Substring(7));
                    var icon32 = Base32.getInstance().Encode(bytes);
                    extraparams += "&icon=" + HttpUtility.UrlEncode("base64:" + icon32);
                }
                else
                {
                    extraparams += "&icon=" + HttpUtility.UrlEncode(Skin.Replace("Icon.png", ""));
                }
            }

            if (AuthenticatorData.Period != Authenticator.DEFAULT_PERIOD)
            {
                extraparams += "&period=" + AuthenticatorData.Period;
            }

            var url = string.Format("otpauth://" + type + "/{0}?secret={1}&digits={2}{3}",
              !string.IsNullOrEmpty(issuer) ? HttpUtility.UrlPathEncode(issuer) + ":" + HttpUtility.UrlPathEncode(label) : HttpUtility.UrlPathEncode(label),
              secret,
              AuthenticatorData.CodeDigits,
              extraparams);

            return url;
        }

    }

    /// <summary>
    /// Delegate for ConfigChange event
    /// </summary>
    /// <param name="source"></param>
    /// <param name="args"></param>
    public delegate void WinAuthAuthenticatorChangedHandler(WinAuthAuthenticator source, WinAuthAuthenticatorChangedEventArgs args);

    /// <summary>
    /// Change event arguments
    /// </summary>
    public class WinAuthAuthenticatorChangedEventArgs : EventArgs
    {
        public string Property { get; private set; }
        public Authenticator Authenticator { get; private set; }

        /// <summary>
        /// Default constructor
        /// </summary>
        public WinAuthAuthenticatorChangedEventArgs(string property = null, Authenticator authenticator = null)
        {
            Property = property;
            Authenticator = authenticator;
        }

    }
}
