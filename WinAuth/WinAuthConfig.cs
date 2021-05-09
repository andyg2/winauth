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
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;
using WinAuth.Resources;

namespace WinAuth
{
    /// <summary>
    /// Delegate for ConfigChange event
    /// </summary>
    /// <param name="source"></param>
    /// <param name="args"></param>
    public delegate void ConfigChangedHandler(object source, ConfigChangedEventArgs args);

    /// <summary>
    /// Class holding configuration data for application
    /// </summary>
    [Serializable()]
    public class WinAuthConfig : IList<WinAuthAuthenticator>, ICloneable, IWinAuthAuthenticatorChangedListener
    {
        public static decimal CURRENTVERSION = decimal.Parse(System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString(2), System.Globalization.CultureInfo.InvariantCulture);

        /// <summary>
        /// Default actions for double-click or click system tray
        /// </summary>
        public enum NotifyActions
        {
            Notification = 0,
            CopyToClipboard = 1,
            HotKey = 2
        }

        /// <summary>
        /// Event handler fired when a config property is changed
        /// </summary>
        public event ConfigChangedHandler OnConfigChanged;

        /// <summary>
        /// Current file name
        /// </summary>
        private string _filename;

        /// <summary>
        /// Current version of this Config
        /// </summary>
        public decimal Version { get; private set; }

        /// <summary>
        /// Save password for re-saving and encrypting file
        /// </summary>
        public string Password { protected get; set; }

        /// <summary>
        /// If the config was upgraded
        /// </summary>
        public bool Upgraded { get; set; }

        /// <summary>
        /// Current encryption type
        /// </summary>
        private Authenticator.PasswordTypes _passwordType = Authenticator.PasswordTypes.None;

        /// <summary>
        /// Get/set the encryption type
        /// </summary>
        public Authenticator.PasswordTypes PasswordType
        {
            get => _passwordType;
            set
            {
                _passwordType = value;

                if ((_passwordType & Authenticator.PasswordTypes.Explicit) == 0)
                {
                    Password = null;
                }
            }
        }


        /// <summary>
        /// All authenticators
        /// </summary>
        private List<WinAuthAuthenticator> _authenticators = new List<WinAuthAuthenticator>();

        /// <summary>
        /// Current authenticator
        /// </summary>
        private WinAuthAuthenticator _authenticator;

        /// <summary>
        /// Flag for always on top
        /// </summary>
        private bool _alwaysOnTop;

        /// <summary>
        /// Flag to copy the searched single
        /// </summary>
        private bool _copySearchedSingle;

        /// <summary>
        /// Flag to copy the searched single
        /// </summary>
        private bool _autoExitAfterCopy;

        /// <summary>
        /// Flag to use tray icon
        /// </summary>
        private bool _useTrayIcon;

        /// <summary>
        /// Default action when click in system tray
        /// </summary>
        private NotifyActions _notifyAction;

        /// <summary>
        /// Flag to set start with Windows
        /// </summary>
        private bool _startWithWindows;

        /// <summary>
        /// Flag to size form based on numebr authenticators
        /// </summary>
        private bool _autoSize;

        /// <summary>
        /// Remember position
        /// </summary>
        private Point _position = Point.Empty;

        /// <summary>
        /// Width if not autosize
        /// </summary>
        private int _width;

        /// <summary>
        /// Height if not autosize
        /// </summary>
        private int _height;

        /// <summary>
        /// This config is readonly
        /// </summary>
        private bool _readOnly;

        /// <summary>
        /// MetroFormShadowType for main form
        /// </summary>
        private string _shadowType;

        /// <summary>
        /// User's own PGPKey for backups
        /// </summary>
        private string _pgpKey;

        /// <summary>
        /// Class used to serialize the settings inside the Xml config file
        /// </summary>
        [XmlRoot(ElementName = "settings")]
        public class setting
        {
            /// <summary>
            /// Name of dictionary entry
            /// </summary>
            [XmlAttribute(AttributeName = "key")]
            public string Key;

            /// <summary>
            /// Value of dictionary entry
            /// </summary>
            [XmlAttribute(AttributeName = "value")]
            public string Value;
        }

        /// <summary>
        /// Inline settings for Portable mode
        /// </summary>
        private Dictionary<string, string> _settings = new Dictionary<string, string>();

        #region System Settings

        /// <summary>
        /// Get/set file name of config data
        /// </summary>
        public string Filename
        {
            get => _filename;
            set => _filename = value;
        }

        /// <summary>
        /// Get/set on top flag
        /// </summary>
        public bool AlwaysOnTop
        {
            get => _alwaysOnTop;
            set
            {
                _alwaysOnTop = value;
                OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("AlwaysOnTop"));
            }
        }
        /// <summary>
        /// Get/set CopySearchedSingle
        /// </summary>
        public bool CopySearchedSingle
        {
            get => _copySearchedSingle;
            set
            {
                _copySearchedSingle = value;
                OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("CopySearchedSingle"));
            }
        }
        /// <summary>
        /// Get/set AutoExitAfterCopy
        /// </summary>
        public bool AutoExitAfterCopy
        {
            get => _autoExitAfterCopy;
            set
            {
                _autoExitAfterCopy = value;
                OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("AutoExitAfterCopy"));
            }
        }

        /// <summary>
        /// Get/set use tray icon top flag
        /// </summary>
        public bool UseTrayIcon
        {
            get => _useTrayIcon;
            set
            {
                _useTrayIcon = value;
                OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("UseTrayIcon"));
            }
        }

        /// <summary>
        /// Default action when using the system tray or double-click
        /// </summary>
        public NotifyActions NotifyAction
        {
            get => _notifyAction;
            set
            {
                _notifyAction = value;
                OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("NotifyAction"));
            }
        }

        /// <summary>
        /// Get/set start with windows flag
        /// </summary>
        public bool StartWithWindows
        {
            get => _startWithWindows;
            set
            {
                _startWithWindows = value;
                OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("StartWithWindows"));
            }
        }

        /// <summary>
        /// Get/set start with windows flag
        /// </summary>
        public bool AutoSize
        {
            get => _autoSize;
            set
            {
                _autoSize = value;
                OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("AutoSize"));
            }
        }

        /// <summary>
        /// Get/set the position
        /// </summary>
        public Point Position
        {
            get => _position;
            set
            {
                if (_position != value)
                {
                    _position = value;
                    OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("Position"));
                }
            }
        }

        /// <summary>
        /// Saved window width
        /// </summary>
        public int Width
        {
            get => _width;
            set
            {
                if (_width != value)
                {
                    _width = value;
                    OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("Width"));
                }
            }
        }

        /// <summary>
        /// Saved window height
        /// </summary>
        public int Height
        {
            get => _height;
            set
            {
                if (_height != value)
                {
                    _height = value;
                    OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("Height"));
                }
            }
        }

        /// <summary>
        /// Get/set shadow type for main form
        /// </summary>
        public string ShadowType
        {
            get => _shadowType;
            set
            {
                _shadowType = value;
                OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("ShadowType"));
            }
        }

        /// <summary>
        /// Get user's own PGP key
        /// </summary>
        public string PGPKey => _pgpKey;

        /// <summary>
        /// Return if we are in portable mode, which is when the config filename is in teh same directory as the exe
        /// </summary>
        public bool IsPortable => !string.IsNullOrEmpty(Filename)
                    && string.Compare(Path.GetDirectoryName(Filename), Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), true) == 0;

        /// <summary>
        /// Read a setting value.
        /// </summary>
        /// <param name="name">name of setting</param>
        /// <param name="defaultValue">default value if setting doesn't exist</param>
        /// <returns>setting value or default value</returns>
        public string ReadSetting(string name, string defaultValue = null)
        {
            if (IsPortable)
            {
                // read setting from _settings
                if (_settings.TryGetValue(name, out var value))
                {
                    return value;
                }
                else
                {
                    return defaultValue;
                }
            }
            else
            {
                return WinAuthHelper.ReadRegistryValue(name, defaultValue) as string;
            }
        }

        /// <summary>
        /// Get all the settings keys beneath the specified key
        /// </summary>
        /// <param name="name">name of parent key</param>
        /// <returns>string array of all child (recursively) setting names. Empty is none.</returns>
        public string[] ReadSettingKeys(string name)
        {
            if (IsPortable)
            {
                var keys = new List<string>();
                foreach (var entry in _settings)
                {
                    if (entry.Key.StartsWith(name))
                    {
                        keys.Add(entry.Key);
                    }
                }
                return keys.ToArray();
            }
            else
            {
                return WinAuthHelper.ReadRegistryKeys(name);
            }
        }

        /// <summary>
        /// Write a setting value into the Config
        /// </summary>
        /// <param name="name">name of setting value</param>
        /// <param name="value">setting value. If null, the setting is deleted.</param>
        public void WriteSetting(string name, string value)
        {
            if (IsPortable)
            {
                if (value == null)
                {
                    if (_settings.ContainsKey(name))
                    {
                        _settings.Remove(name);
                    }
                }
                else
                {
                    _settings[name] = value;
                }
            }
            else
            {
                if (value == null)
                {
                    WinAuthHelper.DeleteRegistryKey(name);
                }
                else
                {
                    WinAuthHelper.WriteRegistryValue(name, value);
                }
            }
        }

        /// <summary>
        /// Check if a given password is the config's password
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public bool IsPassword(string password) => string.Compare(password, Password) == 0;

        #endregion

        #region IList

        /// <summary>
        /// Rewrite the index values in the WinAuthAuthenticator objects to match our order
        /// </summary>
        private void SetIndexes()
        {
            var count = Count;
            for (var i = 0; i < count; i++)
            {
                this[i].Index = i;
            }
        }

        /// <summary>
        /// Add a new authenticator
        /// </summary>
        /// <param name="authenticator">WinAuthAuthenticator instance</param>
        public void Add(WinAuthAuthenticator authenticator)
        {
            authenticator.OnWinAuthAuthenticatorChanged += new WinAuthAuthenticatorChangedHandler(OnWinAuthAuthenticatorChanged);
            _authenticators.Add(authenticator);
            SetIndexes();
        }

        /// <summary>
        /// Remove all the authenticators
        /// </summary>
        public void Clear()
        {
            foreach (var authenticator in this)
            {
                authenticator.Index = 0;
                authenticator.OnWinAuthAuthenticatorChanged -= new WinAuthAuthenticatorChangedHandler(OnWinAuthAuthenticatorChanged);
            }
            _authenticators.Clear();
        }

        /// <summary>
        /// Check if the config contains an authenticator
        /// </summary>
        /// <param name="authenticator"></param>
        /// <returns></returns>
        public bool Contains(WinAuthAuthenticator authenticator) => _authenticators.Contains(authenticator);

        /// <summary>
        /// Copy elements from the list to an array
        /// </summary>
        /// <param name="index"></param>
        /// <param name="array"></param>
        /// <param name="arrayIndex"></param>
        /// <param name="count"></param>
        public void CopyTo(int index, WinAuthAuthenticator[] array, int arrayIndex, int count) => _authenticators.CopyTo(index, array, arrayIndex, count);

        /// <summary>
        /// Copy the list into an array
        /// </summary>
        /// <param name="array"></param>
        /// <param name="index"></param>
        public void CopyTo(WinAuthAuthenticator[] array, int index) => _authenticators.CopyTo(array, index);

        /// <summary>
        /// return the count of authenticators
        /// </summary>
        public int Count => _authenticators.Count;

        /// <summary>
        /// Get the index of an authenticator
        /// </summary>
        /// <param name="authenticator"></param>
        /// <returns></returns>
        public int IndexOf(WinAuthAuthenticator authenticator) => _authenticators.IndexOf(authenticator);

        /// <summary>
        /// Insert an authenticator at a specified position
        /// </summary>
        /// <param name="index"></param>
        /// <param name="authenticator"></param>
        public void Insert(int index, WinAuthAuthenticator authenticator)
        {
            authenticator.OnWinAuthAuthenticatorChanged += new WinAuthAuthenticatorChangedHandler(OnWinAuthAuthenticatorChanged);
            _authenticators.Insert(index, authenticator);
            SetIndexes();
        }

        /// <summary>
        /// Return if this list is read only
        /// </summary>
        public bool IsReadOnly
        {
            get => _readOnly;
            set => _readOnly = value;
        }

        /// <summary>
        /// Remove an authenticator
        /// </summary>
        /// <param name="authenticator"></param>
        /// <returns></returns>
        public bool Remove(WinAuthAuthenticator authenticator)
        {
            authenticator.OnWinAuthAuthenticatorChanged -= new WinAuthAuthenticatorChangedHandler(OnWinAuthAuthenticatorChanged);
            var result = _authenticators.Remove(authenticator);
            SetIndexes();
            return result;
        }

        /// <summary>
        /// Remove an authenticator from a specific position
        /// </summary>
        /// <param name="index"></param>
        public void RemoveAt(int index)
        {
            _authenticators[index].OnWinAuthAuthenticatorChanged -= new WinAuthAuthenticatorChangedHandler(OnWinAuthAuthenticatorChanged);
            _authenticators.RemoveAt(index);
            SetIndexes();
        }

        /// <summary>
        /// Get an enumerator for the authenticators
        /// </summary>
        /// <returns></returns>
        public IEnumerator<WinAuthAuthenticator> GetEnumerator() => _authenticators.GetEnumerator();

        /// <summary>
        /// Get an enumerator for the authenticators
        /// </summary>
        /// <returns></returns>
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        /// <summary>
        /// Indexer to get an authenticator by postion
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public WinAuthAuthenticator this[int index]
        {
            get => _authenticators[index];
            set => throw new NotImplementedException();
        }

        /// <summary>
        /// Sort the authenticator by their index value
        /// </summary>
        public void Sort() => _authenticators.Sort((a, b) => a.Index.CompareTo(b.Index));

        #endregion

        #region Authenticator Settings

        /// <summary>
        /// Current authenticator
        /// </summary>
        public WinAuthAuthenticator CurrentAuthenticator
        {
            get => _authenticator;
            set => _authenticator = value;
        }

        #endregion

        /// <summary>
        /// Create a default config object
        /// </summary>
        public WinAuthConfig()
        {
            Version = CURRENTVERSION;
            AutoSize = true;
            NotifyAction = NotifyActions.Notification;
        }

        public void OnWinAuthAuthenticatorChanged(WinAuthAuthenticator sender, WinAuthAuthenticatorChangedEventArgs e)
        {
            OnConfigChanged?.Invoke(this, new ConfigChangedEventArgs("Authenticator", sender, e));
        }

        #region ICloneable

        /// <summary>
        /// Clone return a new WinAuthConfig object
        /// </summary>
        /// <returns></returns>
        public object Clone()
        {
            var clone = (WinAuthConfig)MemberwiseClone();
            // close the internal authenticator so the data is kept separate
            clone.OnConfigChanged = null;
            clone._authenticators = new List<WinAuthAuthenticator>();
            foreach (var wa in _authenticators)
            {
                clone._authenticators.Add(wa.Clone() as WinAuthAuthenticator);
            }
            clone.CurrentAuthenticator = CurrentAuthenticator != null ? clone._authenticators[_authenticators.IndexOf(CurrentAuthenticator)] : null;
            return clone;
        }

        public bool ReadXml(XmlReader reader, string password = null)
        {
            var changed = false;

            reader.Read();
            while (!reader.EOF && reader.IsEmptyElement)
            {
                reader.Read();
            }
            reader.MoveToContent();
            while (!reader.EOF)
            {
                if (reader.IsStartElement())
                {
                    switch (reader.Name)
                    {
                        // v2 file
                        case "WinAuth":
                            changed = ReadXmlInternal(reader, password);
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

        protected bool ReadXmlInternal(XmlReader reader, string password = null)
        {
            var changed = false;

            if (decimal.TryParse(reader.GetAttribute("version"), System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var version))
            {
                Version = version;

                if (version > WinAuthConfig.CURRENTVERSION)
                {
                    // ensure we don't overwrite a newer config
                    throw new WinAuthInvalidNewerConfigException(string.Format(strings.ConfigIsNewer, version));
                }
            }

            var encrypted = reader.GetAttribute("encrypted");
            PasswordType = Authenticator.DecodePasswordTypes(encrypted);
            if (PasswordType != Authenticator.PasswordTypes.None)
            {
                // read the encrypted text from the node
                var data = reader.ReadElementContentAsString();
                // decrypt
                data = Authenticator.DecryptSequence(data, PasswordType, password);

                using (var ms = new MemoryStream(Authenticator.StringToByteArray(data)))
                {
                    reader = XmlReader.Create(ms);
                    changed = ReadXml(reader, password);
                }

                PasswordType = Authenticator.DecodePasswordTypes(encrypted);
                Password = password;

                return changed;
            }

            reader.MoveToContent();
            if (reader.IsEmptyElement)
            {
                reader.Read();
                return changed;
            }

            var defaultAutoRefresh = true;
            var defaultAllowCopy = false;
            var defaultCopyOnCode = false;
            var defaultHideSerial = true;
            string defaultSkin = null;

            reader.Read();
            while (!reader.EOF)
            {
                if (reader.IsStartElement())
                {
                    switch (reader.Name)
                    {
                        case "config":
                            changed = ReadXmlInternal(reader, password) || changed;
                            break;

                        // 3.2 has new layout 
                        case "data":
                        {
                            encrypted = reader.GetAttribute("encrypted");
                            PasswordType = Authenticator.DecodePasswordTypes(encrypted);
                            if (PasswordType != Authenticator.PasswordTypes.None)
                            {
                                HashAlgorithm hasher;
                                var hash = reader.GetAttribute("sha1");
                                if (!string.IsNullOrEmpty(hash))
                                {
                                    hasher = Authenticator.SafeHasher("SHA1");
                                }
                                else
                                {
                                    // old version has md5
                                    hash = reader.GetAttribute("md5");
                                    hasher = Authenticator.SafeHasher("MD5");
                                }
                                // read the encrypted text from the node
                                var data = reader.ReadElementContentAsString();

                                hasher.ComputeHash(Authenticator.StringToByteArray(data));
                                hasher.Dispose();

                                // decrypt
                                data = Authenticator.DecryptSequence(data, PasswordType, password);
                                var plain = Authenticator.StringToByteArray(data);

                                using (var ms = new MemoryStream(plain))
                                {
                                    var datareader = XmlReader.Create(ms);
                                    changed = ReadXmlInternal(datareader, password) || changed;
                                }

                                PasswordType = Authenticator.DecodePasswordTypes(encrypted);
                                Password = password;
                            }
                        }
                        break;

                        case "alwaysontop":
                            _alwaysOnTop = reader.ReadElementContentAsBoolean();
                            break;

                        case "usetrayicon":
                            _useTrayIcon = reader.ReadElementContentAsBoolean();
                            break;

                        case "notifyaction":
                            var s = reader.ReadElementContentAsString();
                            if (!string.IsNullOrEmpty(s))
                            {
                                try
                                {
                                    _notifyAction = (NotifyActions)Enum.Parse(typeof(NotifyActions), s, true);
                                }
                                catch (Exception) { }
                            }
                            break;

                        case "startwithwindows":
                            _startWithWindows = reader.ReadElementContentAsBoolean();
                            break;

                        case "autosize":
                            _autoSize = reader.ReadElementContentAsBoolean();
                            break;

                        case "copysearchedsingle":
                            _copySearchedSingle = reader.ReadElementContentAsBoolean();
                            break;

                        case "autoexitaftercopy":
                            _autoExitAfterCopy = reader.ReadElementContentAsBoolean();
                            break;

                        case "left":
                            _position.X = reader.ReadElementContentAsInt();
                            break;

                        case "top":
                            _position.Y = reader.ReadElementContentAsInt();
                            break;

                        case "width":
                            _width = reader.ReadElementContentAsInt();
                            break;

                        case "height":
                            _height = reader.ReadElementContentAsInt();
                            break;

                        case "shadowtype":
                            _shadowType = reader.ReadElementContentAsString();
                            break;

                        case "pgpkey":
                            _pgpKey = reader.ReadElementContentAsString();
                            break;

                        case "settings":
                            var serializer = new XmlSerializer(typeof(setting[]), new XmlRootAttribute() { ElementName = "settings" });
                            _settings = ((setting[])serializer.Deserialize(reader)).ToDictionary(e => e.Key, e => e.Value);
                            break;

                        // previous setting used as defaults for new
                        case "autorefresh":
                            defaultAutoRefresh = reader.ReadElementContentAsBoolean();
                            break;
                        case "allowcopy":
                            defaultAllowCopy = reader.ReadElementContentAsBoolean();
                            break;
                        case "copyoncode":
                            defaultCopyOnCode = reader.ReadElementContentAsBoolean();
                            break;
                        case "hideserial":
                            defaultHideSerial = reader.ReadElementContentAsBoolean();
                            break;
                        case "skin":
                            defaultSkin = reader.ReadElementContentAsString();
                            break;

                        case "WinAuthAuthenticator":
                            var wa = new WinAuthAuthenticator();
                            changed = wa.ReadXml(reader, password) || changed;
                            Add(wa);
                            if (CurrentAuthenticator == null)
                            {
                                CurrentAuthenticator = wa;
                            }
                            break;

                        // for old 2.x configs
                        case "authenticator":
                            var waold = new WinAuthAuthenticator
                            {
                                AuthenticatorData = Authenticator.ReadXmlv2(reader, password)
                            };
                            if (waold.AuthenticatorData is BattleNetAuthenticator)
                            {
                                waold.Name = "Battle.net";
                            }
                            Add(waold);
                            CurrentAuthenticator = waold;
                            waold.AutoRefresh = defaultAutoRefresh;
                            waold.AllowCopy = defaultAllowCopy;
                            waold.CopyOnCode = defaultCopyOnCode;
                            waold.HideSerial = defaultHideSerial;
                            break;

                        // old 2.x auto login script
                        case "autologin":
                            var hks = new HoyKeySequence();
                            hks.ReadXml(reader, password);
                            if (hks.HotKey != 0)
                            {
                                if (CurrentAuthenticator.HotKey == null)
                                {
                                    CurrentAuthenticator.HotKey = new HotKey();
                                }
                                var hotkey = CurrentAuthenticator.HotKey;
                                hotkey.Action = HotKey.HotKeyActions.Inject;
                                hotkey.Key = hks.HotKey;
                                hotkey.Modifiers = hks.Modifiers;
                                if (hks.WindowTitleRegex && !string.IsNullOrEmpty(hks.WindowTitle))
                                {
                                    hotkey.Window = "/" + Regex.Escape(hks.WindowTitle);
                                }
                                else if (!string.IsNullOrEmpty(hks.WindowTitle))
                                {
                                    hotkey.Window = hks.WindowTitle;
                                }
                                else if (!string.IsNullOrEmpty(hks.ProcessName))
                                {
                                    hotkey.Window = hks.ProcessName;
                                }
                                if (hks.Advanced)
                                {
                                    hotkey.Action = HotKey.HotKeyActions.Advanced;
                                    hotkey.Advanced = hks.AdvancedScript;
                                }
                            }
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
        public void WriteXmlString(XmlWriter writer, bool includeFilename = false, bool includeSettings = true)
        {
            writer.WriteStartDocument(true);
            //
            if (includeFilename && !string.IsNullOrEmpty(Filename))
            {
                writer.WriteComment(Filename);
            }
            //
            writer.WriteStartElement("WinAuth");
            writer.WriteAttributeString("version", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString(2));
            //
            writer.WriteStartElement("alwaysontop");
            writer.WriteValue(AlwaysOnTop);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("copysearchedsingle");
            writer.WriteValue(CopySearchedSingle);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("autoexitaftercopy");
            writer.WriteValue(AutoExitAfterCopy);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("usetrayicon");
            writer.WriteValue(UseTrayIcon);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("notifyaction");
            writer.WriteValue(Enum.GetName(typeof(NotifyActions), NotifyAction));
            writer.WriteEndElement();
            //
            writer.WriteStartElement("startwithwindows");
            writer.WriteValue(StartWithWindows);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("autosize");
            writer.WriteValue(AutoSize);
            writer.WriteEndElement();
            //
            if (!Position.IsEmpty)
            {
                writer.WriteStartElement("left");
                writer.WriteValue(Position.X);
                writer.WriteEndElement();
                writer.WriteStartElement("top");
                writer.WriteValue(Position.Y);
                writer.WriteEndElement();
            }
            //
            writer.WriteStartElement("width");
            writer.WriteValue(Width);
            writer.WriteEndElement();
            //
            writer.WriteStartElement("height");
            writer.WriteValue(Height);
            writer.WriteEndElement();
            //
            if (!string.IsNullOrEmpty(ShadowType))
            {
                writer.WriteStartElement("shadowtype");
                writer.WriteValue(ShadowType);
                writer.WriteEndElement();
            }
            //
            if (!string.IsNullOrEmpty(PGPKey))
            {
                writer.WriteStartElement("pgpkey");
                writer.WriteCData(PGPKey);
                writer.WriteEndElement();
            }

            if (PasswordType != Authenticator.PasswordTypes.None)
            {
                writer.WriteStartElement("data");

                var encryptedTypes = new StringBuilder();
                if ((PasswordType & Authenticator.PasswordTypes.Explicit) != 0)
                {
                    encryptedTypes.Append("y");
                }
                if ((PasswordType & Authenticator.PasswordTypes.User) != 0)
                {
                    encryptedTypes.Append("u");
                }
                if ((PasswordType & Authenticator.PasswordTypes.Machine) != 0)
                {
                    encryptedTypes.Append("m");
                }
                writer.WriteAttributeString("encrypted", encryptedTypes.ToString());

                byte[] data;
                using (var ms = new MemoryStream())
                {
                    var settings = new XmlWriterSettings
                    {
                        Indent = true,
                        Encoding = Encoding.UTF8
                    };
                    using (var encryptedwriter = XmlWriter.Create(ms, settings))
                    {
                        encryptedwriter.WriteStartElement("config");
                        foreach (var wa in this)
                        {
                            wa.WriteXmlString(encryptedwriter);
                        }
                        encryptedwriter.WriteEndElement();
                    }

                    data = ms.ToArray();
                }

                using (var hasher = Authenticator.SafeHasher("SHA1"))
                {
                    var encdata = Authenticator.EncryptSequence(Authenticator.ByteArrayToString(data), PasswordType, Password);
                    var enchash = Authenticator.ByteArrayToString(hasher.ComputeHash(Authenticator.StringToByteArray(encdata)));
                    writer.WriteAttributeString("sha1", enchash);
                    writer.WriteString(encdata);
                }

                writer.WriteEndElement();
            }
            else
            {
                foreach (var wa in this)
                {
                    wa.WriteXmlString(writer);
                }
            }

            if (includeSettings && _settings.Count != 0)
            {
                var ns = new XmlSerializerNamespaces();
                ns.Add(string.Empty, string.Empty);
                var serializer = new XmlSerializer(typeof(setting[]), new XmlRootAttribute() { ElementName = "settings" });
                serializer.Serialize(writer, _settings.Select(e => new setting { Key = e.Key, Value = e.Value }).ToArray(), ns);
            }

            // close WinAuth
            writer.WriteEndElement();

            // end document
            writer.WriteEndDocument();
        }

        #endregion

    }

    /// <summary>
    /// Config change event arguments
    /// </summary>
    public class ConfigChangedEventArgs : EventArgs
    {
        public string PropertyName { get; private set; }

        public WinAuthAuthenticator Authenticator { get; private set; }
        public WinAuthAuthenticatorChangedEventArgs AuthenticatorChangedEventArgs { get; private set; }

        /// <summary>
        /// Default constructor
        /// </summary>
        public ConfigChangedEventArgs(string propertyName, WinAuthAuthenticator authenticator = null, WinAuthAuthenticatorChangedEventArgs acargs = null)
            : base()
        {
            PropertyName = propertyName;
            Authenticator = authenticator;
            AuthenticatorChangedEventArgs = acargs;
        }
    }

    public class WinAuthInvalidConfigException : ApplicationException
    {
        public WinAuthInvalidConfigException(string msg, Exception ex)
          : base(msg, ex)
        {
        }
    }
    public class WinAuthConfigRequirePasswordException : ApplicationException
    {
        public WinAuthConfigRequirePasswordException()
          : base()
        {
        }
    }
    public class WinAuthInvalidNewerConfigException : ApplicationException
    {
        public WinAuthInvalidNewerConfigException(string msg)
            : base(msg)
        {
        }
    }

}
