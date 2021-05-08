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
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using MetroFramework.Forms;
using NLog;
using WinAuth.Resources;

namespace WinAuth
{
    public partial class WinAuthForm : ResourceForm
    {
        public WinAuthForm()
        {
            InitializeComponent();
        }

        #region Properties

        /// <summary>
        /// The current winauth config
        /// </summary>
        public WinAuthConfig Config { get; set; }

        /// <summary>
        /// Datetime for when we should save config
        /// </summary>
        private DateTime? _saveConfigTime;

        /// <summary>
        /// Self-updating object
        /// </summary>
        private WinAuthUpdater Updater { get; set; }

        /// <summary>
        /// Flag used to set AutoSizing based on authenticators
        /// </summary>
        public bool AutoAuthenticatorSize { get; set; }

        /// <summary>
        /// Flag used to see if we are closing manually
        /// </summary>
        private bool m_explictClose;

        /// <summary>
        /// Hook for hotkey to send code to window
        /// </summary>
        private KeyboardHook m_hook;

        /// <summary>
        /// Flag to say we are processing sending message to other window
        /// </summary>
        private readonly object m_sendingKeys = new object();

        /// <summary>
        /// Delegates for clipbaord manipulation
        /// </summary>
        /// <param name="data"></param>
        public delegate void SetClipboardDataDelegate(object data);
        public delegate object GetClipboardDataDelegate(Type format);

        /// <summary>
        /// Save the position of the list within the form for starting as minimized
        /// </summary>
        private Rectangle _listoffset;

        /// <summary>
        /// If we were passed command line arg to minimise
        /// </summary>
        private bool _initiallyMinimised;

        /// <summary>
        /// Existing v2 config file so we can prompt for import
        /// </summary>
        private string _existingv2Config;

        private string _startupConfigFile;

        /// <summary>
        /// Forwarder for mousewheel messages to list control
        /// </summary>
        private WinAPI.MessageForwarder _wheelMessageForwarder;

        /// <summary>
        /// First time only initialzation
        /// </summary>
        private bool m_initOnce;

        /// <summary>
        /// Initial form size so we can reset
        /// </summary>
        private Size m_initialSize;

        /// <summary>
        /// Locker for WM_DEVICECHANGE
        /// </summary>
        private readonly object m_deviceArrivalMutex = new object();

        #endregion

        /// <summary>
        /// Load the main form
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void WinAuthForm_Load(object sender, EventArgs e)
        {
            // get any command arguments
            string password = null;
            string proxy = null;
            var args = Environment.GetCommandLineArgs();
            for (var i = 1; i < args.Length; i++)
            {
                var arg = args[i];
                if (arg[0] == '-')
                {
                    switch (arg)
                    {
                        case "-min":
                        case "--minimize":
                            // set initial state as minimized
                            _initiallyMinimised = true;
                            break;
                        case "-p":
                        case "--password":
                            // set explicit password to use
                            i++;
                            password = args[i];
                            break;
                        case "--proxy":
                            // set proxy [user[:pass]@]ip[:host]
                            i++;
                            proxy = args[i];
                            break;
                        case "-l":
                        case "--log":
                            i++;
                            var fi = typeof(LogLevel).GetField(args[i], BindingFlags.Static | BindingFlags.IgnoreCase | BindingFlags.Public);
                            if (fi == null)
                            {
                                WinAuthForm.ErrorDialog(this, "Invalid parameter: log value: " + args[i] + " (must be error,info,debug,trace)");
                                System.Diagnostics.Process.GetCurrentProcess().Kill();
                            }
                            var loglevel = fi.GetValue(null) as LogLevel;
                            var target = NLog.LogManager.Configuration.AllTargets.Where(t => t.Name == null).FirstOrDefault();
                            if (target != null)
                            {
                                LogManager.Configuration.LoggingRules.Add(new NLog.Config.LoggingRule("*", loglevel, target));
                            }
                            break;
                        default:
                            break;
                    }
                }
                else
                {
                    _startupConfigFile = arg;
                }
            }

            // set the default web proxy
            if (string.IsNullOrEmpty(proxy) == false)
            {
                try
                {
                    var uri = new Uri(proxy.IndexOf("://") == -1 ? "http://" + proxy : proxy);
                    var webproxy = new WebProxy(uri.Host + ":" + uri.Port, true);
                    if (string.IsNullOrEmpty(uri.UserInfo) == false)
                    {
                        var auth = uri.UserInfo.Split(':');
                        webproxy.Credentials = new NetworkCredential(auth[0], (auth.Length > 1 ? auth[1] : string.Empty));
                    }
                    WebRequest.DefaultWebProxy = webproxy;
                }
                catch (UriFormatException)
                {
                    ErrorDialog(this, "Invalid proxy value (" + proxy + ")" + Environment.NewLine + Environment.NewLine + "Use --proxy [user[:password]@]ip[:port], e.g. 127.0.0.1:8080 or me:mypass@10.0.0.1:8080");
                    Close();
                }
            }

            InitializeOnce();

            loadConfig(password);
        }

        #region Private Methods

        /// <summary>
        /// Load the current config into WinAuth
        /// </summary>
        /// <param name="password">optional password to decrypt config</param>
        /// <param name="configFile">optional explicit config file</param>
        private void loadConfig(string password)
        {
            var configFile = _startupConfigFile;

            loadingPanel.Visible = true;
            passwordPanel.Visible = false;
            Task.Factory.StartNew<Tuple<WinAuthConfig, Exception>>(() =>
            {
                try
                {
                    // use previous config if we have one
                    var config = WinAuthHelper.LoadConfig(this, configFile, password);
                    return new Tuple<WinAuthConfig, Exception>(config, null);
                }
                catch (Exception ex)
                {
                    return new Tuple<WinAuthConfig, Exception>(null, ex);
                }
            }).ContinueWith((configTask) =>
            {
                var ex = configTask.Result.Item2;
                if (ex is WinAuthInvalidNewerConfigException)
                {
                    MessageBox.Show(this, ex.Message, WinAuthMain.APPLICATION_TITLE, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    System.Diagnostics.Process.GetCurrentProcess().Kill();
                    return;
                }
                else if (ex is EncryptedSecretDataException)
                {
                    loadingPanel.Visible = false;
                    passwordPanel.Visible = true;

                    passwordButton.Focus();
                    passwordField.Focus();

                    return;
                }
                else if (ex is BadPasswordException)
                {
                    loadingPanel.Visible = false;
                    passwordPanel.Visible = true;
                    passwordErrorLabel.Text = strings.InvalidPassword;
                    passwordErrorLabel.Tag = DateTime.Now.AddSeconds(3);
                    // oddity with MetroFrame controls in have to set focus away and back to field to make it stick
                    Invoke((MethodInvoker)delegate
                    { passwordButton.Focus(); passwordField.Focus(); });
                    passwordTimer.Enabled = true;
                    return;
                }
                else if (ex is Exception)
                {
                    if (ErrorDialog(this, strings.UnknownError + ": " + ex.Message, ex, MessageBoxButtons.RetryCancel) == System.Windows.Forms.DialogResult.Cancel)
                    {
                        Close();
                        return;
                    }
                    loadConfig(password);
                    return;
                }

                var config = configTask.Result.Item1;
                if (config == null)
                {
                    System.Diagnostics.Process.GetCurrentProcess().Kill();
                    return;
                }

                // check for a v2 config file if this is a new config
                if (config.Count == 0 && string.IsNullOrEmpty(config.Filename) == true)
                {
                    _existingv2Config = WinAuthHelper.GetLastV2Config();
                }

                Config = config;
                Config.OnConfigChanged += new ConfigChangedHandler(OnConfigChanged);

                if (config.Upgraded == true)
                {
                    SaveConfig(true);
                    // display warning
                    WinAuthForm.ErrorDialog(this, string.Format(strings.ConfigUpgraded, WinAuthConfig.CURRENTVERSION));
                }

                InitializeForm();
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        /// <summary>
        /// Import authenticators from a file
        /// 
        /// *.xml = WinAuth v2
        /// *.txt = plain text with KeyUriFormat per line (https://code.google.com/p/google-authenticator/wiki/KeyUriFormat)
        /// *.zip = encrypted zip, containing import file
        /// *.pgp = PGP encrypted, containing import file
        /// 
        /// </summary>
        /// <param name="authenticatorFile">name import file</param>
        private void importAuthenticator(string authenticatorFile)
        {
            // call legacy import for v2 xml files
            if (string.Compare(Path.GetExtension(authenticatorFile), ".xml", true) == 0)
            {
                importAuthenticatorFromV2(authenticatorFile);
                return;
            }

            List<WinAuthAuthenticator> authenticators = null;
            bool retry;
            do
            {
                retry = false;
                try
                {
                    authenticators = WinAuthHelper.ImportAuthenticators(this, authenticatorFile);
                }
                catch (ImportException ex)
                {
                    if (ErrorDialog(this, ex.Message, ex.InnerException, MessageBoxButtons.RetryCancel) == System.Windows.Forms.DialogResult.Cancel)
                    {
                        return;
                    }
                    retry = true;
                }
            } while (retry);
            if (authenticators == null)
            {
                return;
            }

            // save all the new authenticators
            foreach (var authenticator in authenticators)
            {
                //sync
                authenticator.Sync();

                // make sure there isn't a name clash
                var rename = 0;
                var importedName = authenticator.Name;
                while (Config.Where(a => a.Name == importedName).Count() != 0)
                {
                    importedName = authenticator.Name + " " + (++rename);
                }
                authenticator.Name = importedName;

                // save off any new authenticators as a backup
                WinAuthHelper.SaveToRegistry(Config, authenticator);

                // first time we prompt for protection and set out main settings from imported config
                if (Config.Count == 0)
                {
                    var form = new ChangePasswordForm
                    {
                        PasswordType = Authenticator.PasswordTypes.Explicit
                    };
                    if (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK)
                    {
                        Config.PasswordType = form.PasswordType;
                        if ((Config.PasswordType & Authenticator.PasswordTypes.Explicit) != 0 && string.IsNullOrEmpty(form.Password) == false)
                        {
                            Config.Password = form.Password;
                        }
                    }
                }

                // add to main list
                Config.Add(authenticator);
            }

            SaveConfig(true);
            loadAuthenticatorList();

            // reset UI
            setAutoSize();
            introLabel.Visible = (Config.Count == 0);

            // reset hotkeys
            HookHotkeys();
        }

        /// <summary>
        /// Import a v2 authenticator from an existing file name
        /// </summary>
        /// <param name="authenticatorFile">name of v2 xml file</param>
        private void importAuthenticatorFromV2(string authenticatorFile)
        {
            var retry = false;
            string password = null;
            var needPassword = false;
            var invalidPassword = false;
            do
            {
                try
                {
                    var config = WinAuthHelper.LoadConfig(this, authenticatorFile, password);
                    if (config.Count == 0)
                    {
                        return;
                    }

                    // get the actual authenticator and ensure it is synced
                    var imported = new List<WinAuthAuthenticator>();
                    foreach (var importedAuthenticator in config)
                    {
                        importedAuthenticator.Sync();

                        // make sure there isn't a name clash
                        var rename = 0;
                        var importedName = importedAuthenticator.Name;
                        while (Config.Where(a => a.Name == importedName).Count() != 0)
                        {
                            importedName = importedAuthenticator.Name + " (" + (++rename) + ")";
                        }
                        importedAuthenticator.Name = importedName;

                        imported.Add(importedAuthenticator);
                    }

                    // first time we prompt for protection and set out main settings from imported config
                    if (Config.Count == 0)
                    {
                        Config.StartWithWindows = config.StartWithWindows;
                        Config.UseTrayIcon = config.UseTrayIcon;
                        Config.AlwaysOnTop = config.AlwaysOnTop;
                        Config.CopySearchedSingle = config.CopySearchedSingle;
                        Config.AutoExitAfterCopy = config.AutoExitAfterCopy;

                        var form = new ChangePasswordForm
                        {
                            PasswordType = Authenticator.PasswordTypes.Explicit
                        };
                        if (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK)
                        {
                            Config.PasswordType = form.PasswordType;
                            if ((Config.PasswordType & Authenticator.PasswordTypes.Explicit) != 0 && string.IsNullOrEmpty(form.Password) == false)
                            {
                                Config.Password = form.Password;
                            }
                        }
                    }

                    foreach (var auth in imported)
                    {
                        // save off any new authenticators as a backup
                        WinAuthHelper.SaveToRegistry(Config, auth);

                        // add to main list
                        Config.Add(auth);
                        loadAuthenticatorList(auth);
                    }
                    SaveConfig(true);

                    // reset UI
                    setAutoSize();
                    introLabel.Visible = (Config.Count == 0);

                    // reset hotkeys
                    HookHotkeys();

                    needPassword = false;
                    retry = false;
                }
                catch (EncryptedSecretDataException)
                {
                    needPassword = true;
                    invalidPassword = false;
                }
                catch (BadPasswordException)
                {
                    needPassword = true;
                    invalidPassword = true;
                }
                catch (Exception ex)
                {
                    if (ErrorDialog(this, strings.UnknownError + ": " + ex.Message, ex, MessageBoxButtons.RetryCancel) == System.Windows.Forms.DialogResult.Cancel)
                    {
                        return;
                    }
                    needPassword = false;
                    invalidPassword = false;
                    retry = true;
                }

                if (needPassword == true)
                {
                    var form = new GetPasswordForm
                    {
                        InvalidPassword = invalidPassword
                    };
                    var result = form.ShowDialog(this);
                    if (result == DialogResult.Cancel)
                    {
                        return;
                    }
                    password = form.Password;
                    retry = true;
                }
            } while (retry == true);
        }

        private void InitializeOnce()
        {
            if (m_initOnce == false)
            {
                // hook into System time change event
                Microsoft.Win32.SystemEvents.TimeChanged += new EventHandler(SystemEvents_TimeChanged);

                // save the initial form size
                m_initialSize = Size;

                // redirect mouse wheel events
                _wheelMessageForwarder = new WinAPI.MessageForwarder(authenticatorList, WinAPI.WM_MOUSEWHEEL);

                m_initOnce = true;
            }
        }

        /// <summary>
        /// Initialise the current form and UI
        /// </summary>
        private void InitializeForm()
        {
            // create the updater and check for update if appropriate
            if (System.Deployment.Application.ApplicationDeployment.IsNetworkDeployed == false)
            {
                Updater = new WinAuthUpdater(Config);
                // the very first time, we set it to update each time
                if (Updater.LastCheck == DateTime.MinValue)
                {
                    Updater.SetUpdateInterval(new TimeSpan(3, 0, 0, 0));
                }
                if (Updater.IsAutoCheck == true)
                {
                    var latest = Updater.LastKnownLatestVersion;

                    if (latest != null && latest > Updater.CurrentVersion)
                    {
                        newVersionLink.Text = "New version " + latest + " available";
                        newVersionLink.Visible = true;
                    }
                }
                // spin up the autocheck thread and assign callback
                Updater.AutoCheck(NewVersionAvailable);
            }

            // set up list
            loadAuthenticatorList();

            // set always on top
            TopMost = Config.AlwaysOnTop;

            // size the form based on the authenticators
            setAutoSize();

            // initialize UI
            LoadAddAuthenticatorTypes();
            loadOptionsMenu(optionsMenu);
            loadNotifyMenu(notifyMenu);
            loadingPanel.Visible = false;
            passwordPanel.Visible = false;
            commandPanel.Visible = true;
            ActiveControl = searchTextbox;
            introLabel.Visible = (Config.Count == 0);
            authenticatorList.Visible = (Config.Count != 0);
            addAuthenticatorButton.Visible = !Config.IsReadOnly;

            // set title
            notifyIcon.Visible = Config.UseTrayIcon;
            notifyIcon.Text = Text = WinAuthMain.APPLICATION_TITLE;

            // hook hotkeys
            HookHotkeys();

            // hook Steam notifications
            //HookSteam();

            // save the position of the list within the form else starting as minimized breaks the size
            _listoffset = new Rectangle(authenticatorList.Left, authenticatorList.Top, (Width - authenticatorList.Width), (Height - authenticatorList.Height));

            // set the shadow type (change in config for compatibility)
            try
            {
                var shadow = (MetroFormShadowType)Enum.Parse(typeof(MetroFormShadowType), Config.ShadowType, true);
                ShadowType = shadow;
            }
            catch (Exception) { }

            // set positions
            if (Config.Position.IsEmpty == false)
            {
                // check we aren't out of bounds in case of multi-monitor change
                var v = SystemInformation.VirtualScreen;
                if ((Config.Position.X + Width) >= v.Left && Config.Position.X < v.Width && Config.Position.Y > v.Top)
                {
                    try
                    {
                        StartPosition = FormStartPosition.Manual;
                        Left = Config.Position.X;
                        Top = Config.Position.Y;
                    }
                    catch (Exception) { }
                }

                // check we aren't below the taskbar
                var lowesty = Screen.GetWorkingArea(this).Bottom;
                var bottom = Top + Height;
                if (bottom > lowesty)
                {
                    Top -= (bottom - lowesty);
                    if (Top < 0)
                    {
                        Height += Top;
                        Top = 0;
                    }
                }
            }
            else if (Config.AutoSize == true)
            {
                CenterToScreen();
            }

            // if we passed "-min" flag
            if (_initiallyMinimised == true)
            {
                WindowState = FormWindowState.Minimized;
                ShowInTaskbar = true;
            }
            if (Config.UseTrayIcon == true)
            {
                notifyIcon.Visible = true;
                notifyIcon.Text = Text;

                // if initially minimized, we need to hide
                if (WindowState == FormWindowState.Minimized)
                {
                    // hide this and metro owner
                    Form form = this;
                    do
                    {
                        form.Hide();
                    } while ((form = form.Owner) != null);
                }
            }
        }

        /// <summary>
        /// Load the authenticators into the display list
        /// </summary>
        /// <param name="added">authenticator we just added</param>
        private void loadAuthenticatorList(WinAuthAuthenticator added = null)
        {
            // set up list
            authenticatorList.Items.Clear();

            var index = 0;
            AuthenticatorListitem lastFound = null;
            foreach (var auth in Config)
            {
                var ali = new AuthenticatorListitem(auth, index);
                if (added != null && added == auth && auth.AutoRefresh == false && !(auth.AuthenticatorData is HOTPAuthenticator))
                {
                    ali.LastUpdate = DateTime.Now;
                    ali.DisplayUntil = DateTime.Now.AddSeconds(10);
                }

                if (searchString == "" || ali.Authenticator.Name.ToLower().Contains(searchString.ToLower()))
                {
                    lastFound = ali;
                    authenticatorList.Items.Add(ali);
                }
                index++;
            }
            // Copy found item OneTimeCode if it's single result
            if (Config.CopySearchedSingle && authenticatorList.Items.Count == 1)
            {
                Clipboard.SetText(lastFound.Authenticator.CurrentCode);
                noticeLabel.Text = "Copied!";
                if (Config.AutoExitAfterCopy)
                {
                    Close();
                }
            }
            else if (authenticatorList.Items.Count == 0)
            {
                noticeLabel.Text = "Not found";
            }

            authenticatorList.Visible = (authenticatorList.Items.Count != 0);
        }

        /// <summary>
        /// Save the current config immediately or delay it for a few seconds so we can make more changes
        /// </summary>
        private void SaveConfig(bool immediate = false)
        {
            if (immediate == true || (_saveConfigTime != null && _saveConfigTime <= DateTime.Now))
            {
                _saveConfigTime = null;
                lock (Config)
                {
                    WinAuthHelper.SaveConfig(Config);
                }
            }
            else
            {
                // save it in a few seconds so we can batch up saves
                _saveConfigTime = DateTime.Now.AddSeconds(1);
            }
        }

        /// <summary>
        /// Show an error message dialog
        /// </summary>
        /// <param name="form">owning form</param>
        /// <param name="message">optional message to display</param>
        /// <param name="ex">optional exception details</param>
        /// <param name="buttons">button choice other than OK</param>
        /// <returns>DialogResult</returns>
        public static DialogResult ErrorDialog(Form form, string message = null, Exception ex = null, MessageBoxButtons buttons = MessageBoxButtons.OK)
        {
            if (message == null)
            {
                message = strings.ErrorOccured + (ex != null ? ": " + ex.Message : string.Empty);
            }
            if (ex != null && string.IsNullOrEmpty(ex.Message) == false)
            {
                message += Environment.NewLine + Environment.NewLine + ex.Message;
            }
#if DEBUG
            var capture = new StringBuilder();
            var e = ex;
            while (e != null)
            {
                capture.Append(new System.Diagnostics.StackTrace(e).ToString()).Append(Environment.NewLine);
                e = e.InnerException;
            }
            message += Environment.NewLine + Environment.NewLine + capture.ToString();

            if (ex != null)
            {
                WinAuthMain.LogException(ex);
            }
#endif

            return MessageBox.Show(form, message, WinAuthMain.APPLICATION_TITLE, buttons, MessageBoxIcon.Exclamation);
        }

        /// <summary>
        /// Show a confirmation Yes/No dialog
        /// </summary>
        /// <param name="form">owning form</param>
        /// <param name="message">message to display</param>
        /// <param name="buttons">button if other than YesNo</param>
        /// <returns>DialogResult</returns>
        public static DialogResult ConfirmDialog(Form form, string message, MessageBoxButtons buttons = MessageBoxButtons.YesNo, MessageBoxIcon icon = MessageBoxIcon.Question, MessageBoxDefaultButton defaultButton = MessageBoxDefaultButton.Button1) => MessageBox.Show(form, message, WinAuthMain.APPLICATION_TITLE, buttons, icon, defaultButton);

        /// <summary>
        /// Preload the context menu with the possible set of authenticator types
        /// </summary>
        private void LoadAddAuthenticatorTypes()
        {
            addAuthenticatorMenu.Items.Clear();

            ToolStripMenuItem subitem;
            var index = 0;
            foreach (var auth in WinAuthMain.REGISTERED_AUTHENTICATORS)
            {
                if (auth == null)
                {
                    addAuthenticatorMenu.Items.Add(new ToolStripSeparator());
                    continue;
                }

                subitem = new ToolStripMenuItem
                {
                    Text = auth.Name,
                    Name = "addAuthenticatorMenuItem_" + index++,
                    Tag = auth
                };
                if (string.IsNullOrEmpty(auth.Icon) == false)
                {
                    subitem.Image = new Bitmap(Assembly.GetExecutingAssembly().GetManifestResourceStream("WinAuth.Resources." + auth.Icon));
                    subitem.ImageAlign = ContentAlignment.MiddleLeft;
                    subitem.ImageScaling = ToolStripItemImageScaling.SizeToFit;
                }
                subitem.Click += addAuthenticatorMenu_Click;
                addAuthenticatorMenu.Items.Add(subitem);
            }
            //
            addAuthenticatorMenu.Items.Add(new ToolStripSeparator());
            //
            subitem = new ToolStripMenuItem
            {
                Text = strings.MenuImportText,
                Name = "importTextMenuItem",
                Image = new Bitmap(Assembly.GetExecutingAssembly().GetManifestResourceStream("WinAuth.Resources.TextIcon.png")),
                ImageAlign = ContentAlignment.MiddleLeft,
                ImageScaling = ToolStripItemImageScaling.SizeToFit
            };
            subitem.Click += importTextMenu_Click;
            addAuthenticatorMenu.Items.Add(subitem);
        }

        /// <summary>
        /// Unhook the current key hook
        /// </summary>
        private void UnhookHotkeys()
        {
            // remove the hotkey hook
            if (m_hook != null)
            {
                m_hook.UnHook();
                m_hook = null;
            }
        }

        /// <summary>
        /// Hook the hot key for the authenticator
        /// </summary>
        /// <param name="config">current config settings</param>
        private void HookHotkeys()
        {
            // unhook any old hotkeys
            UnhookHotkeys();

            // hook hotkey
            var keys = new List<WinAuthAuthenticator>();
            foreach (var auth in Config)
            {
                if (auth.HotKey != null)
                {
                    keys.Add(auth);
                }
            }
            if (keys.Count != 0)
            {
                m_hook = new KeyboardHook(this, keys);
                m_hook.KeyPressed += new KeyboardHook.KeyboardHookEventHandler(Hotkey_KeyPressed);
            }
        }

        #region Steam Notifications

        /// <summary>
        /// Unhook the Steam notifications
        /// </summary>
        public void UnhookSteam()
        {
            if (Config == null)
            {
                return;
            }

            foreach (var auth in Config)
            {
                if (auth.AuthenticatorData != null && auth.AuthenticatorData is SteamAuthenticator && ((SteamAuthenticator)auth.AuthenticatorData).Client != null)
                {
                    var client = ((SteamAuthenticator)auth.AuthenticatorData).GetClient();
                    client.ConfirmationEvent -= SteamClient_ConfirmationEvent;
                    client.ConfirmationErrorEvent -= SteamClient_ConfirmationErrorEvent;
                }
            }
        }

        /// <summary>
        /// Hook the Steam authenticators for notifications
        /// </summary>
        public void HookSteam()
        {
            UnhookSteam();
            if (Config == null)
            {
                return;
            }

            // do async as setting up clients can take time (Task.Factory.StartNew wait for UI so need to use new Thread(...))
            new Thread(new ThreadStart(() =>
            {
                foreach (var auth in Config)
                {
                    if (auth.AuthenticatorData != null && auth.AuthenticatorData is SteamAuthenticator)
                    {
                        var client = ((SteamAuthenticator)auth.AuthenticatorData).GetClient();
                        client.ConfirmationEvent += SteamClient_ConfirmationEvent;
                        client.ConfirmationErrorEvent += SteamClient_ConfirmationErrorEvent;
                    }
                }
            })).Start();
        }

        /// <summary>
        /// Display error message from Steam polling
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="message"></param>
        /// <param name="ex"></param>
        private void SteamClient_ConfirmationErrorEvent(object sender, string message, SteamClient.PollerAction action, Exception ex)
        {
            var steam = sender as SteamClient;
            var auth = Config.Cast<WinAuthAuthenticator>().Where(a => a.AuthenticatorData is SteamAuthenticator && ((SteamAuthenticator)a.AuthenticatorData).Serial == steam.Authenticator.Serial).FirstOrDefault();

            WinAuthMain.LogException(ex, true);

            if (action != SteamClient.PollerAction.SilentAutoConfirm)
            {
                // show the Notification window in the correct context
                Invoke(new ShowNotificationCallback(ShowNotification), new object[] {
                        auth,
                        auth.Name,
                        message,
                        false,
                        0
                    });
            }
        }

        /// <summary>
        /// Delegate for Steam notification
        /// </summary>
        /// <param name="auth">current Authenticator</param>
        /// <param name="title">title of notification</param>
        /// <param name="message">notification body</param>
        /// <param name="openOnClick">if can open on click</param>
        /// <param name="extraHeight">extra height (for errors)</param>
        public delegate void ShowNotificationCallback(WinAuthAuthenticator auth, string title, string message, bool openOnClick, int extraHeight);

        /// <summary>
        /// Display a new Notification for a Trading confirmation
        /// </summary>
        /// <param name="auth"></param>
        /// <param name="title"></param>
        /// <param name="message"></param>
        /// <param name="extraHeight"></param>
        public void ShowNotification(WinAuthAuthenticator auth, string title, string message, bool openOnClick, int extraHeight)
        {
            var notify = new Notification(title, message, 10000);
            if (extraHeight != 0)
            {
                notify.Height += extraHeight;
            }
            notify.Tag = auth;
            if (openOnClick == true)
            {
                notify.OnNotificationClicked += Notify_Click;
            }
            notify.Show();
        }

        /// <summary>
        /// The Notification window is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Notify_Click(object sender, EventArgs e)
        {
            var auth = ((Notification)sender).Tag as WinAuthAuthenticator;

            // ensure window is front
            BringToFront();
            Show();
            WindowState = FormWindowState.Normal;
            Activate();

            // show waiting
            Cursor.Current = Cursors.WaitCursor;

            // open the confirmations
            var item = authenticatorList.ContextMenuStrip.Items.Cast<ToolStripItem>().Where(i => i.Name == "showSteamTradesMenuItem").FirstOrDefault();
            authenticatorList.CurrentItem = authenticatorList.Items.Cast<AuthenticatorListitem>().Where(i => i.Authenticator == auth).FirstOrDefault();
            item.PerformClick();
        }

        /// <summary>
        /// Receive a new confirmation event from the SteamClient
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="confirmation"></param>
        /// <param name="action"></param>
        private void SteamClient_ConfirmationEvent(object sender, SteamClient.Confirmation confirmation, SteamClient.PollerAction action)
        {
            var steam = sender as SteamClient;

            var auth = Config.Cast<WinAuthAuthenticator>().Where(a => a.AuthenticatorData is SteamAuthenticator && ((SteamAuthenticator)a.AuthenticatorData).Serial == steam.Authenticator.Serial).FirstOrDefault();

            string title = null;
            string message = null;
            var openOnClick = false;
            var extraHeight = 0;

            if (action == SteamClient.PollerAction.AutoConfirm || action == SteamClient.PollerAction.SilentAutoConfirm)
            {
                if (steam.ConfirmTrade(confirmation.Id, confirmation.Key, true) == true)
                {
                    if (action != SteamClient.PollerAction.SilentAutoConfirm)
                    {
                        title = "Confirmed";
                        message = string.Format("<h1>{0}</h1><table width=250 cellspacing=0 cellpadding=0 border=0><tr><td width=40><img src=\"{1}\" /></td><td width=210>{2}<br/>{3}</td></tr></table>", auth.Name, confirmation.Image, confirmation.Details, confirmation.Traded);
                    }
                }
                else
                {
                    title = "Confirmation Failed";
                    message = string.Format("<h1>{0}</h1><table width=250 cellspacing=0 cellpadding=0 border=0><tr><td width=40><img src=\"{1}\" /></td><td width=210>{2}<br/>{3}<br/>Error: {4}</td></tr></table>", auth.Name, confirmation.Image, confirmation.Details, confirmation.Traded, steam.Error ?? "Unknown error");
                    extraHeight += 20;
                }
            }
            else if (confirmation.IsNew == true) // if (action == SteamClient.PollerAction.Notify)
            {
                title = "New Confirmation";
                message = string.Format("<h1>{0}</h1><table width=250 cellspacing=0 cellpadding=0 border=0><tr valign=top><td width=40><img src=\"{1}\" /></td><td width=210>{2}<br/>{3}</td></tr></table>", auth.Name, confirmation.Image, confirmation.Details, confirmation.Traded);
                openOnClick = true;
            }

            if (title != null)
            {
                // show the Notification window in the correct context
                Invoke(new ShowNotificationCallback(ShowNotification), new object[] {
                    auth,
                    title,
                    message,
                    openOnClick,
                    extraHeight
                });
            }
        }

        #endregion

        /// <summary>
        /// General Windows Message handler
        /// </summary>
        /// <param name="m"></param>
        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);

            // pick up the HotKey message from RegisterHotKey and call hook callback
            if (m.Msg == WinAPI.WM_HOTKEY)
            {
                var key = (Keys)(((int)m.LParam >> 16) & 0xffff);
                var modifier = (WinAPI.KeyModifiers)((int)m.LParam & 0xffff);

                if (m_hook != null)
                {
                    m_hook.KeyCallback(new KeyboardHookEventArgs(key, modifier));
                }
            }
            else if (m.Msg == WinAPI.WM_USER + 1)
            {
                // show the main form
                BringToFront();
                Show();
                WindowState = FormWindowState.Normal;
                Activate();
            }
        }

        /// <summary>
        /// A hotkey keyboard event occured, e.g. "Ctrl-Alt-C"
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void Hotkey_KeyPressed(object sender, KeyboardHookEventArgs e)
        {
            // avoid multiple keypresses being sent
            if (e.Authenticator != null && Monitor.TryEnter(m_sendingKeys) == true)
            {
                try
                {
                    // set Tag as HotKeyLauncher so we can pull back related authenticator and check for timeout
                    hotkeyTimer.Tag = new HotKeyLauncher(this, e.Authenticator);
                    hotkeyTimer.Enabled = true;

                    // mark event as handled
                    e.Handled = true;
                }
                finally
                {
                    Monitor.Exit(m_sendingKeys);
                }
            }
        }

        /// <summary>
        /// Timer tick for hotkey
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void hotkeyTimer_Tick(object sender, EventArgs e)
        {
            var data = hotkeyTimer.Tag as HotKeyLauncher;

            // check we don't wait forever
            if (data.Started.AddSeconds(5) < DateTime.Now)
            {
                hotkeyTimer.Enabled = false;
                return;
            }

            // wait until the modifiers are released
            if ((System.Windows.Forms.Control.ModifierKeys & Keys.Alt) != 0
                || (System.Windows.Forms.Control.ModifierKeys & Keys.Control) != 0
                || (System.Windows.Forms.Control.ModifierKeys & Keys.Shift) != 0)
            {
                return;
            }

            // cancel the timer
            hotkeyTimer.Enabled = false;

            // invoke the handler method in the correct context
            data.Form.Invoke((MethodInvoker)delegate
            { HandleHotkey(data.Authenticator); });
        }

        /// <summary>
        /// Process the pressed hotkey by performing the appropriate operation
        /// </summary>
        /// <param name="auth">Authenticator</param>
        private void HandleHotkey(WinAuthAuthenticator auth)
        {
            // get the code
            string code = null;
            try
            {
                code = auth.CurrentCode;
            }
            catch (EncryptedSecretDataException)
            {
                // if the authenticator is current protected we display the password window, get the code, and reprotect it
                // with a bit of window jiggling to make sure we get focus and then put it back

                // save the current window
                var fgwindow = WinAPI.GetForegroundWindow();
                var screen = Screen.FromHandle(fgwindow);
                var activewindow = IntPtr.Zero;
                if (Visible == true)
                {
                    activewindow = WinAPI.SetActiveWindow(Handle);
                    BringToFront();
                }

                var item = authenticatorList.Items.Cast<AuthenticatorListitem>().Where(i => i.Authenticator == auth).FirstOrDefault();
                code = authenticatorList.GetItemCode(item, screen);

                // restore active window
                if (activewindow != IntPtr.Zero)
                {
                    WinAPI.SetActiveWindow(activewindow);
                }
                WinAPI.SetForegroundWindow(fgwindow);
            }
            if (code != null)
            {
                // default to sending the code to the current window
                var keysend = new KeyboardSender(auth.HotKey.Window);
                string command = null;
                if (auth.HotKey.Action == HotKey.HotKeyActions.Notify)
                {
                    if (auth.CopyOnCode)
                    {
                        auth.CopyCodeToClipboard(this, code);
                    }
                    if (code.Length > 5)
                    {
                        code = code.Insert(code.Length / 2, " ");
                    }
                    notifyIcon.ShowBalloonTip(10000, auth.Name, code, ToolTipIcon.Info);
                }
                if (auth.HotKey.Action == HotKey.HotKeyActions.Copy)
                {
                    command = "{COPY}";
                }
                else if (auth.HotKey.Action == HotKey.HotKeyActions.Advanced)
                {
                    command = auth.HotKey.Advanced;
                }
                else if (auth.HotKey.Action == HotKey.HotKeyActions.Inject)
                {
                    command = "{CODE}";
                }
                if (command != null)
                {
                    keysend.SendKeys(this, command, code);
                }
            }
        }

        /// <summary>
        /// Run an action on the authenticator
        /// </summary>
        /// <param name="auth">Authenticator to use</param>
        /// <param name="action">Action to perform</param>
        private void RunAction(WinAuthAuthenticator auth, WinAuthConfig.NotifyActions action)
        {
            // get the code
            string code = null;
            try
            {
                code = auth.CurrentCode;
            }
            catch (EncryptedSecretDataException)
            {
                // if the authenticator is current protected we display the password window, get the code, and reprotect it
                // with a bit of window jiggling to make sure we get focus and then put it back

                // save the current window
                var fgwindow = WinAPI.GetForegroundWindow();
                var screen = Screen.FromHandle(fgwindow);
                var activewindow = IntPtr.Zero;
                if (Visible == true)
                {
                    activewindow = WinAPI.SetActiveWindow(Handle);
                    BringToFront();
                }

                var item = authenticatorList.Items.Cast<AuthenticatorListitem>().Where(i => i.Authenticator == auth).FirstOrDefault();
                code = authenticatorList.GetItemCode(item, screen);

                // restore active window
                if (activewindow != IntPtr.Zero)
                {
                    WinAPI.SetActiveWindow(activewindow);
                }
                WinAPI.SetForegroundWindow(fgwindow);
            }
            if (code != null)
            {
                var keysend = new KeyboardSender(auth.HotKey != null ? auth.HotKey.Window : null);
                string command = null;

                if (action == WinAuthConfig.NotifyActions.CopyToClipboard)
                {
                    command = "{COPY}";
                }
                else if (action == WinAuthConfig.NotifyActions.HotKey)
                {
                    command = auth.HotKey != null ? auth.HotKey.Advanced : null;
                }
                else // if (this.Config.NotifyAction == WinAuthConfig.NotifyActions.Notification)
                {
                    if (code.Length > 5)
                    {
                        code = code.Insert(code.Length / 2, " ");
                    }
                    notifyIcon.ShowBalloonTip(10000, auth.Name, code, ToolTipIcon.Info);
                }
                if (command != null)
                {
                    keysend.SendKeys(this, command, code);
                    if (Config.AutoExitAfterCopy && action == WinAuthConfig.NotifyActions.CopyToClipboard)
                    {
                        Close();
                    }
                }
            }
        }

        /// <summary>
        /// Put data into the clipboard
        /// </summary>
        /// <param name="data"></param>
        public void SetClipboardData(object data)
        {
            var clipRetry = false;
            do
            {
                try
                {
                    Clipboard.Clear();
                    Clipboard.SetDataObject(data, true, 4, 250);
                }
                catch (ExternalException)
                {
                    // only show an error the first time
                    clipRetry = (MessageBox.Show(this, strings.ClipboardInUse,
                        WinAuthMain.APPLICATION_NAME,
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes);
                }
            }
            while (clipRetry == true);
        }

        /// <summary>
        /// Get data from the clipboard
        /// </summary>
        /// <param name="format"></param>
        /// <returns></returns>
        public object GetClipboardData(Type format)
        {
            var clipRetry = false;
            do
            {
                try
                {
                    var clipdata = Clipboard.GetDataObject();
                    return (clipdata != null ? clipdata.GetData(format) : null);
                }
                catch (ExternalException)
                {
                    // only show an error the first time
                    clipRetry = (MessageBox.Show(this, strings.ClipboardInUse,
                        WinAuthMain.APPLICATION_NAME,
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes);
                }
            }
            while (clipRetry == true);

            return null;
        }

        /// <summary>
        /// Set the size of the form based on config AutoSize property
        /// </summary>
        private void setAutoSize()
        {
            if (Config.AutoSize == true)
            {
                if (Config.Count != 0)
                {
                    Width = Math.Max(420, authenticatorList.Margin.Horizontal + authenticatorList.GetMaxItemWidth() + (Width - authenticatorList.Width));
                }
                else
                {
                    Width = 420;
                }

                // Issue#175; take the smallest of full height or 62% screen height
                var height = Height - authenticatorList.Height;
                height += (Config.Count * authenticatorList.ItemHeight);
                Height = Math.Min(Screen.GetWorkingArea(this).Height * 62 / 100, height);

                Resizable = false;
            }
            else
            {
                Resizable = true;
                if (Config.Width != 0)
                {
                    Width = Config.Width;
                }
                if (Config.Height != 0)
                {
                    Height = Config.Height;
                }
            }
        }

        /// <summary>
        /// Can the renaming of an authenticator
        /// </summary>
        private void EndRenaming()
        {
            // set focus to form, so that the edit field will disappear if it is visble
            if (authenticatorList.IsRenaming == true)
            {
                authenticatorList.EndRenaming();
            }
        }

        /// <summary>
        /// Callback from the Updater if a newer version is available
        /// </summary>
        /// <param name="latest"></param>
        private void NewVersionAvailable(Version latest)
        {
            if (Updater != null && Updater.IsAutoCheck == true && latest != null && latest > Updater.CurrentVersion)
            {
                Invoke((MethodInvoker)delegate
                { newVersionLink.Text = "New version " + latest.ToString(3) + " available"; newVersionLink.Visible = true; });
            }
            else
            {
                Invoke((MethodInvoker)delegate
                { newVersionLink.Visible = false; });
            }
        }

        /// <summary>
        /// Show the Update form and update status if necessary
        /// </summary>
        private void ShowUpdaterForm()
        {
            var form = new UpdateCheckForm
            {
                Config = Config,
                Updater = Updater
            };
            if (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK)
            {
                NewVersionAvailable(Updater.LastKnownLatestVersion);
                SaveConfig();
            }
        }

        /// <summary>
        /// Set up the notify icon when the main form is shown
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void WinAuthForm_Shown(object sender, EventArgs e)
        {
            // if we use tray icon make sure it is set
            if (Config != null && Config.UseTrayIcon == true)
            {
                notifyIcon.Visible = true;
                notifyIcon.Text = Text;

                // if initially minizied, we need to hide
                if (WindowState == FormWindowState.Minimized)
                {
                    // hide this and metro owner
                    Form form = this;
                    do
                    {
                        form.Hide();
                    } while ((form = form.Owner) != null);
                }
            }

            // prompt to import v2
            if (string.IsNullOrEmpty(_existingv2Config) == false)
            {
                var importResult = MessageBox.Show(this,
                    string.Format(strings.LoadPreviousAuthenticator, _existingv2Config),
                    WinAuthMain.APPLICATION_TITLE,
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (importResult == System.Windows.Forms.DialogResult.Yes)
                {
                    importAuthenticatorFromV2(_existingv2Config);
                }
                _existingv2Config = null;
            }
        }

        /// <summary>
        /// Minimize to icon when closing or unbind and close
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void WinAuthForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            // keep in the tray when closing Form 
            if (Config != null && Config.UseTrayIcon == true && Visible == true && m_explictClose == false)
            {
                e.Cancel = true;
                notifyIcon.Visible = true;
                // hide this and metro owner
                Form form = this;
                do
                {
                    form.Hide();
                } while ((form = form.Owner) != null);
                return;
            }

            // remove the Steam hook
            UnhookSteam();

            // remove the hotkey hook
            UnhookHotkeys();

            // ensure the notify icon is closed
            notifyIcon.Visible = false;

            // save size if we are not autoresize
            if (Config != null && Config.AutoSize == false && (Config.Width != Width || Config.Height != Height))
            {
                Config.Width = Width;
                Config.Height = Height;
            }
            if (Config != null /* && this.Config.Position.IsEmpty == false */)
            {
                Config.Position = new Point(Left, Top);
            }

            // perform save if we have one pending
            if (_saveConfigTime != null)
            {
                SaveConfig(true);
            }
        }

        /// <summary>
        /// Click on a choice of new authenticator
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void addAuthenticatorMenu_Click(object sender, EventArgs e)
        {
            var menuitem = (ToolStripItem)sender;
            var registeredauth = menuitem.Tag as RegisteredAuthenticator;
            if (registeredauth != null)
            {
                // add the new authenticator
                var winauthauthenticator = new WinAuthAuthenticator();
                var added = false;

                if (registeredauth.AuthenticatorType == RegisteredAuthenticator.AuthenticatorTypes.BattleNet)
                {
                    var existing = 0;
                    string name;
                    do
                    {
                        name = "Battle.net" + (existing != 0 ? " (" + existing + ")" : string.Empty);
                        existing++;
                    } while (authenticatorList.Items.Cast<AuthenticatorListitem>().Where(a => a.Authenticator.Name == name).Count() != 0);

                    winauthauthenticator.Name = name;
                    winauthauthenticator.AutoRefresh = false;

                    // create the Battle.net authenticator
                    var form = new AddBattleNetAuthenticator
                    {
                        Authenticator = winauthauthenticator
                    };
                    added = (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK);
                }
                else if (registeredauth.AuthenticatorType == RegisteredAuthenticator.AuthenticatorTypes.Steam)
                {
                    // create the authenticator
                    var existing = 0;
                    string name;
                    do
                    {
                        name = "Steam" + (existing != 0 ? " (" + existing + ")" : string.Empty);
                        existing++;
                    } while (authenticatorList.Items.Cast<AuthenticatorListitem>().Where(a => a.Authenticator.Name == name).Count() != 0);

                    winauthauthenticator.Name = name;
                    winauthauthenticator.AutoRefresh = false;

                    var form = new AddSteamAuthenticator
                    {
                        Authenticator = winauthauthenticator
                    };
                    added = (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK);
                }
                else if (registeredauth.AuthenticatorType == RegisteredAuthenticator.AuthenticatorTypes.Google)
                {
                    // create the Google authenticator
                    // add the new authenticator
                    var existing = 0;
                    string name;
                    do
                    {
                        name = "Google" + (existing != 0 ? " (" + existing + ")" : string.Empty);
                        existing++;
                    } while (authenticatorList.Items.Cast<AuthenticatorListitem>().Where(a => a.Authenticator.Name == name).Count() != 0);
                    winauthauthenticator.Name = name;
                    winauthauthenticator.AutoRefresh = false;

                    var form = new AddGoogleAuthenticator
                    {
                        Authenticator = winauthauthenticator
                    };
                    added = (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK);
                }
                else if (registeredauth.AuthenticatorType == RegisteredAuthenticator.AuthenticatorTypes.Microsoft)
                {
                    // create the Microsoft authenticator
                    var existing = 0;
                    string name;
                    do
                    {
                        name = "Microsoft" + (existing != 0 ? " (" + existing + ")" : string.Empty);
                        existing++;
                    } while (authenticatorList.Items.Cast<AuthenticatorListitem>().Where(a => a.Authenticator.Name == name).Count() != 0);
                    winauthauthenticator.Name = name;
                    winauthauthenticator.AutoRefresh = false;

                    var form = new AddMicrosoftAuthenticator
                    {
                        Authenticator = winauthauthenticator
                    };
                    added = (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK);
                }
                else if (registeredauth.AuthenticatorType == RegisteredAuthenticator.AuthenticatorTypes.RFC6238_TIME)
                {
                    // create the Google authenticator
                    // add the new authenticator
                    var existing = 0;
                    string name;
                    do
                    {
                        name = "Authenticator" + (existing != 0 ? " (" + existing + ")" : string.Empty);
                        existing++;
                    } while (authenticatorList.Items.Cast<AuthenticatorListitem>().Where(a => a.Authenticator.Name == name).Count() != 0);
                    winauthauthenticator.Name = name;
                    winauthauthenticator.AutoRefresh = false;
                    winauthauthenticator.Skin = "WinAuthIcon.png";

                    var form = new AddAuthenticator
                    {
                        Authenticator = winauthauthenticator
                    };
                    added = (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK);
                }
                else if (registeredauth.AuthenticatorType == RegisteredAuthenticator.AuthenticatorTypes.OktaVerify)
                {
                    // create the Okta Verify authenticator
                    var existing = 0;
                    string name;
                    do
                    {
                        name = "Okta" + (existing != 0 ? " (" + existing + ")" : string.Empty);
                        existing++;
                    } while (authenticatorList.Items.Cast<AuthenticatorListitem>().Where(a => a.Authenticator.Name == name).Count() != 0);
                    winauthauthenticator.Name = name;
                    winauthauthenticator.AutoRefresh = false;

                    var form = new AddOktaVerifyAuthenticator
                    {
                        Authenticator = winauthauthenticator
                    };
                    added = (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK);
                }
                else
                {
                    throw new NotImplementedException(strings.AuthenticatorNotImplemented + ": " + registeredauth.AuthenticatorType.ToString());
                }

                if (added == true)
                {
                    // save off any new authenticators as a backup
                    WinAuthHelper.SaveToRegistry(Config, winauthauthenticator);

                    // first time we prompt for protection
                    if (Config.Count == 0)
                    {
                        var form = new ChangePasswordForm
                        {
                            PasswordType = Authenticator.PasswordTypes.Explicit
                        };
                        if (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK)
                        {
                            Config.PasswordType = form.PasswordType;
                            if ((Config.PasswordType & Authenticator.PasswordTypes.Explicit) != 0 && string.IsNullOrEmpty(form.Password) == false)
                            {
                                Config.Password = form.Password;
                            }
                        }
                    }

                    Config.Add(winauthauthenticator);
                    SaveConfig(true);
                    loadAuthenticatorList(winauthauthenticator);

                    // reset UI
                    setAutoSize();
                    introLabel.Visible = (Config.Count == 0);

                    // reset hotkeeys
                    HookHotkeys();
                }
            }
        }

        /// <summary>
        /// Click to import an text file of authenticators
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void importTextMenu_Click(object sender, EventArgs e)
        {
            var menuitem = (ToolStripItem)sender;

            var ofd = new OpenFileDialog
            {
                AddExtension = true,
                CheckFileExists = true,
                CheckPathExists = true
            };
            //
            var lastv2file = WinAuthHelper.GetLastV2Config();
            if (string.IsNullOrEmpty(lastv2file) == false)
            {
                ofd.InitialDirectory = Path.GetDirectoryName(lastv2file);
                ofd.FileName = Path.GetFileName(lastv2file);
            }
            //
            ofd.Filter = "WinAuth Files (*.xml)|*.xml|Text Files (*.txt)|*.txt|Zip Files (*.zip)|*.zip|PGP Files (*.pgp)|*.pgp|All Files (*.*)|*.*";
            ofd.RestoreDirectory = true;
            ofd.Title = WinAuthMain.APPLICATION_TITLE;
            if (ofd.ShowDialog(this) == System.Windows.Forms.DialogResult.OK)
            {
                importAuthenticator(ofd.FileName);
            }
        }

        /// <summary>
        /// Timer tick event
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void mainTimer_Tick(object sender, EventArgs e)
        {
            authenticatorList.Tick(sender, e);

            // if a save is due
            if (_saveConfigTime != null && _saveConfigTime.Value <= DateTime.Now)
            {
                SaveConfig();
            }
        }

        /// <summary>
        /// Click the Add button to add an authenticator
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void addAuthenticatorButton_Click(object sender, EventArgs e) => addAuthenticatorMenu.Show(addAuthenticatorButton, addAuthenticatorButton.Width, 0);

        /// <summary>
        /// Click the Options button to show menu
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void optionsButton_Click(object sender, EventArgs e) => optionsMenu.Show(optionsButton, optionsButton.Width - optionsMenu.Width, optionsButton.Height - 1);

        /// <summary>
        /// Double click notify to re-open
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void notifyIcon_DoubleClick(object sender, EventArgs e)
        {
            BringToFront();
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        /// <summary>
        /// Event fired when an authenticator is removed (i.e. deleted) from the list
        /// </summary>
        /// <param name="source"></param>
        /// <param name="args"></param>
        private void authenticatorList_ItemRemoved(object source, AuthenticatorListItemRemovedEventArgs args)
        {
            foreach (var auth in Config)
            {
                if (auth == args.Item.Authenticator)
                {
                    Config.Remove(auth);
                    break;
                }
            }

            // update UI
            setAutoSize();

            // if no authenticators, show intro text and remove any encryption
            if (Config.Count == 0)
            {
                introLabel.Visible = true;
                authenticatorList.Visible = false;
                Config.PasswordType = Authenticator.PasswordTypes.None;
                Config.Password = null;
            }

            // save the current config
            SaveConfig();
        }

        /// <summary>
        /// Event fired when an authenticator is dragged and dropped in the listbox
        /// </summary>
        /// <param name="source"></param>
        /// <param name="args"></param>
        private void authenticatorList_Reordered(object source, AuthenticatorListReorderedEventArgs args)
        {
            // set the new order of items in Config from that of the list
            var count = authenticatorList.Items.Count;
            for (var i = 0; i < count; i++)
            {
                var item = (AuthenticatorListitem)authenticatorList.Items[i];
                Config.Where(a => a == item.Authenticator).FirstOrDefault().Index = i;
            }
            // resort the config list
            Config.Sort();
            // update the notify menu
            loadNotifyMenu(notifyMenu);

            // update UI
            setAutoSize();

            // save the current config
            SaveConfig();
        }

        /// <summary>
        /// Double click an item in the list
        /// </summary>
        /// <param name="source"></param>
        /// <param name="args"></param>
        private void authenticatorList_DoubleClick(object source, AuthenticatorListDoubleClickEventArgs args) => RunAction(args.Authenticator, WinAuthConfig.NotifyActions.CopyToClipboard);

        /// <summary>
        /// Click in the main form
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void WinAuthForm_MouseDown(object sender, MouseEventArgs e) => EndRenaming();

        /// <summary>
        /// Click in the command panel
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void commandPanel_MouseDown(object sender, MouseEventArgs e) => EndRenaming();

        /// <summary>
        /// Resizing the form, we have to manually adjust the width and height of list else starting as minimized borks
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void WinAuthForm_Resize(object sender, EventArgs e)
        {
            SuspendLayout();
            if (_listoffset.Bottom != 0)
            {
                authenticatorList.Height = Height - _listoffset.Height;
                authenticatorList.Width = Width - _listoffset.Width;
            }
            ResumeLayout(true);
        }

        /// <summary>
        /// Set the config once resizing has completed
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void WinAuthForm_ResizeEnd(object sender, EventArgs e)
        {
            if (Config != null && Config.AutoSize == false)
            {
                Config.Width = Width;
                Config.Height = Height;
            }
        }

        /// <summary>
        /// Click the button to enter a password
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void passwordButton_Click(object sender, EventArgs e)
        {
            if (passwordField.Text.Trim().Length == 0)
            {
                passwordErrorLabel.Text = strings.EnterPassword;
                passwordErrorLabel.Tag = DateTime.Now.AddSeconds(3);
                passwordTimer.Enabled = true;
                return;
            }

            loadConfig(passwordField.Text);
            passwordField.Text = string.Empty;
        }

        /// <summary>
        /// Filtering the list
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void searchTextbox_changed(object sender, EventArgs e)
        {
            var txt = searchTextbox.Text.Trim();
            if (txt != "")
            {
                searchString = txt;
            }
            else
            {
                searchString = "";
            }
            noticeLabel.Text = "";
            loadAuthenticatorList();
        }
        string searchString = "";

        /// <summary>
        /// Remove the password error message after a few seconds
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void passwordTimer_Tick(object sender, EventArgs e)
        {
            if (passwordErrorLabel.Tag != null && (DateTime)passwordErrorLabel.Tag <= DateTime.Now)
            {
                passwordTimer.Enabled = false;
                passwordErrorLabel.Tag = null;
                passwordErrorLabel.Text = string.Empty;
            }
        }

        /// <summary>
        /// Catch pressing Enter in the password field
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void passwordField_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Return)
            {
                e.Handled = true;
                passwordButton_Click(sender, null);
            }
        }
        /// <summary>
        /// Catch pressing Enter in the searchbox
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void searchTextbox_KeyUp(object sender, KeyEventArgs e) => searchTextbox_changed(sender, null);

        /// <summary>
        /// If click the new version status link
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void newVersionLink_Click(object sender, EventArgs e)
        {
            if (System.Deployment.Application.ApplicationDeployment.IsNetworkDeployed == false)
            {
                ShowUpdaterForm();
            }
        }

        /// <summary>
        /// System time change event. We need to resync any unprotected authenticators
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void SystemEvents_TimeChanged(object sender, EventArgs e)
        {
            var cursor = Cursor.Current;
            Cursor.Current = Cursors.WaitCursor;
            foreach (var auth in Config)
            {
                if (auth.AuthenticatorData != null && auth.AuthenticatorData.RequiresPassword == false)
                {
                    try
                    {
                        auth.Sync();
                    }
                    catch (Exception) { }
                }
            }
            Cursor.Current = cursor;
        }

        #endregion

        #region Options menu

        /// <summary>
        /// Load the menu items for the options menu
        /// </summary>
        private void loadOptionsMenu(ContextMenuStrip menu)
        {
            ToolStripMenuItem menuitem;

            menu.Items.Clear();

            if (Config == null || Config.IsReadOnly == false)
            {
                menuitem = new ToolStripMenuItem(strings.MenuChangeProtection + "...")
                {
                    Name = "changePasswordOptionsMenuItem"
                };
                menuitem.Click += changePasswordOptionsMenuItem_Click;
                menu.Items.Add(menuitem);
                menu.Items.Add(new ToolStripSeparator() { Name = "changePasswordOptionsSeparatorItem" });
            }

            if (Config != null && Config.IsPortable == false)
            {
                menuitem = new ToolStripMenuItem(strings.MenuStartWithWindows)
                {
                    Name = "startWithWindowsOptionsMenuItem"
                };
                menuitem.Click += startWithWindowsOptionsMenuItem_Click;
                menu.Items.Add(menuitem);
            }

            menuitem = new ToolStripMenuItem(strings.MenuAlwaysOnTop)
            {
                Name = "alwaysOnTopOptionsMenuItem"
            };
            menuitem.Click += alwaysOnTopOptionsMenuItem_Click;
            menu.Items.Add(menuitem);

            menuitem = new ToolStripMenuItem(strings.MenuUseSystemTrayIcon)
            {
                Name = "useSystemTrayIconOptionsMenuItem"
            };
            menuitem.Click += useSystemTrayIconOptionsMenuItem_Click;
            menu.Items.Add(menuitem);

            menuitem = new ToolStripMenuItem(strings.MenuAutoSize)
            {
                Name = "autoSizeOptionsMenuItem"
            };
            menuitem.Click += autoSizeOptionsMenuItem_Click;
            menu.Items.Add(menuitem);

            menuitem = new ToolStripMenuItem(strings.CopySearchedSingle)
            {
                Name = "copySearchedSingleOptionsMenuItem"
            };
            menuitem.Click += copySearchedSingleOptionsMenuItem_Click;
            menu.Items.Add(menuitem);

            menuitem = new ToolStripMenuItem(strings.AutoExitAfterCopy)
            {
                Name = "autoExitAfterCopyOptionsMenuItem"
            };
            menuitem.Click += autoExitAfterCopyOptionsMenuItem_Click;
            menu.Items.Add(menuitem);

            menu.Items.Add(new ToolStripSeparator());

            menuitem = new ToolStripMenuItem(strings.MenuExport)
            {
                Name = "exportOptionsMenuItem"
            };
            menuitem.Click += exportOptionsMenuItem_Click;
            menu.Items.Add(menuitem);

            menu.Items.Add(new ToolStripSeparator());

            if (System.Deployment.Application.ApplicationDeployment.IsNetworkDeployed == false)
            {
                menuitem = new ToolStripMenuItem(strings.MenuUpdates + "...")
                {
                    Name = "aboutUpdatesMenuItem"
                };
                menuitem.Click += aboutUpdatesMenuItem_Click;
                menu.Items.Add(menuitem);

                menu.Items.Add(new ToolStripSeparator());
            }

            menuitem = new ToolStripMenuItem(strings.MenuAbout + "...")
            {
                Name = "aboutOptionsMenuItem"
            };
            menuitem.Click += aboutOptionMenuItem_Click;
            menu.Items.Add(menuitem);

            menu.Items.Add(new ToolStripSeparator());

            menuitem = new ToolStripMenuItem(strings.MenuExit)
            {
                Name = "exitOptionsMenuItem",
                ShortcutKeys = Keys.F4 | Keys.Alt
            };
            menuitem.Click += exitOptionMenuItem_Click;
            menu.Items.Add(menuitem);
        }

        /// <summary>
        /// Load the menu items for the notify menu
        /// </summary>
        private void loadNotifyMenu(ContextMenuStrip menu)
        {
            ToolStripMenuItem menuitem;
            ToolStripMenuItem subitem;

            menu.Items.Clear();

            menuitem = new ToolStripMenuItem(strings.MenuOpen)
            {
                Name = "openOptionsMenuItem"
            };
            menuitem.Click += openOptionsMenuItem_Click;
            menu.Items.Add(menuitem);
            menu.Items.Add(new ToolStripSeparator() { Name = "openOptionsSeparatorItem" });

            if (Config != null && Config.Count != 0)
            {
                // because of window size, we only show first 30.
                // @todo change to MRU
                var index = 1;
                foreach (var auth in Config.Take(30))
                {
                    menuitem = new ToolStripMenuItem(index.ToString() + ". " + auth.Name)
                    {
                        Name = "authenticatorOptionsMenuItem_" + index,
                        Tag = auth,
                        ShortcutKeyDisplayString = (auth.HotKey != null ? auth.HotKey.ToString() : null)
                    };
                    menuitem.Click += authenticatorOptionsMenuItem_Click;
                    menu.Items.Add(menuitem);
                    index++;
                }
                var separator = new ToolStripSeparator
                {
                    Name = "authenticatorOptionsSeparatorItem"
                };
                menu.Items.Add(separator);

                menuitem = new ToolStripMenuItem(strings.DefaultAction)
                {
                    Name = "defaultActionOptionsMenuItem"
                };
                menu.Items.Add(menuitem);
                subitem = new ToolStripMenuItem(strings.DefaultActionNotification)
                {
                    Name = "defaultActionNotificationOptionsMenuItem"
                };
                subitem.Click += defaultActionNotificationOptionsMenuItem_Click;
                menuitem.DropDownItems.Add(subitem);
                subitem = new ToolStripMenuItem(strings.DefaultActionCopyToClipboard)
                {
                    Name = "defaultActionCopyToClipboardOptionsMenuItem"
                };
                subitem.Click += defaultActionCopyToClipboardOptionsMenuItem_Click;
                menuitem.DropDownItems.Add(subitem);
                subitem = new ToolStripMenuItem(strings.DefaultActionHotkey)
                {
                    Name = "defaultActionHotkeyOptionsMenuItem"
                };
                subitem.Click += defaultActionHotkeyOptionsMenuItem_Click;
                menuitem.DropDownItems.Add(subitem);
                menu.Items.Add(menuitem);

                separator = new ToolStripSeparator
                {
                    Name = "authenticatorActionOptionsSeparatorItem"
                };
                menu.Items.Add(separator);
            }

            //if (this.Config != null)
            //{
            //	menuitem = new ToolStripMenuItem(strings.MenuUseSystemTrayIcon);
            //	menuitem.Name = "useSystemTrayIconOptionsMenuItem";
            //	menuitem.Click += useSystemTrayIconOptionsMenuItem_Click;
            //	menu.Items.Add(menuitem);

            //	menu.Items.Add(new ToolStripSeparator());
            //}

            menuitem = new ToolStripMenuItem(strings.MenuAbout + "...")
            {
                Name = "aboutOptionsMenuItem"
            };
            menuitem.Click += aboutOptionMenuItem_Click;
            menu.Items.Add(menuitem);

            menu.Items.Add(new ToolStripSeparator());

            menuitem = new ToolStripMenuItem(strings.MenuExit)
            {
                Name = "exitOptionsMenuItem",
                ShortcutKeys = Keys.F4 | Keys.Alt
            };
            menuitem.Click += exitOptionMenuItem_Click;
            menu.Items.Add(menuitem);
        }

        /// <summary>
        /// Set the state of the items when opening the Options menu
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void optionsMenu_Opening(object sender, CancelEventArgs e) => OpeningOptionsMenu(optionsMenu, e);

        /// <summary>
        /// Set the state of the items when opening the notify menu
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void notifyMenu_Opening(object sender, CancelEventArgs e) => OpeningNotifyMenu(notifyMenu, e);

        /// <summary>
        /// Set state of menuitems when opening the Options menu
        /// </summary>
        /// <param name="menu"></param>
        /// <param name="e"></param>
        private void OpeningOptionsMenu(ContextMenuStrip menu, CancelEventArgs e)
        {
            ToolStripItem item;
            ToolStripMenuItem menuitem;

            if (Config == null)
            {
                return;
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "changePasswordOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Enabled = (Config != null && Config.Count != 0);
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "openOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Visible = (Config.UseTrayIcon == true && Visible == false);
            }
            item = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "openOptionsSeparatorItem").FirstOrDefault();
            if (item != null)
            {
                item.Visible = (Config.UseTrayIcon == true && Visible == false);
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "startWithWindowsOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Checked = Config.StartWithWindows;
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "alwaysOnTopOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Checked = Config.AlwaysOnTop;
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "useSystemTrayIconOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Checked = Config.UseTrayIcon;
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "autoSizeOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Checked = Config.AutoSize;
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "copySearchedSingleOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Checked = Config.CopySearchedSingle;
            }


            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "autoExitAfterCopyOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Checked = Config.AutoExitAfterCopy;
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "autoSizeOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Checked = Config.AutoSize;
            }
        }

        /// <summary>
        /// Set state of menuitemns when opening the notify menu
        /// </summary>
        /// <param name="menu"></param>
        /// <param name="e"></param>
        private void OpeningNotifyMenu(ContextMenuStrip menu, CancelEventArgs e)
        {
            ToolStripItem item;
            ToolStripMenuItem menuitem;

            if (Config == null)
            {
                return;
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "changePasswordOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Enabled = (Config != null && Config.Count != 0);
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "openOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                menuitem.Visible = (Config.UseTrayIcon == true && Visible == false);
            }
            item = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "openOptionsSeparatorItem").FirstOrDefault();
            if (item != null)
            {
                item.Visible = (Config.UseTrayIcon == true && Visible == false);
            }

            menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "defaultActionOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            if (menuitem != null)
            {
                var subitem = menuitem.DropDownItems.Cast<ToolStripItem>().Where(t => t.Name == "defaultActionNotificationOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
                subitem.Checked = (Config.NotifyAction == WinAuthConfig.NotifyActions.Notification);

                subitem = menuitem.DropDownItems.Cast<ToolStripItem>().Where(t => t.Name == "defaultActionCopyToClipboardOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
                subitem.Checked = (Config.NotifyAction == WinAuthConfig.NotifyActions.CopyToClipboard);

                subitem = menuitem.DropDownItems.Cast<ToolStripItem>().Where(t => t.Name == "defaultActionHotkeyOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
                subitem.Checked = (Config.NotifyAction == WinAuthConfig.NotifyActions.HotKey);
            }

            //menuitem = menu.Items.Cast<ToolStripItem>().Where(t => t.Name == "useSystemTrayIconOptionsMenuItem").FirstOrDefault() as ToolStripMenuItem;
            //if (menuitem != null)
            //{
            //	menuitem.Checked = this.Config.UseTrayIcon;
            //}
        }

        /// <summary>
        /// Click the Change Password item of the Options menu
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void changePasswordOptionsMenuItem_Click(object sender, EventArgs e)
        {
            // confirm current password
            if ((Config.PasswordType & Authenticator.PasswordTypes.Explicit) != 0)
            {
                var invalidPassword = false;
                while (true)
                {
                    var checkform = new GetPasswordForm
                    {
                        InvalidPassword = invalidPassword
                    };
                    var result = checkform.ShowDialog(this);
                    if (result == DialogResult.Cancel)
                    {
                        return;
                    }
                    if (Config.IsPassword(checkform.Password) == true)
                    {
                        break;
                    }
                    invalidPassword = true;
                }
            }

            var form = new ChangePasswordForm
            {
                PasswordType = Config.PasswordType,
                HasPassword = ((Config.PasswordType & Authenticator.PasswordTypes.Explicit) != 0)
            };
            if (form.ShowDialog(this) == System.Windows.Forms.DialogResult.OK)
            {
                bool retry;
                var retrypasswordtype = Config.PasswordType;
                do
                {
                    retry = false;

                    Config.PasswordType = form.PasswordType;
                    if ((Config.PasswordType & Authenticator.PasswordTypes.Explicit) != 0 && string.IsNullOrEmpty(form.Password) == false)
                    {
                        Config.Password = form.Password;
                    }

                    try
                    {
                        SaveConfig(true);
                    }
                    catch (InvalidEncryptionException)
                    {
                        var result = WinAuthForm.ConfirmDialog(this, "Decryption test failed. Retry?", MessageBoxButtons.YesNo);
                        if (result == DialogResult.Yes)
                        {
                            retry = true;
                            continue;
                        }
                        Config.PasswordType = retrypasswordtype;
                    }
                } while (retry);
            }
        }

        /// <summary>
        /// Click the Open item of the Options menu
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void openOptionsMenuItem_Click(object sender, EventArgs e)
        {
            // show the main form
            BringToFront();
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        /// <summary>
        /// Click one of the context menu authenticators
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void authenticatorOptionsMenuItem_Click(object sender, EventArgs e)
        {
            var menuitem = (ToolStripMenuItem)sender;
            var auth = menuitem.Tag as WinAuthAuthenticator;
            var item = authenticatorList.Items.Cast<AuthenticatorListitem>().Where(i => i.Authenticator == auth).FirstOrDefault();
            if (item != null)
            {
                RunAction(auth, Config.NotifyAction);

                //string code = authenticatorList.GetItemCode(item);
                //if (code != null)
                //{
                //	if (auth.CopyOnCode)
                //	{
                //		auth.CopyCodeToClipboard(this, code);
                //	}
                //	if (code.Length > 5)
                //	{
                //		code = code.Insert(code.Length / 2, " ");
                //	}
                //	notifyIcon.ShowBalloonTip(10000, auth.Name, code, ToolTipIcon.Info);
                //}
            }
        }

        /// <summary>
        /// Click the Start With Windows menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void startWithWindowsOptionsMenuItem_Click(object sender, EventArgs e) => Config.StartWithWindows = !Config.StartWithWindows;

        /// <summary>
        /// Click the Always On Top menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void alwaysOnTopOptionsMenuItem_Click(object sender, EventArgs e) => Config.AlwaysOnTop = !Config.AlwaysOnTop;

        /// <summary>
        /// Click the Use Tray Icon menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void useSystemTrayIconOptionsMenuItem_Click(object sender, EventArgs e) => Config.UseTrayIcon = !Config.UseTrayIcon;

        /// <summary>
        /// Click the default action options menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void defaultActionNotificationOptionsMenuItem_Click(object sender, EventArgs e) => Config.NotifyAction = WinAuthConfig.NotifyActions.Notification;

        /// <summary>
        /// Click the default action options menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void defaultActionCopyToClipboardOptionsMenuItem_Click(object sender, EventArgs e) => Config.NotifyAction = WinAuthConfig.NotifyActions.CopyToClipboard;

        /// <summary>
        /// Click the default action options menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void defaultActionHotkeyOptionsMenuItem_Click(object sender, EventArgs e) => Config.NotifyAction = WinAuthConfig.NotifyActions.HotKey;

        /// <summary>
        /// Click the Auto Size menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void autoSizeOptionsMenuItem_Click(object sender, EventArgs e) => Config.AutoSize = !Config.AutoSize;

        /// <summary>
        /// Automatically copy the code when search result is only one item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void copySearchedSingleOptionsMenuItem_Click(object sender, EventArgs e) => Config.CopySearchedSingle = !Config.CopySearchedSingle;

        /// <summary>
        /// Automatically exit program after code is copied
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void autoExitAfterCopyOptionsMenuItem_Click(object sender, EventArgs e) => Config.AutoExitAfterCopy = !Config.AutoExitAfterCopy;

        /// <summary>
        /// Click the Export menu
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void exportOptionsMenuItem_Click(object sender, EventArgs e)
        {
            // confirm current password
            if ((Config.PasswordType & Authenticator.PasswordTypes.Explicit) != 0)
            {
                var invalidPassword = false;
                while (true)
                {
                    var checkform = new GetPasswordForm
                    {
                        InvalidPassword = invalidPassword
                    };
                    var result = checkform.ShowDialog(this);
                    if (result == DialogResult.Cancel)
                    {
                        return;
                    }
                    if (Config.IsPassword(checkform.Password) == true)
                    {
                        break;
                    }
                    invalidPassword = true;
                }
            }

            var exportform = new ExportForm();
            if (exportform.ShowDialog(this) == System.Windows.Forms.DialogResult.OK)
            {
                WinAuthHelper.ExportAuthenticators(this, Config, exportform.ExportFile, exportform.Password, exportform.PGPKey);
            }
        }

        /// <summary>
        /// Click the Updates menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void aboutUpdatesMenuItem_Click(object sender, EventArgs e) => ShowUpdaterForm();

        /// <summary>
        /// Click the About menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void aboutOptionMenuItem_Click(object sender, EventArgs e)
        {
            var form = new AboutForm
            {
                Config = Config
            };
            form.ShowDialog(this);
        }

        /// <summary>
        /// Click the Exit menu item
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void exitOptionMenuItem_Click(object sender, EventArgs e)
        {
            m_explictClose = true;
            Close();
        }

        #endregion

        #region Custom Events

        /// <summary>
        /// Event called when any property in the config is changed
        /// </summary>
        /// <param name="source"></param>
        /// <param name="args"></param>
        void OnConfigChanged(object source, ConfigChangedEventArgs args)
        {
            if (args.PropertyName == "AlwaysOnTop")
            {
                TopMost = Config.AlwaysOnTop;
            }
            else if (args.PropertyName == "UseTrayIcon")
            {
                var useTrayIcon = Config.UseTrayIcon;
                if (useTrayIcon == false && Visible == false)
                {
                    BringToFront();
                    Show();
                    WindowState = FormWindowState.Normal;
                    Activate();
                }
                notifyIcon.Visible = useTrayIcon;
            }
            else if (args.PropertyName == "AutoSize" || (args.PropertyName == "Authenticator" && args.AuthenticatorChangedEventArgs.Property == "Name"))
            {
                setAutoSize();
                Invalidate();
            }
            else if (args.PropertyName == "StartWithWindows")
            {
                if (Config.IsPortable == false)
                {
                    WinAuthHelper.SetStartWithWindows(Config.StartWithWindows);
                }
            }
            else if (args.AuthenticatorChangedEventArgs != null && args.AuthenticatorChangedEventArgs.Property == "HotKey")
            {
                // rehook hotkeys
                HookHotkeys();
            }

            // batch up saves so they can be done out of line
            SaveConfig();
        }
        #endregion

        /// <summary>
        /// Inner class used to form details of hot key
        /// </summary>
        class HotKeyLauncher
        {
            /// <summary>
            /// Owning form
            /// </summary>
            public WinAuthForm Form { get; set; }

            /// <summary>
            /// Hotkey authenticator
            /// </summary>
            public WinAuthAuthenticator Authenticator { get; set; }

            /// <summary>
            /// When hotkey was pressed
            /// </summary>
            public DateTime Started { get; set; }

            /// <summary>
            /// Create a new HotKeyLauncher object
            /// </summary>
            /// <param name="form">owning Form</param>
            /// <param name="auth">Authenticator</param>
            public HotKeyLauncher(WinAuthForm form, WinAuthAuthenticator auth)
            {
                Started = DateTime.Now;
                Form = form;
                Authenticator = auth;
            }
        }



    }
}
