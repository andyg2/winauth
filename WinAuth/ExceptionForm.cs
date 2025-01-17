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
#if !DEBUG
using System.Diagnostics;
#endif
using System.Drawing;
#if !DEBUG
using System.IO;
using System.Reflection;
using System.Text;
using System.Xml;
#endif
using WinAuth.Resources;

namespace WinAuth
{
    /// <summary>
    /// General error report form
    /// </summary>
    public partial class ExceptionForm : ResourceForm
    {
        /// <summary>
        /// Exception that caused the error report
        /// </summary>
        public Exception ErrorException { get; set; }

        /// <summary>
        /// Current config
        /// </summary>
        public WinAuthConfig Config { get; set; }

        /// <summary>
        /// Create the  Form
        /// </summary>
        public ExceptionForm()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Load the error report form
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ExceptionForm_Load(object sender, EventArgs e)
        {
            errorIcon.Image = SystemIcons.Error.ToBitmap();
            Height = detailsButton.Top + detailsButton.Height + 45;

            errorLabel.Text = string.Format(errorLabel.Text, ErrorException != null ? ErrorException.Message : strings.UnknownError);

            // build data
#if DEBUG
            dataText.Text = string.Format("{0}\n\n{1}", ErrorException.Message, new System.Diagnostics.StackTrace(ErrorException).ToString());
#else
            try
            {
                dataText.Text = WinAuthHelper.PGPEncrypt(BuildDiagnostics(), WinAuthHelper.WINAUTH_PGP_PUBLICKEY);
            }
            catch (Exception ex)
            {
                dataText.Text = string.Format("{0}\n\n{1}", ex.Message, new StackTrace(ex).ToString());
            }
#endif
        }

#if !DEBUG
        /// <summary>
        /// Build a diagnostics string for the current Config and any exception that had been thrown
        /// </summary>
        /// <returns>diagnostics information</returns>
        private string BuildDiagnostics()
        {
            var diag = new StringBuilder();

            if (Version.TryParse(FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion, out var version))
            {
                diag.Append("Version:" + version.ToString(4));
            }

            // add winauth log
            try
            {
                var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), WinAuthMain.APPLICATION_NAME);
                if (Directory.Exists(dir))
                {
                    var winauthlog = Path.Combine(dir, "winauth.log");
                    if (File.Exists(winauthlog))
                    {
                        diag.Append("--WINAUTH.LOG--").Append(Environment.NewLine);
                        diag.Append(File.ReadAllText(winauthlog)).Append(Environment.NewLine).Append(Environment.NewLine);
                    }

                    // add authenticator.xml
                    foreach (var file in Directory.GetFiles(dir, "*.xml"))
                    {
                        diag.Append("--" + file + "--").Append(Environment.NewLine);
                        diag.Append(File.ReadAllText(file)).Append(Environment.NewLine).Append(Environment.NewLine);
                    }
                }
            }
            catch (Exception) { }

            // add the current config
            if (Config != null)
            {
                using (var ms = new MemoryStream())
                {
                    var settings = new XmlWriterSettings
                    {
                        Indent = true
                    };
                    using (var xml = XmlWriter.Create(ms, settings))
                    {
                        Config.WriteXmlString(xml);
                    }

                    ms.Position = 0;

                    diag.Append("-- Config --").Append(Environment.NewLine);
                    diag.Append(new StreamReader(ms).ReadToEnd()).Append(Environment.NewLine).Append(Environment.NewLine);
                }
            }

            // add the exception
            if (ErrorException != null)
            {
                diag.Append("--EXCEPTION--").Append(Environment.NewLine);

                var ex = ErrorException;
                while (ex != null)
                {
                    diag.Append("Stack: ").Append(ex.Message).Append(Environment.NewLine).Append(new StackTrace(ex).ToString()).Append(Environment.NewLine);
                    ex = ex.InnerException;
                }
                if (ErrorException is InvalidEncryptionException invalidEncryptionException)
                {
                    diag.Append("Plain: " + invalidEncryptionException.Plain).Append(Environment.NewLine);
                    diag.Append("Password: " + invalidEncryptionException.Password).Append(Environment.NewLine);
                    diag.Append("Encrypted: " + invalidEncryptionException.Encrypted).Append(Environment.NewLine);
                    diag.Append("Decrypted: " + invalidEncryptionException.Decrypted).Append(Environment.NewLine);
                }
                else if (ErrorException is InvalidSecretDataException invalidSecretDataException)
                {
                    diag.Append("EncType: " + invalidSecretDataException.EncType).Append(Environment.NewLine);
                    diag.Append("Password: " + invalidSecretDataException.Password).Append(Environment.NewLine);
                    foreach (var data in invalidSecretDataException.Decrypted)
                    {
                        diag.Append("Data: " + data).Append(Environment.NewLine);
                    }
                }
            }

            return diag.ToString();
        }
#endif

        /// <summary>
        /// Click the Quit button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void QuitButton_Click(object sender, EventArgs e) => Close();

        /// <summary>
        /// Click the Continue button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ContinueButton_Click(object sender, EventArgs e) => Close();

        /// <summary>
        /// Click to show the details
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void DetailsButton_Click(object sender, EventArgs e)
        {
            dataText.Visible = !dataText.Visible;
            if (dataText.Visible)
            {
                detailsButton.Text = strings.HideDetails;
                Height += 160;
            }
            else
            {
                detailsButton.Text = strings._ExceptionForm_detailsButton_;
                Height -= 160;
            }
        }
    }
}
