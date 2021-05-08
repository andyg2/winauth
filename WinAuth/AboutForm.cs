﻿/*
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
using System.IO;
using System.Xml;

namespace WinAuth
{
    /// <summary>
    /// Show the About form
    /// </summary>
    public partial class AboutForm : ResourceForm
    {
        /// <summary>
        /// Current config object
        /// </summary>
        public WinAuthConfig Config { get; set; }

        /// <summary>
        /// Create the form
        /// </summary>
        public AboutForm()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Load the about form
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void AboutForm_Load(object sender, EventArgs e)
        {
            // get the version of the application
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            var debug = string.Empty;
#if DEBUG
            debug += " (DEBUG)";
#endif
            aboutLabel.Text = string.Format(aboutLabel.Text, version.ToString(3) + debug, DateTime.Today.Year);
        }

        /// <summary>
        /// Click the close button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void closeButton_Click(object sender, EventArgs e) => Close();

        /// <summary>
        /// Click the report button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void reportButton_Click(object sender, EventArgs e)
        {
            // display the error form, loading it with current authenticator data
            var errorreport = new DiagnosticForm();
            errorreport.Config = Config;
            if (string.IsNullOrEmpty(errorreport.Config.Filename) == false)
            {
                errorreport.ConfigFileContents = File.ReadAllText(errorreport.Config.Filename);
            }
            else
            {
                using (var ms = new MemoryStream())
                {
                    var settings = new XmlWriterSettings();
                    settings.Indent = true;
                    using (var writer = XmlWriter.Create(ms, settings))
                    {
                        Config.WriteXmlString(writer);
                    }
                    ms.Position = 0;
                    errorreport.ConfigFileContents = new StreamReader(ms).ReadToEnd();
                }
            }
            errorreport.ShowDialog(this);
        }
    }
}
