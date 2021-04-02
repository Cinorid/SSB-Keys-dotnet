using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace SSB.Keys
{
	/// <summary>
	/// Handling Scret File Operations
	/// </summary>
	public class Storage
	{
		/// <summary>
		/// Default file name of secret file
		/// </summary>
		public static string SecretFileName { get; set; } = "secret";

		/// <summary>
		/// Generate Secret File Content
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="legacy"></param>
		/// <returns></returns>
		public static string ConstructKeys(Keys keys, bool legacy)
		{
			string res =
				"# WARNING: Never show this to anyone." + Environment.NewLine +
				"# WARNING: Never edit it or use it on multiple devices at once." + Environment.NewLine +
				"#" + Environment.NewLine +
				"# This is your SECRET, it gives you magical powers. With your secret you can" + Environment.NewLine +
				"# sign your messages so that your friends can verify that the messages came" + Environment.NewLine +
				"# from you. If anyone learns your secret, they can use it to impersonate you." + Environment.NewLine +
				"#" + Environment.NewLine +
				"# If you use this secret on more than one device you will create a fork and" + Environment.NewLine +
				"# your friends will stop replicating your content." + Environment.NewLine +
				"#" + Environment.NewLine +
				(legacy ? keys.Private : Keys.ToString(keys)) + "" + Environment.NewLine +
				"#" + Environment.NewLine +
				"# The only part of this file that's safe to share is your public name:" + Environment.NewLine +
				"#" + Environment.NewLine +
				"#   " + keys.ID;

			return res;
		}

		/// <summary>
		/// Load Secret File
		/// </summary>
		/// <param name="keysFilePath"></param>
		/// <returns></returns>
		public static Keys LoadFile(string keysFilePath)
		{
			var keyText = File.ReadAllText(keysFilePath, Encoding.ASCII);
			return ReconstructKeys(keyText);
		}

		/// <summary>
		/// Load Secret File Async
		/// </summary>
		/// <param name="keysFilePath"></param>
		/// <returns></returns>
		public static async Task<Keys> LoadFileAsync(string keysFilePath)
		{
			return LoadFile(keysFilePath);
		}

		/// <summary>
		/// Generate and Save Secret File
		/// </summary>
		/// <param name="fileName"></param>
		/// <param name="curve"></param>
		/// <param name="legacy"></param>
		/// <returns></returns>
		public static Keys CreateFile(string fileName, string curve = "ed25519", bool legacy = false)
		{
			if (string.IsNullOrEmpty(fileName)) throw new ArgumentException("empty or null file path not allowed");

			var keys = Keys.Generate();
			var keyText = Storage.ConstructKeys(keys, legacy);
			File.WriteAllText(fileName, keyText, Encoding.ASCII);
			return keys;
		}

		/// <summary>
		/// Generate and save Secret file Async
		/// </summary>
		/// <param name="fileName"></param>
		/// <param name="curve"></param>
		/// <param name="legacy"></param>
		/// <returns></returns>
		public static async Task<Keys> CreateFileAsync(string fileName, string curve = "ed25519", bool legacy = false)
		{
			return CreateFile(fileName, curve, legacy);
		}

		/// <summary>
		/// Load Secret vile vontent into memory
		/// </summary>
		/// <param name="keysText"></param>
		/// <returns></returns>
		public static Keys ReconstructKeys(string keysText)
		{
			var lines = keysText.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

			string noneCommentLines = string.Empty;
			for (int i = 0; i < lines.Length; i++)
			{
				if (!lines[i].StartsWith("#"))
				{
					noneCommentLines += lines[i] + Environment.NewLine;
				}
			}

			return Keys.FromString(noneCommentLines);
		}
	}
}
