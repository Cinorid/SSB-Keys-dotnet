using Rebex.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SSB.Keys
{

	public static class Utilities
	{
		public static string Hash(byte[] data)
		{
			return Sodium.Utilities.BinaryToBase64(Sodium.CryptoHash.Sha256(data)) + ".sha256";
		}

		public static string Hash(string data)
		{
			return Sodium.Utilities.BinaryToBase64(Sodium.CryptoHash.Sha256(data)) + ".sha256";
		}

		/// <summary>
		/// check to see parameter has sigil
		/// </summary>
		/// <param name="s"></param>
		/// <returns></returns>
		public static bool HasSigil(string s)
		{
			if (s.Contains("@") || s.Contains("%") || s.Contains("&"))
			{
				return true;
			}

			return false;
		}

		/// <summary>
		/// Get string tag
		/// </summary>
		/// <param name="s"></param>
		/// <returns></returns>
		public static string GetTag(string s)
		{
			if (!string.IsNullOrEmpty(s))
			{
				var i = s.IndexOf(".");
				return s.Substring(i + 1);
			}

			return string.Empty;
		}

		/// <summary>
		/// return a byte array from public, private or sig string
		/// </summary>
		/// <param name="s"></param>
		/// <returns></returns>
		public static byte[] ToByteArray(string s)
		{
			var i = s.IndexOf(".");
			if (i >= 0)
			{
				string base64 = s.Substring(0, i);
				return Convert.FromBase64String(base64);
			}
			else
			{
				return Convert.FromBase64String(s);
			}
		}

		internal static T[] SubArray<T>(this T[] data, int index, int length)
		{
			T[] result = new T[length];
			Array.Copy(data, index, result, 0, length);
			return result;
		}
	}
}
