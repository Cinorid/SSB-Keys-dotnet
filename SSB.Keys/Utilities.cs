using Rebex.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SSB.Keys
{
	public class Utilities
	{
		static SHA256 sha256 = SHA256.Create();

		public static byte[] Hash(byte[] data, Encoding encoding)
		{
			if (data.GetType() == typeof(string) && encoding == null)
			{
				return sha256.ComputeHash(data);
			}

			return new byte[0];
		}

		public static bool hasSigil(string s)
		{
			if (s.Contains("@") || s.Contains("%") || s.Contains("&"))
			{
				return true;
			}

			return false;
		}
	}
}
