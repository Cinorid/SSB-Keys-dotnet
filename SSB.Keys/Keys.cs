using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using Rebex.Security.Cryptography;

namespace SSB.Keys
{
	/// <summary>
	/// keyfile operations for SSB
	/// </summary>
	public class Keys
	{
		/// <summary>
		/// Elliptic-curve cryptography algorithms
		/// </summary>
		[JsonProperty("curve")]
		public string Curve { get; set; } = "ed25519";

		/// <summary>
		/// Public key
		/// </summary>
		[JsonProperty("public")]
		public string Public { get; set; }

		/// <summary>
		/// SSB Private key
		/// </summary>
		[JsonProperty("private")]
		public string Private { get; set; }

		/// <summary>
		/// SSB ID
		/// </summary>
		[JsonProperty("id")]
		public string ID { get; set; }

		private Ed25519 ed25519 = new Ed25519();

		/// <summary>
		/// check equality of SSB keys
		/// </summary>
		/// <param name="keys">target SSB keys</param>
		/// <returns>result of equality</returns>
		public override bool Equals(object keys)
		{
			if (keys != null)
			{
				if (keys.GetHashCode() == GetHashCode())
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// A simple algorithm to distinguish between two SSB keys
		/// </summary>
		/// <returns>Numeric hash</returns>
		public override int GetHashCode()
		{
			int hashCode = 0;

			unchecked
			{
				if (Curve != null)
				{
					foreach (char c in Curve)
					{
						hashCode *= c.GetHashCode();
					}
				}

				if (Public != null)
				{
					foreach (char c in Public)
					{
						hashCode *= c.GetHashCode();
					}
				}

				if (Private != null)
				{
					foreach (char c in Private)
					{
						hashCode *= c.GetHashCode();
					}
				}

				if (ID != null)
				{
					foreach (char c in ID)
					{
						hashCode *= c.GetHashCode();
					}
				}

				return hashCode;
			}
		}

		/// <summary>
		/// Converts SSB keys to a indented Json string
		/// </summary>
		/// <returns>Equivalent Json string</returns>
		public override string ToString()
		{
			return Keys.ToString(this);
		}

		/// <summary>
		/// Converts SSB keys to a indented Json string
		/// </summary>
		/// <param name="keys">SSB keys object</param>
		/// <returns>Equivalent Json string</returns>
		public static string ToString(Keys keys)
		{
			if (keys != null)
			{
				return JsonConvert.SerializeObject(keys, Formatting.Indented);
			}

			return null;
		}

		/// <summary>
		/// Converts a Json string to SSB keys
		/// </summary>
		/// <param name="text">Json string</param>
		/// <returns>Equivalent SSB keys</returns>
		public static Keys FromString(string text)
		{
			if (!string.IsNullOrEmpty(text))
			{
				return (Keys)JsonConvert.DeserializeObject(text, typeof(Keys));
			}

			return null;
		}

		/// <summary>
		/// Generate new Keys
		/// </summary>
		/// <returns></returns>
		public static Keys Generate()
		{
			return Generate(null);
		}

		/// <summary>
		/// Generate new Keys from seed
		/// </summary>
		/// <param name="seed"></param>
		/// <returns></returns>
		public static Keys Generate(byte[] seed)
		{
			if (seed == null)
			{
				Random rnd = new Random();
				seed = new byte[32];
				rnd.NextBytes(seed);
			}

			Ed25519 ed25519 = new Ed25519();
			ed25519.FromSeed(seed);
			var secretKey = ed25519.GetPrivateKey();
			var publicKey = ed25519.GetPublicKey();

			var _public = Convert.ToBase64String(publicKey) + ".ed25519";
			var _private = Convert.ToBase64String(secretKey) + ".ed25519";

			var keys = new Keys
			{
				Curve = "ed25519",
				Public = _public,
				Private = _private,
				ID = "@" + _public,
			};

			return keys;
		}

		public static string SignMessage(byte[] privateKey, byte[] message)
		{
			Ed25519 ed25519 = new Ed25519();
			ed25519.FromPrivateKey(privateKey);
			return Convert.ToBase64String(ed25519.SignMessage(message)) + ".sig" + ".ed25519";
		}

		public static string SignMessage(string privateKey, string message)
		{
			var _privateKey = Convert.FromBase64String(privateKey.Replace(".ed25519", ""));
			var _message = Encoding.UTF8.GetBytes(message);

			return SignMessage(_privateKey, _message);
		}

		public static string SignMessage(Keys keys, string message)
		{
			return SignMessage(keys.Private, message);
		}

		public static string SignMessage(Keys keys, byte[] message)
		{
			var _privateKey = Convert.FromBase64String(keys.Private.Replace(".ed25519", ""));

			return SignMessage(_privateKey, message);
		}

		public string SignMessage(string message)
		{
			return SignMessage(this, message);
		}

		public string SignMessage(byte[] message)
		{
			return SignMessage(this, message);
		}

		public static bool VerifyMessage(byte[] publicKey, byte[] sign, byte[] message)
		{
			Ed25519 ed25519 = new Ed25519();
			ed25519.FromPublicKey(publicKey);
			return ed25519.VerifyMessage(message, sign);
		}

		public static bool VerifyMessage(string publicKey, string sign, string message)
		{
			var _publicKey = Convert.FromBase64String(publicKey.Replace(".ed25519", ""));
			var _message = Encoding.UTF8.GetBytes(message);
			var _sign = Convert.FromBase64String(sign.Replace(".ed25519", "").Replace(".sig", ""));

			return VerifyMessage(_publicKey, _sign, _message);
		}

		public static bool VerifyMessage(Keys keys, string sign, string message)
		{
			return VerifyMessage(keys.Public, sign, message);
		}

		public static bool VerifyMessage(Keys keys, byte[] sign, byte[] message)
		{
			var _publicKey = Convert.FromBase64String(keys.Public.Replace(".ed25519", ""));

			return VerifyMessage(_publicKey, sign, message);
		}

		public bool VerifyMessage(string sign, string message)
		{
			return Keys.VerifyMessage(this.Public, sign, message);
		}

		public bool VerifyMessage(string sign, byte[] message)
		{
			var _sign = Convert.FromBase64String(sign.Replace(".ed25519", "").Replace(".sig", ""));

			return Keys.VerifyMessage(this, _sign, message);
		}
	}
}
