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
	[Serializable]
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

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="privateKey"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public static string SignMessage(byte[] privateKey, byte[] message)
		{
			Ed25519 ed25519 = new Ed25519();
			ed25519.FromPrivateKey(privateKey);
			return Convert.ToBase64String(ed25519.SignMessage(message)) + ".sig" + ".ed25519";
		}

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="privateKey"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public static string SignMessage(string privateKey, string message)
		{
			var _privateKey = Convert.FromBase64String(privateKey.Replace(".ed25519", ""));
			var _message = Encoding.UTF8.GetBytes(message);

			return SignMessage(_privateKey, _message);
		}

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public static string SignMessage(Keys keys, string message)
		{
			return SignMessage(keys.Private, message);
		}

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public static string SignMessage(Keys keys, byte[] message)
		{
			var _privateKey = Convert.FromBase64String(keys.Private.Replace(".ed25519", ""));

			return SignMessage(_privateKey, message);
		}

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="message"></param>
		/// <returns></returns>
		public string SignMessage(string message)
		{
			return SignMessage(this, message);
		}

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="message"></param>
		/// <returns></returns>
		public string SignMessage(byte[] message)
		{
			return SignMessage(this, message);
		}

		/// <summary>
		/// sign object using a key
		/// </summary>
		/// <param name="privateKey"></param>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static string SignObject(byte[] privateKey, object obj)
		{
			var _obj = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(obj));

			return SignMessage(privateKey, _obj);
		}

		/// <summary>
		/// sign object using a key
		/// </summary>
		/// <param name="privateKey"></param>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static string SignObject(string privateKey, object obj)
		{
			var _privateKey = Convert.FromBase64String(privateKey.Replace(".ed25519", ""));

			return SignObject(_privateKey, obj);
		}

		/// <summary>
		/// sign object using a key
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static string SignObject(Keys keys, object obj)
		{
			return SignObject(keys.Private, obj);
		}

		/// <summary>
		/// sign object using a key
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public string SignObject(object obj)
		{
			return SignObject(this, obj);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="publicKey"></param>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public static bool VerifyMessage(byte[] publicKey, byte[] sign, byte[] message)
		{
			Ed25519 ed25519 = new Ed25519();
			ed25519.FromPublicKey(publicKey);
			return ed25519.VerifyMessage(message, sign);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="publicKey"></param>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public static bool VerifyMessage(string publicKey, string sign, string message)
		{
			var _publicKey = Convert.FromBase64String(publicKey.Replace(".ed25519", ""));
			var _message = Encoding.UTF8.GetBytes(message);
			var _sign = Convert.FromBase64String(sign.Replace(".ed25519", "").Replace(".sig", ""));

			return VerifyMessage(_publicKey, _sign, _message);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public static bool VerifyMessage(Keys keys, string sign, string message)
		{
			return VerifyMessage(keys.Public, sign, message);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public static bool VerifyMessage(Keys keys, byte[] sign, byte[] message)
		{
			var _publicKey = Convert.FromBase64String(keys.Public.Replace(".ed25519", ""));

			return VerifyMessage(_publicKey, sign, message);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public bool VerifyMessage(string sign, string message)
		{
			return Keys.VerifyMessage(this.Public, sign, message);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public bool VerifyMessage(string sign, byte[] message)
		{
			var _sign = Convert.FromBase64String(sign.Replace(".ed25519", "").Replace(".sig", ""));

			return Keys.VerifyMessage(this, _sign, message);
		}

		/// <summary>
		/// verify signed object using a key
		/// </summary>
		/// <param name="publicKey"></param>
		/// <param name="sign"></param>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static bool VerifyObject(byte[] publicKey, byte[] sign, object obj)
		{
			var _obj = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(obj));
			return VerifyMessage(publicKey, sign, _obj);
		}

		/// <summary>
		/// verify signed object using a key
		/// </summary>
		/// <param name="publicKey"></param>
		/// <param name="sign"></param>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static bool VerifyObject(string publicKey, string sign, object obj)
		{
			var _publicKey = Convert.FromBase64String(publicKey.Replace(".ed25519", ""));
			var _sign = Convert.FromBase64String(sign.Replace(".ed25519", "").Replace(".sig", ""));

			return VerifyObject(_publicKey, _sign, obj);
		}

		/// <summary>
		/// verify signed object using a key
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="sign"></param>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static bool VerifyObject(Keys keys, string sign, object obj)
		{
			return VerifyObject(keys.Public, sign, obj);
		}

		/// <summary>
		/// verify signed object using a key
		/// </summary>
		/// <param name="sign"></param>
		/// <param name="obj"></param>
		/// <returns></returns>
		public bool VerifyObject(string sign, object obj)
		{
			return Keys.VerifyObject(this.Public, sign, obj);
		}

		/// <summary>
		/// Clone a Keys object
		/// </summary>
		/// <param name="keys"></param>
		/// <returns></returns>
		public static Keys Clone(Keys keys)
		{
			if (!typeof(Keys).IsSerializable)
			{
				throw new ArgumentException("The type must be serializable.", "source");
			}

			// Don't serialize a null object, simply return the default for that object
			if (Object.ReferenceEquals(keys, null))
			{
				return default(Keys);
			}

			System.Runtime.Serialization.IFormatter formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
			System.IO.Stream stream = new System.IO.MemoryStream();
			using (stream)
			{
				formatter.Serialize(stream, keys);
				stream.Seek(0, System.IO.SeekOrigin.Begin);
				return (Keys)formatter.Deserialize(stream);
			}
		}

		/// <summary>
		/// Clone a Keys object
		/// </summary>
		/// <returns></returns>
		public Keys Clone()
		{
			return Keys.Clone(this);
		}
	}
}
