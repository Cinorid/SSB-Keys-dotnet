using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Rebex.Security.Cryptography;
using System.Linq;

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
				RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
				seed = new byte[32];
				rng.GetBytes(seed);
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
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
		public static string SignMessage(byte[] privateKey, byte[] message)
		{
			if (privateKey == null || privateKey.Length != 64) throw new InvalidOperationException("Invalid private key format");

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
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
		public static string SignMessage(Keys keys, string message)
		{
			return SignMessage(keys.Private, message);
		}

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="privateKeys"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
		public static string SignMessage(string privateKeys, byte[] message)
		{
			var _privateKey = Convert.FromBase64String(privateKeys.Replace(".ed25519", ""));

			return SignMessage(_privateKey, message);
		}

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
		public string SignMessage(string message)
		{
			return SignMessage(this, message);
		}

		/// <summary>
		/// sign message using a key
		/// </summary>
		/// <param name="message"></param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
		public static string SignObject(Keys keys, object obj)
		{
			return SignObject(keys.Private, obj);
		}

		/// <summary>
		/// sign object using a key
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException">Invalid private key format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
		public static bool VerifyMessage(byte[] publicKey, byte[] sign, byte[] message)
		{
			if (publicKey == null || publicKey.Length != 32) throw new InvalidOperationException("Invalid public key format");
			if (sign == null || sign.Length != 64) throw new InvalidOperationException("Invalid signature format");

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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
		public static bool VerifyMessage(Keys keys, byte[] sign, byte[] message)
		{
			var _publicKey = Convert.FromBase64String(keys.Public.Replace(".ed25519", ""));

			return VerifyMessage(_publicKey, sign, message);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="keys"></param>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
		public static bool VerifyMessage(Keys keys, string sign, byte[] message)
		{
			var _publicKey = Convert.FromBase64String(keys.Public.Replace(".ed25519", ""));
			var _sign = Convert.FromBase64String(sign.Replace(".ed25519", "").Replace(".sig", ""));

			return VerifyMessage(_publicKey, _sign, message);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="publicKeys"></param>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
		public static bool VerifyMessage(string publicKeys, string sign, byte[] message)
		{
			var _publicKey = Convert.FromBase64String(publicKeys.Replace(".ed25519", ""));
			var _sign = Convert.FromBase64String(sign.Replace(".ed25519", "").Replace(".sig", ""));

			return VerifyMessage(_publicKey, _sign, message);
		}

		/// <summary>
		/// verify signed message using a key
		/// </summary>
		/// <param name="sign"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
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
		/// <exception cref="InvalidOperationException">Invalid public key format</exception>
		/// <exception cref="InvalidOperationException">Invalid signature format</exception>
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

		public static byte[] SecretKeyToPrivateBoxSecret(string privateKeys)
		{
			return Sodium.PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(Utilities.ToByteArray(privateKeys));
		}

		public static byte[] SecretKeyToPrivateBoxSecret(Keys keys)
		{
			return SecretKeyToPrivateBoxSecret(keys.Private);
		}

		public static byte[] UnboxKey(string boxed, Keys keys)
		{
			var _boxed = Utilities.ToByteArray(boxed);
			return UnboxKey(_boxed, keys);
		}

		public static byte[] UnboxKey(byte[] boxed, Keys keys)
		{
			var sk = SecretKeyToPrivateBoxSecret(keys);
			return Sodium.SecretBox.Open(boxed, null, (Utilities.ToByteArray(keys.Private)));
		}

		public static object UnboxBody(byte[] boxed, Keys key)
		{
			if (key == null) return null;
			//var _boxed = Utilities.ToByteArray(boxed);
			var _key = Utilities.ToByteArray(key.Private);
			var msg = PrivateBox.MultiboxOpenBody(boxed, _key);
			try
			{
				return JsonConvert.DeserializeObject(Encoding.UTF8.GetString(msg));
			}
			catch
			{
				return null;
			}
		}

		public static object Unbox(string boxed, byte[] privateKey)
		{
			if (privateKey == null) return null;
			var _boxed = Utilities.ToByteArray(boxed);

			var sk = Sodium.PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(privateKey);

			try
			{
				var msg = PrivateBox.MultiboxOpen(_boxed, sk);
				return JsonConvert.DeserializeObject(Encoding.UTF8.GetString(msg));
			}
			catch
			{
				return null;
			}
		}

		public static object Unbox(string boxed, string privateKey)
		{
			var _key = Utilities.ToByteArray(privateKey);
			return Unbox(boxed, _key);
		}

		public static object Unbox(string boxed, Keys keys)
		{
			var _key = Utilities.ToByteArray(keys.Private);
			return Unbox(boxed, _key);
		}

		public static byte[] SecretBox(byte[] data, byte[] privateKeys)
		{
			if (data == null || data.Length == 0) return null;

			var ptxt = Utilities.ToByteArray(JsonConvert.SerializeObject(data));

			return Sodium.SecretBox.Create(ptxt, Utilities.SubArray(privateKeys, 0, 24), privateKeys);
		}

		public static byte[] SecretBox(byte[] data, string privateKeys)
		{
			var _private = Utilities.ToByteArray(privateKeys);
			return SecretBox(data, _private);
		}

		public static byte[] SecretBox(string data, string privateKeys)
		{
			var _data = Utilities.ToByteArray(data);
			return SecretBox(_data, privateKeys);
		}

		public static byte[] SecretBox(byte[] data, Keys keys)
		{
			return SecretBox(data, keys.Private);
		}

		public static byte[] SecretBox(string data, Keys keys)
		{
			return SecretBox(data, keys.Private);
		}

		public static object SecretUnBox(byte[] cipherText, byte[] privateKeys)
		{
			if (cipherText == null || cipherText.Length == 0) return null;

			var ptxt = Sodium.SecretBox.Open(cipherText, Utilities.SubArray(privateKeys, 0, 24), privateKeys);
			if (ptxt == null || ptxt.Length == 0) return null;

			return JsonConvert.DeserializeObject(Encoding.UTF8.GetString(ptxt));
		}

		public static object SecretUnBox(byte[] cipherText, string privateKeys)
		{
			var _private = Utilities.ToByteArray(privateKeys);
			return SecretUnBox(cipherText, _private);
		}

		public static object SecretUnBox(string cipherText, string privateKeys)
		{
			var _cipherText = Encoding.UTF8.GetBytes(cipherText);
			return SecretUnBox(_cipherText, privateKeys);
		}

		public static object SecretUnBox(byte[] cipherText, Keys keys)
		{
			return SecretUnBox(cipherText, keys.Private);
		}

		public static object SecretUnBox(string cipherText, Keys keys)
		{
			var _cipherText = Encoding.UTF8.GetBytes(cipherText);
			return SecretUnBox(_cipherText, keys.Private);
		}

		public static string Box(object msg, byte[][] recipientsPublicKey)
		{
			var _msg = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(msg));
			var _box = new List<byte[]>();
			foreach (var recPubKey in recipientsPublicKey)
			{
				_box.Add(Sodium.PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(recPubKey));
			}

			var boxed = PrivateBox.Encrypt(_msg, _box);

			return Convert.ToBase64String(boxed) + ".box";
		}

		public static string Box(object msg, List<byte[]> recipientsPublicKey)
		{
			return Box(msg, recipientsPublicKey.ToArray());
		}

		public static string Box(object msg, Keys[] recipients)
		{
			var pubKeys = recipients.Select(x => Utilities.ToByteArray(x.Public)).ToArray();

			return Box(msg, pubKeys);
		}

		public static string Box(object msg, string[] recipients)
		{
			var pubKeys = recipients.Select(x => Utilities.ToByteArray(x)).ToArray();

			return Box(msg, pubKeys);
		}
	}
}
