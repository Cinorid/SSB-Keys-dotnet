using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace SSB.Keys.Tests
{
	public class TestsKeys
	{
		Keys keys;
		string path;

		[SetUp]
		public void Setup()
		{
			keys = new Keys
			{
				Curve = "ed25519",
				Public = "1nf1T1tUSa43dWglCHzyKIxV61jG/EeeL1Xq1Nk8I3U=.ed25519",
				Private = "GO0Lv5BvcuuJJdHrokHoo0PmCDC/XjO/SZ6H+ddq4UvWd/VPW1RJrjd1aCUIfPIojFXrWMb8R54vVerU2TwjdQ==.ed25519",
				ID = "@1nf1T1tUSa43dWglCHzyKIxV61jG/EeeL1Xq1Nk8I3U=.ed25519"
			};

			path = "Secret-" + DateTime.Now.Ticks;
		}

		[Test]
		public void TestParseKeyFromString()
		{
			var testKey = Keys.FromString(
										@"{ curve: 'ed25519',
										  public: '1nf1T1tUSa43dWglCHzyKIxV61jG/EeeL1Xq1Nk8I3U=.ed25519',
										  private: 'GO0Lv5BvcuuJJdHrokHoo0PmCDC/XjO/SZ6H+ddq4UvWd/VPW1RJrjd1aCUIfPIojFXrWMb8R54vVerU2TwjdQ==.ed25519',
										  id: '@1nf1T1tUSa43dWglCHzyKIxV61jG/EeeL1Xq1Nk8I3U=.ed25519' }");

			Assert.AreEqual(testKey, keys);
		}

		[Test]
		public void TestCreateAndLoadFile()
		{
			var k1 = Storage.CreateFile(path + "-1.txt");
			var k2 = Storage.LoadFile(path + "-1.txt");

			Assert.AreEqual(k1, k2);
		}

		[Test]
		public async System.Threading.Tasks.Task TestCreateAndLoadFileAsync()
		{
			var k1 = await Storage.CreateFileAsync(path + "-2.txt");
			var k2 = await Storage.LoadFileAsync(path + "-2.txt");

			Assert.AreEqual(k1, k2);
		}

		[Test]
		public void TestSignAndVerifyMessage()
		{
			var str = "secure scuttlebutt";
			var arr = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

			var keys = Keys.Generate();

			{
				var sig = Keys.SignMessage(keys, str);
				var ok = Keys.VerifyMessage(keys, sig, str);
				Assert.AreEqual(ok, true);
			}

			{
				var sig = Keys.SignMessage(keys.Private, str);
				var ok = Keys.VerifyMessage(keys.Public, sig, str);
				Assert.AreEqual(ok, true);
			}

			{
				var sig = Keys.SignMessage(keys, arr);
				var ok = Keys.VerifyMessage(keys, sig, arr);
				Assert.AreEqual(ok, true);
			}

			{
				var sig = Keys.SignMessage(keys.Private, arr);
				var ok = Keys.VerifyMessage(keys.Public, sig, arr);
				Assert.AreEqual(ok, true);
			}
		}

		[Test]
		public void TestSignAndVerifyObject()
		{
			var obj = new
			{
				Filed1 = "12345",
				Field2 = new string[] { "str1", "str2", "str3" },
				Field3 = 123.456,
			};

			var keys = Keys.Generate();

			{
				var sig = Keys.SignObject(keys.Private, obj);
				var ok = Keys.VerifyObject(keys.Public, sig, obj);
				Assert.AreEqual(ok, true);
			}

			{
				var sig = Keys.SignObject(keys, obj);
				var ok = Keys.VerifyObject(keys, sig, obj);
				Assert.AreEqual(ok, true);
			}
		}

		[Test]
		public void TestKeysClone()
		{
			var k1 = keys;
			var k2 = keys.Clone();

			Assert.AreEqual(k1, k2);
		}

		[Test]
		public void TestSeededKeys()
		{
			var k1 = Keys.Generate(PrivateBox.RandomBytes(32));
			var k2 = Keys.Generate(PrivateBox.RandomBytes(32));

			Assert.IsTrue(k1 != k2);
		}

		[Test]
		public void TestKeysID()
		{
			var k = Keys.Generate();

			Assert.AreEqual(k.ID, "@" + k.Public);
		}

		[Test]
		public void TestGetTag()
		{
			var hash = "lFluepOmDxEUcZWlLfz0rHU61xLQYxknAEd6z4un8P8=.sha256";
			var author = "@/02iw6SFEPIHl8nMkYSwcCgRWxiG6VP547Wcp1NW8Bo=.ed25519";
			Assert.AreEqual(Utilities.GetTag(hash), "sha256");
			Assert.AreEqual(Utilities.GetTag(author), "ed25519");
		}
	}
}