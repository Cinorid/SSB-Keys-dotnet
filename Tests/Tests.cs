using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace SSB.Keys.Tests
{
	public class Tests
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
		public void TestSignAndVerifyString1()
		{
			var str = "secure scuttlebutt";

			var keys = Keys.Generate();
			var sig = Keys.SignMessage(keys.Private, str);
			var ok = Keys.VerifyMessage(keys.Public, sig, str);
			Assert.AreEqual(ok, true);
		}

		[Test]
		public void TestSignAndVerifyString2()
		{
			var str = "secure scuttlebutt";

			var keys = Keys.Generate();
			var sig = Keys.SignMessage(keys.Private, str);
			var ok = Keys.VerifyMessage(keys, sig, str);
			Assert.AreEqual(ok, true);
		}

		[Test]
		public void TestSignAndVerifyString3()
		{
			var str = "secure scuttlebutt";

			var keys = Keys.Generate();
			var sig = keys.SignMessage(str);
			var ok = keys.VerifyMessage(sig, str);
			Assert.AreEqual(ok, true);
		}

		[Test]
		public void TestSignAndVerifyArray()
		{
			var arr = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

			var keys = Keys.Generate();
			var sig = keys.SignMessage(arr);
			var ok = keys.VerifyMessage(sig, arr);
			Assert.AreEqual(ok, true);
		}

		[Test]
		public void TestSignAndVerifyObject()
		{
			var arr = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

			var keys = Keys.Generate();
			var sig = keys.SignObject(arr);
			var ok = keys.VerifyObject(sig, arr);
			Assert.AreEqual(ok, true);
		}
	}
}