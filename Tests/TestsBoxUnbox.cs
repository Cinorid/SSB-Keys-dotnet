using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace SSB.Keys.Tests
{
	public class TestsBoxUnbox
	{
		[SetUp]
		public void Setup()
		{
		}

		[Test]
		public void BoxUnbox()
		{
			var obj = new
			{
				okay = true
			};

			var alice = Keys.Generate();
			var bob = Keys.Generate();
			var pubKeys = new string[] { alice.Public, bob.Public };
			var prvKeys = new string[] { alice.Private, bob.Private };

			var boxed = Keys.Box(obj, new string[] { alice.Public, bob.Public });

			foreach (var key in prvKeys)
			{
				var msg = Keys.Unbox(boxed, key);
				Assert.AreEqual(JObject.DeepEquals(msg, JObject.FromObject(obj)), true);
			}
		}

		[Test]
		public void ReturnNullForInvalidContent()
		{
			var alice = Keys.Generate();

			var msg = Keys.Unbox("this is invalid content", alice.Private);
			Assert.AreEqual(msg, null);
		}
	}
}
