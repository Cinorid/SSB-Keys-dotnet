using Newtonsoft.Json;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace SSB.Keys.Tests
{
	class TestsWeird
	{
		string expected;
		object msg;

		[SetUp]
		public void Setup()
		{
			expected = "lFluepOmDxEUcZWlLfz0rHU61xLQYxknAEd6z4un8P8=.sha256";
			msg = new
			{
				previous = "%VBfEJjeNUlxLuK0eyRzVha3TLu5PPWLwsvGgnmAdPas=.sha256",
				author = "@/02iw6SFEPIHl8nMkYSwcCgRWxiG6VP547Wcp1NW8Bo=.ed25519",
				sequence = 2888,
				timestamp = 1457679971682,
				hash = "sha256",
				content = new
				{
					type = "post",
					text = "oh no\n\nhttps://medium.com/making-instapaper/bookmarklets-are-dead-d470d4bbb626\n\n> The ultimate catch-22 of the new Content Security Policy wording is that it’s intended to benefit the users, by providing additional security from hypothetical malicious add-ons on websites that enforce a Content Security Policy. In the end the bookmarklet has been relegated obsolete by the change, a casualty of one clause in one section of one web specification, and end-users and developers are the ones who will mourn its demise. The path to hell is paved with good intentions.\n\n> I’d probably try to do more about it, but I’m too busy rewriting Instapaper’s bookmarklet into extensions for every major browser.\n\nhttps://www.youtube.com/watch?v=n5diMImYIIA",
					root = "%VBfEJjeNUlxLuK0eyRzVha3TLu5PPWLwsvGgnmAdPas=.sha256",
					branch = "%VBfEJjeNUlxLuK0eyRzVha3TLu5PPWLwsvGgnmAdPas=.sha256",
					channel = "javascript",
				},
				signature = "Pv+LWJumKE8nIOfsZxgMcg/EcR/tZeJShmiVIGizERuiAMzwzTTjg78r+InmJopJwMogEG7/W3FLTnH/EOzLCg==.sig.ed25519",
			};
		}

		[Test]
		public void TestThatTheLegacyCodeIsAsExpected()
		{
			string str = JsonConvert.SerializeObject(msg, new JsonSerializerSettings { Formatting = Formatting.Indented,  }).Replace("\r\n", "\n");
			var actual = Utilities.Hash(Encoding.ASCII.GetBytes(str));
			Assert.AreEqual(expected, actual);
		}
	}
}
