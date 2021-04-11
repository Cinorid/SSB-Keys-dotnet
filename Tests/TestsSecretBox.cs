using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace SSB.Keys.Tests
{
	class TestsSecretBox
	{
		[Test]
		public void SecretBox_SecretUnbox()
		{
			var key = Encoding.ASCII.GetBytes("somewhere-over-the-rainbow-way-up-high".Substring(0, 32));
			var obj = new
			{
				okay = true
			};
			var obj2 = JObject.FromObject(obj);

			var boxed = Keys.SecretBox(obj, key);
			System.Diagnostics.Debug.WriteLine("boxed", boxed);
			var msg = Keys.SecretUnBox(boxed, key);
			Assert.AreEqual(JObject.DeepEquals(msg, obj2), true);
		}
	}
}
