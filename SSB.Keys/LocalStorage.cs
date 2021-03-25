using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace SSB.Keys
{
	public class LocalStorage
	{
		Hanssens.Net.LocalStorage localStorage = new Hanssens.Net.LocalStorage();

		public LocalStorage()
		{
			localStorage.Load();
		}

		~LocalStorage()
		{
			localStorage.Persist();
		}

		public Keys Create(string fileName, string curve, string legacy)
		{
			var keys = Generate(curve, legacy);
			localStorage.Store(fileName, Keys.ToString(keys));
			return keys;
		}

		public Keys Load(string fileName)
		{
			return Keys.FromString(localStorage.Get<string>(fileName));
		}

		public Keys Generate(string curve, string legacy)
		{
			return new Keys();
		}
	}
}
