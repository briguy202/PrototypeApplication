using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace PrototypeApplication.Console
{
	class Program
	{
		private static RNGCryptoServiceProvider _random;
		private static WindowsPrincipal _windowsPrincipal;

		static void Main(string[] args)
		{
			_random = new RNGCryptoServiceProvider();
			_windowsPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());

			//Program.IdentityDemo();
			//Program.ClaimsDemo();
			//Program.ClaimsAuthenticationDemo();
			//Program.ClaimsAuthorizationDemo();
			//Program.SessionTokenDemo();
			//Program.TokenDemo();
			Program.HMACEncryption();

			System.Console.WriteLine();
			System.Console.WriteLine("Press any key to continue ...");
			System.Console.ReadKey();
		}

		#region Encryption Demo
		private static readonly string secretKey = "2ijds@#$erkjer33$rkr";

		private static void HMACEncryption()
		{
			var apiKey = "ThisIsMyApplicationKey";
			var now = DateTime.UtcNow;
			
			var secondsSinceEpoch = (int)Program.ConvertToEpochTime(now).TotalSeconds;
			var expiresEpoch = (int)Program.ConvertToEpochTime(now.AddHours(1)).TotalSeconds;

			var future = now.AddSeconds(5);
			var futureSinceEpoch = (int)Program.ConvertToEpochTime(future).TotalSeconds;

			System.Console.WriteLine("HMAC ...");
			System.Console.WriteLine("UTC now: " + now);
			System.Console.WriteLine("Seconds since unix epoch: " + secondsSinceEpoch);
			System.Console.WriteLine("Expires unix epoch: " + expiresEpoch);
			System.Console.WriteLine();
			System.Console.WriteLine(Program.HMACEncrypt(apiKey, secretKey, now));
			System.Console.WriteLine(Program.HMACEncrypt(apiKey, secretKey, now));
			System.Console.WriteLine(Program.HMACEncrypt(apiKey, secretKey, future));
			
			System.Console.WriteLine();
			System.Console.WriteLine("TripleDES ...");
			var nowEncrypt = Program.TripleDESEncrypt(apiKey + "-" + secondsSinceEpoch);
			var futureEncrypt = Program.TripleDESEncrypt(apiKey + "-" + futureSinceEpoch);
			System.Console.WriteLine(nowEncrypt);
			System.Console.WriteLine(futureEncrypt);
			System.Console.WriteLine(Program.TripleDESDecrypt(nowEncrypt));
			System.Console.WriteLine(Program.TripleDESDecrypt(futureEncrypt));
		}

		private static string TripleDESEncrypt(string value)
		{
			byte[] keyArray;
			byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(value);

			var md5 = new MD5CryptoServiceProvider();
			keyArray = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(secretKey));
			md5.Clear();

			// Set the secret key for the tripleDES algorithm
			var tripleDes = new TripleDESCryptoServiceProvider();
			tripleDes.Key = keyArray;
			tripleDes.Mode = CipherMode.ECB;
			tripleDes.Padding = PaddingMode.PKCS7;

			// Transform the specified region of bytes array to resultArray
			var encryptor = tripleDes.CreateEncryptor();
			byte[] resultArray = encryptor.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
			tripleDes.Clear();

			return Convert.ToBase64String(resultArray);
		}

		private static string TripleDESDecrypt(string value)
		{
			//value = value.Replace(' ', '+');
			byte[] keyArray;
			byte[] toEncryptArray = Convert.FromBase64String(value);

			MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
			keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(secretKey));
			hashmd5.Clear();

			// Set the secret key for the tripleDES algorithm
			var tdes = new TripleDESCryptoServiceProvider();
			tdes.Key = keyArray;
			tdes.Mode = CipherMode.ECB;
			tdes.Padding = PaddingMode.PKCS7;

			ICryptoTransform cTransform = tdes.CreateDecryptor();
			byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
			tdes.Clear();

			return UTF8Encoding.UTF8.GetString(resultArray);
		}

		private static string HMACEncrypt(string value, string secret, DateTime date)
		{
			var secretBytes = Encoding.UTF8.GetBytes(secret);
			var valueBytes = Encoding.UTF8.GetBytes(value);
			string signature;
			byte[] bytes = new byte[15];
			_random.GetBytes(bytes);

			using (var hmac = new HMACSHA256(secretBytes))
			{
				value = value + "-" + date.ToString();
				var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(value));
				signature = Convert.ToBase64String(hash);
			}
			return signature;
		}

		private static TimeSpan ConvertToEpochTime(DateTime utcTime)
		{
			return utcTime - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
		}
		#endregion

		#region Identity Demo
		/// <summary>
		/// This is a demo of the older (circa 2002) approach to doing Identity and Principal authentication/authorization.  It demonstrates
		/// the IPrincipal and IIdentity approaches by creating a WindowsIdentity which implements the IIdentity interface.
		/// </summary>
		static void IdentityDemo()
		{
			WindowsIdentity id = WindowsIdentity.GetCurrent();
			System.Console.WriteLine("Windows Account Name: " + id.Name);

			var account = new NTAccount(id.Name);
			System.Console.WriteLine("Windows Account SID: " + account.Translate(typeof(SecurityIdentifier)));

			System.Console.WriteLine();
			System.Console.WriteLine("Groups ...");
			foreach (var group in id.Groups.Translate(typeof(NTAccount)))
			{
				System.Console.WriteLine("  " + group);
			}

			WindowsPrincipal principal = new WindowsPrincipal(id);

			var domainGroup = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, id.User.AccountDomainSid);
			System.Console.WriteLine("Domain Group ...");
			System.Console.WriteLine("SID: " + domainGroup.AccountDomainSid);
			System.Console.WriteLine("Name: " + domainGroup.Translate(typeof(NTAccount)));
			System.Console.WriteLine("Is in Role: " + principal.IsInRole(domainGroup));

			// Note that the windows principal is not set as the current thread principal.
			System.Console.WriteLine("Current Identity Name: " + ClaimsPrincipal.Current.Identity.Name);

			Thread.CurrentPrincipal = principal;
			System.Console.WriteLine("Current Identity Name: " + ClaimsPrincipal.Current.Identity.Name);
		}
		#endregion

		#region Claims Demo
		static void ClaimsDemo()
		{
			SetupClaimsPrincipal();
			//CustomIdentityTest();

			LegacyApproach();
			NewApproach();
			//WindowsIdentityTest();
		}

		private static void CustomIdentityTest()
		{
			var id = new MyIdentity("Phil Guy", "Upline Guy", "IT Department");
			var cp = new ClaimsPrincipal(id);
			Thread.CurrentPrincipal = cp;
		}

		private static void WindowsIdentityTest()
		{
			System.Console.WriteLine("*** WINDOWS IDENTITY TEST ***");
			var windows = WindowsIdentity.GetCurrent();
			System.Console.WriteLine("Claims ...");
			foreach (var claim in windows.Claims)
			{
				System.Console.WriteLine("  " + claim);
			}

			System.Console.WriteLine();
		}

		/// <summary>
		/// The new approach to identity management is to do claims-based identity.  
		/// </summary>
		private static void NewApproach()
		{
			System.Console.WriteLine("*** NEW APPROACH ***");

			// No need to do the casting below ... the new ClaimsPrincipal.Current does this for you (throws exception if it's older, non-claims-based code).
			//var claimsPrincipal = principal as ClaimsPrincipal;
			var claimsPrincipal = ClaimsPrincipal.Current;

			System.Console.WriteLine("Claims ...");
			foreach (var claim in claimsPrincipal.Claims)
			{
				System.Console.WriteLine("  " + claim);
			}

			System.Console.WriteLine("Roles ...");
			foreach (var role in claimsPrincipal.FindAll(ClaimTypes.Role))
			{
				System.Console.WriteLine("  " + role);
			}

			System.Console.WriteLine();
		}

		private static void LegacyApproach()
		{
			System.Console.WriteLine("*** LEGACY APPROACH ***");
			// Demonstrates code using the older IPrincipal logic which still works now after .NET 4.5's new Claims-based classes were introduced since they
			// all still inherit from IIdentity and IPrincipal.
			var principal = Thread.CurrentPrincipal;
			// Identity.Name looks through the claims collection for the ClaimTypes.Name value.
			System.Console.WriteLine("Principal Identity Name: " + principal.Identity.Name);
			System.Console.WriteLine("Is a developer: " + principal.IsInRole("Developer"));

			System.Console.WriteLine();
		}

		private static void SetupClaimsPrincipal()
		{
			System.Console.WriteLine("*** SETUP CLAIMS PRINCIPAL ***");
			var claims = new List<Claim> {
				new Claim(ClaimTypes.Name, "Bubba"),
				new Claim("http://myclaims/mycustomnametype", "BubbaCustom"),
				new Claim(ClaimTypes.Email, "bhibma@gmail.com"),
				new Claim(ClaimTypes.Role, "Developer"),
				new Claim(ClaimTypes.Role, "Administrator"),
				new Claim("http://myclaims/location", "Grand Rapids")
			};

			// Authentication occurs when the user has an authentication type ... 
			var anonID = new ClaimsIdentity(claims);
			System.Console.WriteLine("IsAuthenticated (anonID): " + anonID.IsAuthenticated); // Is "false"

			var authedID = new ClaimsIdentity(claims, "My Authn");

			// Uncomment the following line to see how to re-map what is used for the "Name" claim which gets mapped to the principal's identity's "Name" property.
			//var authedID = new ClaimsIdentity(claims, "My Authn", "http://myclaims/mycustomnametype", ClaimTypes.Role);
			// Uncomment the following line to see how to re-map what is used for the "Name" claim which to the email address using the predefined ClaimTypes value.
			//var authedID = new ClaimsIdentity(claims, "My Authn", ClaimTypes.Email, ClaimTypes.Role);

			System.Console.WriteLine("IsAuthenticated (authedID): " + authedID.IsAuthenticated); // Is "true"

			var principal = new ClaimsPrincipal(authedID);

			// Assign the principal to the Thread.
			Thread.CurrentPrincipal = principal;

			System.Console.WriteLine();
		}

		class MyIdentity : ClaimsIdentity
		{
			public MyIdentity(string name, string upline, string department)
			{
				this.AddClaims(new[] {
					new Claim(ClaimTypes.Name, name),
					new Claim("http://myclaims/upline", upline),
					new Claim("http://myclaims/department", department)
				});
			}

			public string Upline { get; set; }
			public string Department { get; set; }
		}
		#endregion

		#region Claims Authentication Demo
		static void ClaimsAuthenticationDemo()
		{
			// This line triggers the transformation to occur.  The transformer is specified in the configuration (app.config).
			Thread.CurrentPrincipal = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthenticationManager.Authenticate("nothing", _windowsPrincipal);
			
			System.Console.WriteLine("Current Identity Name: " + ClaimsPrincipal.Current.Identity.Name);
			System.Console.WriteLine("Claims ...");
			foreach (var claim in ClaimsPrincipal.Current.Claims)
				System.Console.WriteLine("  " + claim);
		}
		#endregion

		#region Claims Authorization Demo
		private static void ClaimsAuthorizationDemo()
		{
			Thread.CurrentPrincipal = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthenticationManager.Authenticate("nothing", _windowsPrincipal);

			Program.ProtectedOperation();
		}

		// Using a claims principal permission object like this makes it such that we're not specifying exactly who is allowed to call this method, instead
		// we are specifying what attributes that user must have to call the method.
		[ClaimsPrincipalPermission(SecurityAction.Demand, Operation = "Invoke", Resource = "Protected")]
		private static void ProtectedOperation()
		{
			System.Console.WriteLine("Accessed protected operation.");
		}
		#endregion

		#region Session Token Demo
		private static void SessionTokenDemo()
		{
			var sessionToken = new SessionSecurityToken(_windowsPrincipal, TimeSpan.FromHours(8));

			// This would occur in ASP.NET ...
			//FederatedAuthentication.SessionAuthenticationModule.WriteSessionTokenToCookie(sessionToken);

			System.Console.WriteLine("Session Token ID: " + sessionToken.Id);
		}
		#endregion

		#region Token Demo
		static void TokenDemo()
		{
			Saml2SecurityTokenHandler h = new Saml2SecurityTokenHandler();
			var token = h.CreateToken(new SecurityTokenDescriptor());
			System.Console.WriteLine(token);
		}
		#endregion

	}
}
