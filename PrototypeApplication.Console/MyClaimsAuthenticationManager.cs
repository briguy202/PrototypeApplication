using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace PrototypeApplication.Console
{
	class MyClaimsAuthenticationManager : ClaimsAuthenticationManager
	{
		public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
		{
			// The incoming principal is the one that the token handler produced, and here we can translate that into claims
			// that our application understands.
			var name = incomingPrincipal.Identity.Name;
			if (string.IsNullOrWhiteSpace(name))
			{
				throw new SecurityException("name claim is missing.");
			}

			var claims = new List<Claim>
				{
					new Claim(ClaimTypes.Name, name),
					new Claim("http://myclaims/location", "Transformed to Grand Rapids"),
					new Claim("http://myclaims/usertype", "PowerUser")
				};
			var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Custom"));
			return principal;
		}
	}
}
