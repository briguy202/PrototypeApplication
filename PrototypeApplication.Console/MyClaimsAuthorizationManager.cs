using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace PrototypeApplication.Console
{
	class MyClaimsAuthorizationManager : ClaimsAuthorizationManager
	{
		public override bool CheckAccess(AuthorizationContext context)
		{
			var resource = context.Resource.First().Value;
			var action = context.Action.First().Value;

			if (context.Principal.HasClaim("http://myclaims/usertype", "PowerUser"))
				return true;

			return false;
		}
	}
}
