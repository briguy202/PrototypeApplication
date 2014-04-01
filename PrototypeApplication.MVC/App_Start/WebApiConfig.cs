using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;

namespace PrototypeApplication.MVC
{
	public static class WebApiConfig
	{
		public static void Register(HttpConfiguration config)
		{
			//// Web API configuration and services
			//config.Routes.MapHttpRoute(
			//	name: "DefaultApi2",
			//	routeTemplate: "api/{controller}/{action}",
			//	defaults: new { action = "get", id = RouteParameter.Optional }
			//);

			// Web API routes
			config.MapHttpAttributeRoutes();

			config.Routes.MapHttpRoute(
				name: "DefaultApi",
				routeTemplate: "api/{controller}/{id}",
				defaults: new { id = RouteParameter.Optional }
			);
		}
	}
}
