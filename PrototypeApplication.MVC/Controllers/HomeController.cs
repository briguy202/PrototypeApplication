using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace PrototypeApplication.MVC.Controllers
{
	public class HomeController : Controller
	{
		public ActionResult Index()
		{
			ViewBag.Title = "Home Page";

			return View();
		}

		[Authorize]
		public ActionResult Identity()
		{
			return View(ClaimsPrincipal.Current);
		}

		public ActionResult CookieCycle()
		{
			Response.SetCookie(new HttpCookie("test", "1"));
			return View("CookieTest");
		}

	}
}
