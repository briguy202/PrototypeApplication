using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Web;
using System.Web.Http;

namespace PrototypeApplication.MVC.Controllers
{
	public class ValuesController : ApiController
	{
		static int _cookieValue = 0;
		static Random _random = new Random();

		public string GetNewCookie()
		{
			//try
			//{
				var cookieValue = HttpContext.Current.Request.Cookies["test"].Value;
				var headerValue = HttpContext.Current.Request.Headers["X-Custom-Header"];

				if (cookieValue != headerValue)
					throw new ApplicationException("Cookie values don't match! - Cookie: " + cookieValue + ", Header: " + headerValue);

				var newValue = _cookieValue++.ToString();

				HttpContext.Current.Response.SetCookie(new HttpCookie("test", newValue));

				Thread.Sleep(_random.Next(200, 400));

				return newValue;
			//}
			//catch (Exception ex)
			//{
			//	HttpContext.Current.Response.StatusCode = 500;
			//	HttpContext.Current.Response.Status = ex.Message;
			//	return null;
			//}
		}


		// GET api/values
		public IEnumerable<string> Get()
		{
			return new string[] { "value1", "value2" };
		}

		// GET api/values/5
		public string Get(int id)
		{
			return "value";
		}

		// POST api/values
		public void Post([FromBody]string value)
		{
		}

		// PUT api/values/5
		public void Put(int id, [FromBody]string value)
		{
		}

		// DELETE api/values/5
		public void Delete(int id)
		{
		}
	}
}
