// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using RedWolf.Core;
using RedWolf.API.Models;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;

namespace RedWolf.Controllers
{
    [AllowAnonymous]
    public class HttpListenerController : Controller
    {
        private readonly RedWolf.Models.Listeners.HttpListenerContext _context;
        private readonly RedWolf.Models.Listeners.InternalListener _internalListener;

		public HttpListenerController(RedWolf.Models.Listeners.HttpListenerContext context, RedWolf.Models.Listeners.InternalListener internalListener)
        {
            _context = context;
            _internalListener = internalListener;
        }

        private void SetHeaders()
        {
            foreach (HttpProfileHeader header in _context.HttpProfiles.First().HttpResponseHeaders)
            {
                HttpContext.Response.Headers[header.Name] = header.Value;
            }
        }

        [AllowAnonymous]
        public async Task<ActionResult<string>> Route()
        {
            string anotherid = "";
            try
            {
                this.SetHeaders();
                anotherid = GetGuid(HttpContext);
                if (HttpContext.Request.Method == "GET")
                {
                    string response = String.Format(_context.HttpProfiles.First().HttpGetResponse.Replace("{", "{{").Replace("}", "}}").Replace("{{DATA}}", "{0}").Replace("{{ANOTHERID}}", "{1}"), await _internalListener.Read(anotherid), anotherid);
                    return Ok(response);
		        }
		        else if (HttpContext.Request.Method == "POST")
                {
                    using StreamReader reader = new StreamReader(Request.Body, System.Text.Encoding.UTF8);
                    string body = await reader.ReadToEndAsync();
                    string ExtractedMessage = body.ParseExact(_context.HttpProfiles.First().HttpPostRequest.Replace("{", "{{").Replace("}", "}}").Replace("{{DATA}}", "{0}").Replace("{{ANOTHERID}}", "{1}")).FirstOrDefault();
                    string anotheridToRead = await _internalListener.Write(anotherid, ExtractedMessage);
                    string postRead = await _internalListener.Read(anotheridToRead);
                    string response = String.Format(_context.HttpProfiles.First().HttpPostResponse.Replace("{", "{{").Replace("}", "}}").Replace("{{DATA}}", "{0}").Replace("{{ANOTHERID}}", "{1}"), postRead, anotherid);
                    return Ok(response);
                }
		        else
		        {
                    return NotFound();
                }
            }
            catch (ControllerNotFoundException e)
            {
                string response = String.Format(_context.HttpProfiles.First().HttpGetResponse.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}"), e.Message, anotherid);
                return NotFound(response);
            }
            catch (Exception e)
            {
                string response = String.Format(_context.HttpProfiles.First().HttpGetResponse.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}"), e.Message, anotherid);
                return NotFound(response);
            }
        }

        private string GetGuid(HttpContext httpContext)
        {
            foreach (HttpProfileHeader header in _context.HttpProfiles.First().HttpRequestHeaders)
            {
                if (header.Name.Contains("{ANOTHERID}"))
                {
                    return Parse(httpContext.Request.Headers.First(H => H.Value == header.Value).Key, header.Name.Replace("{ANOTHERID}", "{0}"))[0];
                }
                if (header.Value.Contains("{ANOTHERID}"))
                {
                    return Parse(httpContext.Request.Headers[header.Name].First(), header.Value.Replace("{ANOTHERID}", "{0}"))[0];
                }
            }
            string url = _context.HttpProfiles.First().HttpUrls.FirstOrDefault(U => U.StartsWith(httpContext.Request.Path, StringComparison.CurrentCultureIgnoreCase));
            if (url != null && url.Contains("{ANOTHERID}"))
            {
                return Parse((httpContext.Request.Path + httpContext.Request.QueryString), url.Replace("{ANOTHERID}", "{0}"))[0];
            }
            return null;
        }

        private static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{");
            if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'grp0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'grp1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'grp2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'grp3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'grp4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'grp5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
            if (match.Groups["grp0"] != null) { matches.Add(match.Groups["grp0"].Value); }
            if (match.Groups["grp1"] != null) { matches.Add(match.Groups["grp1"].Value); }
            if (match.Groups["grp2"] != null) { matches.Add(match.Groups["grp2"].Value); }
            if (match.Groups["grp3"] != null) { matches.Add(match.Groups["grp3"].Value); }
            if (match.Groups["grp4"] != null) { matches.Add(match.Groups["grp4"].Value); }
            if (match.Groups["grp5"] != null) { matches.Add(match.Groups["grp5"].Value); }
            return matches;
        }
    }
}
