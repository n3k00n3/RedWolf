// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using RedWolf.Core;
using RedWolf.Models.Grawls;
using RedWolf.Models.RedWolf;

namespace RedWolf.Controllers
{
    [ApiController, Route("api/grawls"), Authorize(Policy = "RequireJwtBearer")]
    public class GrawlApiController : Controller
    {
        private readonly IRedWolfService _service;

        public GrawlApiController(IRedWolfService service)
        {
            _service = service;
        }

        // GET: api/grawls
        // <summary>
        // Get a list of Grawls
        // </summary>
        [HttpGet(Name = "GetGrawls")]
        public async Task<ActionResult<IEnumerable<Grawl>>> GetGrawls()
        {
            return Ok(await _service.GetGrawls());
        }

        // GET api/grawls/{id}
        // <summary>
        // Get a Grawl by id
        // </summary>
        [HttpGet("{id:int}", Name = "GetGrawl")]
        public async Task<ActionResult<Grawl>> GetGrawl(int id)
        {
            try
            {
                return await _service.GetGrawl(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET: api/grawls/{name}
        // <summary>
        // Get a Grawl by name
        // </summary>
        [HttpGet("{name}", Name = "GetGrawlByName")]
        public async Task<ActionResult<Grawl>> GetGrawlByName(string name)
        {
            try
            {
                return await _service.GetGrawlByName(name);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grawls/anotherid/{anotherid}
        // <summary>
        // Get a Grawl by ANOTHERID
        // </summary>
        [HttpGet("anotherid/{anotherid}", Name = "GetGrawlByANOTHERID")]
        public async Task<ActionResult<Grawl>> GetGrawlByANOTHERID(string anotherid)
        {
            try
            {
                return await _service.GetGrawlByANOTHERID(anotherid);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grawls/originalanotherid/{serveranotherid}
        // <summary>
        // Get a Grawl by OriginalServerANOTHERID
        // </summary>
        [HttpGet("originalanotherid/{serveranotherid}", Name = "GetGrawlByOriginalServerANOTHERID")]
        public async Task<ActionResult<Grawl>> GetGrawlByOriginalServerANOTHERID(string serveranotherid)
        {
            try
            {
                return await _service.GetGrawlByOriginalServerANOTHERID(serveranotherid);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grawls/{id}/path/{cid}
        // <summary>
        // Get a path to a child Grawl by id
        // </summary>
        [HttpGet("{id}/path/{cid}", Name = "GetPathToChildGrawl")]
        public async Task<ActionResult<List<string>>> GetPathToChildGrawl(int id, int cid)
        {
            try
            {
                return await _service.GetPathToChildGrawl(id, cid);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grawls/{id}/outbound
        // <summary>
        // Get the outbound Grawl for a Grawl in the graph
        // </summary>
        [HttpGet("{id}/outbound", Name = "GetOutboundGrawl")]
        public async Task<ActionResult<Grawl>> GetOutboundGrawl(int id)
		{
			try
			{
				return await _service.GetOutboundGrawl(id);
			}
			catch (ControllerNotFoundException e)
			{
				return NotFound(e.Message);
			}
			catch (ControllerBadRequestException e)
			{
				return BadRequest(e.Message);
			}
		}


        // POST api/grawls
        // <summary>
        // Create a Grawl
        // </summary>
        [HttpPost(Name = "CreateGrawl")]
        [ProducesResponseType(typeof(Grawl), 201)]
        public async Task<ActionResult<Grawl>> CreateGrawl([FromBody]Grawl grawl)
        {
            try
            {
                Grawl createdGrawl = await _service.CreateGrawl(grawl);
                return CreatedAtRoute(nameof(GetGrawl), new { id = createdGrawl.Id }, createdGrawl);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // PUT api/grawls
        // <summary>
        // Edit a Grawl
        // </summary>
        [HttpPut(Name = "EditGrawl")]
        public async Task<ActionResult<Grawl>> EditGrawl([FromBody] Grawl grawl)
        {
            try
            {
                return await _service.EditGrawl(grawl, await _service.GetCurrentUser(HttpContext.User));
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // DELETE api/grawls/{id}
        // <summary>
        // Delete a Grawl
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGrawl")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteGrawl(int id)
        {
            try
            {
                await _service.DeleteGrawl(id);
                return new NoContentResult();
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // POST api/grawls/{id}/interact
        // <summary>
        // Interact with a Grawl
        // </summary>
        [HttpPost("{id}/interact", Name = "InteractGrawl")]
        [ProducesResponseType(typeof(GrawlCommand), 201)]
        public async Task<ActionResult<GrawlCommand>> InteractGrawl(int id, [FromBody] string command)
        {
            try
            {
                RedWolfUser user = await _service.GetCurrentUser(this.HttpContext.User);
                GrawlCommand grawlCommand = await _service.InteractGrawl(id, user.Id, command);
                return CreatedAtRoute("GetGrawlCommand", new { id = grawlCommand.Id }, grawlCommand);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grawls/{id}/compileexecutor
        // <summary>
        // Compile an ImplantTemplate for a given Grawl
        // </summary>
        [HttpGet("{id}/compileexecutor", Name = "CompileGrawlExecutor")]
        public async Task<ActionResult<byte[]>> CompileGrawlExecutor(int id)
        {
            try
            {
                return await _service.CompileGrawlExecutorCode(id, Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary, false);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }
    }
}
