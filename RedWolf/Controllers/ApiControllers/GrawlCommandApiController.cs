// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using RedWolf.Core;
using RedWolf.Models.Grawls;

namespace RedWolf.Controllers
{
    [ApiController, Route("api/commands"), Authorize(Policy = "RequireJwtBearer")]
    public class GrawlCommandApiController : Controller
    {
        private readonly IRedWolfService _service;

        public GrawlCommandApiController(IRedWolfService service)
        {
            _service = service;
        }

        // GET: api/commands
        // <summary>
        // Get GrawlCommands
        // </summary>
        [HttpGet(Name = "GetGrawlCommands")]
        public async Task<ActionResult<IEnumerable<GrawlCommand>>> GetGrawlCommands()
        {
            return Ok(await _service.GetGrawlCommands());
        }

        // GET: api/commands/{id}
        // <summary>
        // Get a GrawlCommand
        // </summary>
        [HttpGet("{id}", Name = "GetGrawlCommand")]
        public async Task<ActionResult<GrawlCommand>> GetGrawlCommand(int id)
        {
            try
            {
                return await _service.GetGrawlCommand(id);
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

        // POST api/commands
        // <summary>
        // Create a GrawlCommand
        // </summary>
        [HttpPost(Name = "CreateGrawlCommand"), ProducesResponseType(typeof(GrawlCommand), 201)]
        public async Task<ActionResult<GrawlCommand>> CreateGrawlCommand([FromBody] GrawlCommand grawlCommand)
        {
            try
            {
                grawlCommand.Grawl = await _service.GetGrawl(grawlCommand.GrawlId);
                GrawlCommand createdCommand = await _service.CreateGrawlCommand(grawlCommand);
                return CreatedAtRoute(nameof(GetGrawlCommand), new { id = createdCommand.Id }, createdCommand);
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

        // PUT api/commands
        // <summary>
        // Edit a GrawlCommand
        // </summary>
        [HttpPut(Name = "EditGrawlCommand")]
        public async Task<ActionResult<GrawlCommand>> EditGrawlCommand([FromBody] GrawlCommand grawlCommand)
        {
            try
            {
                return await _service.EditGrawlCommand(grawlCommand);
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

        // DELETE api/commands/{id}
        // <summary>
        // Delete a GrawlTasking
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGrawlCommand")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteGrawlCommand(int id)
        {
            try
            {
                await _service.DeleteGrawlCommand(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            return new NoContentResult();
        }
    }
}
