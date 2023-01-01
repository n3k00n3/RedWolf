// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using RedWolf.Core;
using RedWolf.Models.Grawls;

namespace RedWolf.Controllers
{
    [ApiController, Route("api/grawltasks"), Authorize(Policy = "RequireJwtBearer")]
    public class GrawlTaskApiController : Controller
    {
        private readonly IRedWolfService _service;

        public GrawlTaskApiController(IRedWolfService service)
        {
            _service = service;
        }

        // GET: api/grawltasks
        // <summary>
        // Get Tasks
        // </summary>
        [HttpGet(Name = "GetGrawlTasks")]
        public async Task<ActionResult<IEnumerable<GrawlTask>>> GetGrawlTasks()
        {
            return Ok(await _service.GetGrawlTasks());
        }

        // GET: api/grawltasks/{id}
        // <summary>
        // Get a Task by Id
        // </summary>
        [HttpGet("{id:int}", Name = "GetGrawlTask")]
        public async Task<ActionResult<GrawlTask>> GetGrawlTask(int id)
        {
            try
            {
                return await _service.GetGrawlTask(id);
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

        // POST api/grawltasks
        // <summary>
        // Create a Task
        // </summary>
        [HttpPost(Name = "CreateGrawlTask")]
        [ProducesResponseType(typeof(GrawlTask), 201)]
        public async Task<ActionResult<GrawlTask>> CreateGrawlTask([FromBody] GrawlTask task)
        {
            GrawlTask savedTask = await _service.CreateGrawlTask(task);
            return CreatedAtRoute(nameof(GetGrawlTask), new { id = savedTask.Id }, savedTask);
        }

        // PUT api/grawltasks
        // <summary>
        // Edit a Task
        // </summary>
        [HttpPut(Name = "EditGrawlTask")]
        public async Task<ActionResult<GrawlTask>> EditGrawlTask([FromBody] GrawlTask task)
        {
            try
            {
                return await _service.EditGrawlTask(task);
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

        // DELETE api/grawltasks/{id}
        // <summary>
        // Delete a Task
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGrawlTask")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteGrawlTask(int id)
        {
            try
            {
                await _service.DeleteGrawlTask(id);
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
