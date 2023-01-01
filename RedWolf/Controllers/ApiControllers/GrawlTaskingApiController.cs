// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using RedWolf.Core;
using RedWolf.Models.Grawls;

namespace RedWolf.Controllers
{
    [ApiController, Route("api"), Authorize(Policy = "RequireJwtBearer")]
    public class GrawlTaskingApiController : Controller
    {
        private readonly IRedWolfService _service;

        public GrawlTaskingApiController(IRedWolfService service)
        {
            _service = service;
        }

        // GET: api/taskings
        // <summary>
        // Get GrawlTaskings
        // </summary>
        [HttpGet("taskings", Name = "GetAllGrawlTaskings")]
        public async Task<ActionResult<IEnumerable<GrawlTasking>>> GetAllGrawlTaskings()
        {
            return Ok(await _service.GetGrawlTaskings());
        }

        // GET: api/grawls/{id}/taskings
        // <summary>
        // Get GrawlTaskings for Grawl
        // </summary>
        [HttpGet("grawls/{id}/taskings", Name = "GetGrawlTaskings")]
        public async Task<ActionResult<IEnumerable<GrawlTasking>>> GetGrawlTaskings(int id)
        {
            return Ok(await _service.GetGrawlTaskingsForGrawl(id));
        }

        // GET: api/grawls/{id}/taskings/search
        // <summary>
        // Get GrawlTaskings for Grawl or any child Grawl
        // </summary>
        [HttpGet("grawls/{id}/taskings/search", Name = "GetSearchGrawlTaskings")]
        public async Task<ActionResult<IEnumerable<GrawlTasking>>> GetSearchGrawlTaskings(int id)
        {
            return Ok(await _service.GetGrawlTaskingsSearch(id));
        }

        // GET: api/grawls/{id}/taskings/uninitialized
        // <summary>
        // Get uninitialized GrawlTaskings for Grawl
        // </summary>
        [HttpGet("grawls/{id}/taskings/uninitialized", Name = "GetUninitializedGrawlTaskings")]
        public async Task<ActionResult<IEnumerable<GrawlTasking>>> GetUninitializedGrawlTaskings(int id)
        {
            return Ok(await _service.GetUninitializedGrawlTaskingsForGrawl(id));
        }

        // GET: api/grawls/{id}/taskings/search/uninitialized
        // <summary>
        // Get uninitialized GrawlTaskings for Grawl or any child Grawl
        // </summary>
        [HttpGet("grawls/{id}/taskings/search/uninitialized", Name = "GetSearchUninitializedGrawlTaskings")]
        public async Task<ActionResult<IEnumerable<GrawlTasking>>> GetSearchUninitializedGrawlTaskings(int id)
        {
            IEnumerable<GrawlTasking> taskings = await _service.GetGrawlTaskingsSearch(id);
            return Ok(taskings
                .Where(GT => GT.Status == GrawlTaskingStatus.Uninitialized)
                .ToList());
        }

        // GET api/taskings/{tid}
        // <summary>
        // Get a GrawlTasking
        // </summary>
        [HttpGet("taskings/{tid:int}", Name = "GetGrawlTasking")]
        public async Task<ActionResult<GrawlTasking>> GetGrawlTasking(int tid)
        {
            try
            {
                return await _service.GetGrawlTasking(tid);
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

        // GET api/taskings/{taskingname}
        // <summary>
        // Get a GrawlTasking
        // </summary>
        [HttpGet("grawls/taskings/{taskingname}", Name = "GetGrawlTaskingByName")]
        public async Task<ActionResult<GrawlTasking>> GetGrawlTaskingByName(string taskingname)
        {
            try
            {
                return await _service.GetGrawlTaskingByName(taskingname);
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

        // POST api/taskings
        // <summary>
        // Create a GrawlTasking
        // </summary>
        [HttpPost("taskings", Name = "CreateGrawlTasking")]
        [ProducesResponseType(typeof(GrawlTasking), 201)]
        public async Task<ActionResult<GrawlTasking>> CreateGrawlTasking([FromBody] GrawlTasking grawlTasking)
        {
            try
            {
                GrawlTasking tasking = await _service.CreateGrawlTasking(grawlTasking);
                return CreatedAtRoute(nameof(GetGrawlTasking), new { tid = tasking.Id }, tasking);
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

        // PUT api/taskings
        // <summary>
        // Edit a GrawlTasking
        // </summary>
        [HttpPut("taskings", Name = "EditGrawlTasking")]
        public async Task<ActionResult<GrawlTasking>> EditGrawlTasking([FromBody] GrawlTasking grawlTasking)
        {
            try
            {
                return await _service.EditGrawlTasking(grawlTasking);
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

        // DELETE api/taskings/{tid}
        // <summary>
        // Delete a GrawlTasking
        // </summary>
        [HttpDelete("taskings/{tid}", Name = "DeleteGrawlTasking")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteGrawlTasking(int tid)
        {
            try
            {
                await _service.DeleteGrawlTasking(tid);
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
