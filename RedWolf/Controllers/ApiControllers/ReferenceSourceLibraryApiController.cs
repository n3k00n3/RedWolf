// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using RedWolf.Core;
using RedWolf.Models.Grawls;

namespace RedWolf.Controllers.ApiControllers
{
    [ApiController, Route("api/referencesourcelibraries"), Authorize(Policy = "RequireJwtBearer")]
    public class ReferenceSourceLibraryApiController : Controller
    {
        private readonly IRedWolfService _service;

        public ReferenceSourceLibraryApiController(IRedWolfService service)
        {
            _service = service;
        }

        // GET: api/referencesourcelibraries
        [HttpGet(Name = "GetReferenceSourceLibraries")]
        public async Task<ActionResult<IEnumerable<ReferenceSourceLibrary>>> GetReferenceSourceLibraries()
        {
            return Ok(await _service.GetReferenceSourceLibraries());
        }

        // GET api/referencesourcelibraries/{id}
        [HttpGet("{id}", Name = "GetReferenceSourceLibrary")]
        public async Task<ActionResult<ReferenceSourceLibrary>> GetReferenceSourceLibrary(int id)
        {
            try
            {
                return await _service.GetReferenceSourceLibrary(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // POST api/referencesourcelibraries
        [HttpPost(Name = "CreateReferenceSourceLibrary")]
        public async Task<ActionResult<ReferenceSourceLibrary>> CreateReferenceSourceLibrary([FromBody]ReferenceSourceLibrary library)
        {
            try
            {
                ReferenceSourceLibrary createdLibrary = await _service.CreateReferenceSourceLibrary(library);
                return CreatedAtRoute(nameof(GetReferenceSourceLibrary), new { id = createdLibrary.Id }, createdLibrary);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // PUT api/referencesourcelibraries
        [HttpPut(Name = "EditReferenceSourceLibrary")]
        public async Task<ActionResult<ReferenceSourceLibrary>> EditReferenceSourceLibrary([FromBody]ReferenceSourceLibrary library)
        {
            try
            {
                return await _service.EditReferenceSourceLibrary(library);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // DELETE api/referencesourcelibraries/{id}
        [HttpDelete("{id}", Name = "DeleteReferenceSourceLibrary")]
        public async Task<ActionResult> DeleteReferenceSourceLibrary(int id)
        {
            try
            {
                await _service.DeleteReferenceSourceLibrary(id);
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
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }
    }
}
