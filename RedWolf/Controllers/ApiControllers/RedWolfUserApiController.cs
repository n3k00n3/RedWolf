// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;

using RedWolf.Core;
using RedWolf.Models.RedWolf;

namespace RedWolf.Controllers
{
    [ApiController, Route("api"), Authorize(Policy = "RequireJwtBearer")]
    public class RedWolfUserApiController : Controller
    {
		private readonly IRedWolfService _service;

		public RedWolfUserApiController(IRedWolfService service)
        {
			_service = service;
        }

        // GET: api/users
        // Get a list of Users
        [HttpGet("users", Name = "GetUsers")]
		public async Task<ActionResult<IEnumerable<RedWolfUser>>> GetUsers()
        {
            try
            {
                IEnumerable<RedWolfUser> users = await _service.GetUsers();
                foreach (RedWolfUser user in users)
                {
                    user.PasswordHash = "";
                }
                return Ok(users);
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

		// GET api/users/{id}
        // Get a User by id
        [HttpGet("users/{id}", Name = "GetUser")]
		public async Task<ActionResult<RedWolfUser>> GetUser(string id)
        {
            try
            {
                RedWolfUser user = await _service.GetUser(id);
                user.PasswordHash = "";
                return user;
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

        // GET: api/users/current
        // Get a list of Users
        [HttpGet("users/current", Name = "GetCurrentUser")]
        public async Task<ActionResult<RedWolfUser>> GetCurrentUser()
        {
            try
            {
                RedWolfUser user = await _service.GetCurrentUser(HttpContext.User);
                user.PasswordHash = "";
                return user;
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

        // POST api/users/login
        // Login a User by password
        [AllowAnonymous]
        [HttpPost("users/login", Name = "Login")]
        public async Task<ActionResult<RedWolfUserLoginResult>> Login([FromBody] RedWolfUserLogin login)
        {
            try
            {
                return await _service.Login(login);
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

        // POST api/users
        // Create a User
        [AllowAnonymous]
        [HttpPost("users", Name = "CreateUser")]
		[ProducesResponseType(typeof(RedWolfUser), 201)]
		public async Task<ActionResult<RedWolfUser>> CreateUser([FromBody] RedWolfUserRegister register)
		{
            try
            {
                RedWolfUser user = await _service.CreateUserVerify(HttpContext.User, register);
                return CreatedAtRoute(nameof(GetUser), new { id = user.Id }, user);
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

        // PUT api/users
        // Edit a User's password
        [HttpPut("users/logon", Name = "EditUserPassword")]
		public async Task<ActionResult<RedWolfUser>> EditUserPassword([FromBody] RedWolfUserLogin user)
        {
            try
            {
                RedWolfUser editedUser = await _service.EditUserPassword(await _service.GetCurrentUser(HttpContext.User), user);
                editedUser.PasswordHash = "";
                return editedUser;
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

        // PUT api/users
        // Edit a User
        [HttpPut("users", Name = "EditUser")]
        public async Task<ActionResult<RedWolfUser>> EditUser([FromBody] RedWolfUser user)
        {
            try
            {
                return await _service.EditUser(user);
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

        // DELETE api/users/{id}
        // Delete a User
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpDelete("users/{id}", Name = "DeleteUser")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteUser(string id)
        {
            try
            {
                await _service.DeleteUser(id);
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

		// GET: api/users/roles
        // Get a list of all UserRoles
        [HttpGet("users/roles", Name = "GetUsersRoles")]
		public async Task<ActionResult<IEnumerable<IdentityUserRole<string>>>> GetUserRoles()
        {
            try
            {
                return Ok(await _service.GetUserRoles());
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

        // GET: api/users/{id}/roles
        // Get a list of Roles for a User
        [HttpGet("users/{id}/roles", Name = "GetUserRoles")]
		public async Task<ActionResult<IEnumerable<IdentityUserRole<string>>>> GetUserRoles(string id)
        {
            try
            {
                return Ok(await _service.GetUserRolesForUser(id));
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

		// GET: api/users/{id}/roles/{rid}
        // Get a Role for a User
		[HttpGet("users/{id}/roles/{rid}", Name = "GetUserRole")]
		public async Task<ActionResult<IdentityUserRole<string>>> GetUserRole(string id, string rid)
        {
            try
            {
                return await _service.GetUserRole(id, rid);
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

        // POST: api/users/{id}/roles/{rid}
        // Create a UserRole
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpPost("users/{id}/roles/{rid}", Name = "CreateUserRole")]
		[ProducesResponseType(typeof(IdentityUserRole<string>), 201)]
		public async Task<ActionResult<IdentityUserRole<string>>> CreateUserRole(string id, string rid)
        {
            try
            {
                IdentityUserRole<string> userRole = await _service.CreateUserRole(id, rid);
                return CreatedAtRoute(nameof(GetUserRole), new { id = id, rid = rid }, userRole);
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

        // DELETE api/users/{id}/roles/{rid}
        // Delete a UserRole
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpDelete("users/{id}/roles/{rid}", Name = "DeleteUserRole")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteUserRole(string id, string rid)
        {
            try
            {
                await _service.DeleteUserRole(id, rid);
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

		// GET: api/roles
        // Get a list of all Roles
        [HttpGet("roles", Name = "GetRoles")]
        public async Task<ActionResult<IEnumerable<IdentityRole>>> GetRoles()
        {
            try
            {
                return Ok(await _service.GetRoles());
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

		// GET: api/roles/{rid}
        // Get a list of Roles for a User
		[HttpGet("roles/{rid}", Name = "GetRole")]
		public async Task<ActionResult<IdentityRole>> GetRole(string rid)
        {
            try
            {
                return await _service.GetRole(rid);
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
