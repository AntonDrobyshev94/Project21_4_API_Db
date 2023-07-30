using Microsoft.AspNetCore.Mvc;
using Project21API_Db.AuthContactApp;
using Project21API_Db.Data;
using Project21API_Db.Models;
using Microsoft.AspNetCore.Authorization;
using System.Data;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Azure;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Identity;
using Project21API_Db.ContextFolder;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;

namespace Project21API_Db.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private readonly ContactData repositoryData;
        public IConfiguration Configuration { get; }

        public ValuesController(ContactData repositoryData, 
            IConfiguration configuration)
        {
            this.repositoryData = repositoryData;
            Configuration = configuration;
        }

        // GET api/values
        [HttpGet]
        public IEnumerable<IContact> Get()
        {
            return repositoryData.GetContacts();
        }

        // GET api/values/5
        [HttpGet]
        [Route("Details/{id}")]
        public async Task<Contact> ContactDetails(int id)
        {
            return await repositoryData.Details(id);
        }

        [HttpGet]
        [Authorize]
        [Route("CurrentRoles")]
        public async Task<IActionResult> CurrentRoles()
        {
            if (User.Identity.IsAuthenticated)
            {
                var userName = User.Identity.Name;
                IList<string> collection = await repositoryData.GetCurrentRoles(userName);
                string json = JsonConvert.SerializeObject(collection);
                return Ok(json);
            }
            return null;
        }

        [HttpGet]
        [Authorize]
        [Route("GetUsers")]
        public async Task<IActionResult> GetUsers()
        {
            IList<string> collection = await repositoryData.GetAllUsers();
            string json = JsonConvert.SerializeObject(collection);
            return Ok(json);
        }

        [HttpGet]
        [Route("GetAdmins")]
        public async Task<IActionResult> GetAdmins()
        {
            IList<string> collection = await repositoryData.GetAllAdmins();
            string json = JsonConvert.SerializeObject(collection);
            return Ok(json);
        }

        //[HttpGet]
        //[Authorize]
        //[Route("GetAdmins")]
        //public async Task<IActionResult> CurrentRoles()
        //{
        //    if (User.Identity.IsAuthenticated)
        //    {
        //        var userName = User.Identity.Name;
        //        IList<string> collection = await repositoryData.GetCurrentRoles(userName);
        //        string json = JsonConvert.SerializeObject(collection);
        //        return Ok(json);
        //    }
        //    return null;
        //}

        // POST api/values
        [HttpPost]
        [Authorize]
        public void Post([FromBody] Contact value)
        {
            repositoryData.AddContacts(value);
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        [Authorize(Policy = "AdminOnly")]
        public void Delete(int id)
        {
            repositoryData.DeleteContact(id);
        }

        [HttpPost]
        [Route("ChangeContactById/{id}")]
        [Authorize(Policy = "AdminOnly")]
        public void ChangeContactById(int id, Contact contact)
        {
            repositoryData.ChangeContact(id, contact);
        }

        [HttpPost]
        [Route("RoleCreate")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<string> RoleCreate(RoleModel model)
        {
            return await repositoryData.CreateRole(model);
        }

        [HttpPost]
        [Route("AddRoleToUser")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<string> AddRoleUser(RoleModel model)
        {
            return await repositoryData.AddRoleToUser(model);
        }

        [HttpPost]
        [Route("RemoveUserRole")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<string> RemoveRoleUser(RoleModel model)
        {
            return await repositoryData.RemoveUserRole(model);
        }

        [HttpPost]
        [Route("RemoveUser")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<string> RemoveUser(RoleModel model)
        {
            return await repositoryData.RemoveUser(model);
        }

        [HttpPost]
        [Route("Registration")]
        public async Task<IActionResult> Registration([FromBody] UserRegistration regData)
        {
            TokenResponseModel loginResponse = await repositoryData.Register(regData);
            if (loginResponse == null)
            {
                return Unauthorized();
            }
            return Ok(loginResponse);
        }

        [HttpPost]
        [Route("AdminRegistration")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> AdministrationRegistration([FromBody] UserRegistration regData)
        {
            TokenResponseModel loginResponse = await repositoryData.AdminRegister(regData);
            if (loginResponse == null)
            {
                return Unauthorized();
            }
            return Ok(loginResponse);
        }

        [HttpPost]
        [Route("Authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] UserLoginProp loginData)
        {
            TokenResponseModel loginResponse = await repositoryData.Login(loginData);
            if (loginResponse == null)
            {
                return Unauthorized();
            }
            return Ok(loginResponse);
        }
    }

    public class TokenResponseModel
    {
        public string access_token { get; set; }
        public string username { get; set; }
    }

    public class RoleModel
    {
        public string roleName { get; set; }
        public string userName { get; set; }
    }
}

