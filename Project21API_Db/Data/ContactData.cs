using Project21API_Db.ContextFolder;
using Project21API_Db.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Project21API_Db.AuthContactApp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Project21API_Db.Controllers;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Project21API_Db.Data
{
    public class ContactData
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly DataContext context;
        public IConfiguration Configuration { get; }

        public ContactData(DataContext context, UserManager<User> userManager,
                                SignInManager<User> signInManager,
                                RoleManager<IdentityRole> roleManager,
                                IConfiguration configuration)
        {
            this.context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            Configuration = configuration;
        }

        public void AddContacts(Contact contact)
        {
            using (var context = new DataContext())
            {
                context.Contacts.Add(contact);
                context.SaveChanges();
            }
        }

        public IEnumerable<IContact> GetContacts()
        {
            return this.context.Contacts;
        }

        public async Task<IList<string>> GetCurrentRoles(string userName)
        {
            User? currentUser = await context.Users.FirstOrDefaultAsync(p => p.UserName == userName);
            string idUser = currentUser.Id;
            IList<string> roleIdCol = new List<string>();

            foreach (var item in context.UserRoles)
            {
                if (item.UserId == idUser)
                {
                    roleIdCol.Add(item.RoleId);
                }
            }
            IList<string> roleNameCol = new List<string>();
            foreach (var item in roleIdCol)
            {
                IdentityRole<string> nextRole = await context.Roles.FirstOrDefaultAsync(p => p.Id == item);
                if (nextRole != null)
                {
                    roleNameCol.Add(nextRole.Name);
                }
            }
            return roleNameCol;
        }

        public async Task<IList<string>> GetAllUsers()
        {
            IList<string> userNameCol= new List<string>();
            foreach (var item in context.Users)
            {
                userNameCol.Add(item.UserName);
            }
            return userNameCol;
        }

        public async Task<IList<string>> GetAllAdmins()
        {
            IList<string> adminsId= new List<string>();
            foreach (var item in context.UserRoles)
            {
                if (item.RoleId == "1")
                {
                    adminsId.Add(item.UserId);
                }
            }
            IList<string> adminNameCol = new List<string>();
            foreach (var item in adminsId)
            {
                User? adminUser = await context.Users.FirstOrDefaultAsync(p => p.Id == item);
                adminNameCol.Add(adminUser.UserName);
            }
            return adminNameCol;
        }

        public async void DeleteContact(int id)
            {
                using (var context = new DataContext())
                {
                    Contact contact = await context.Contacts.FirstOrDefaultAsync(x => x.ID == id);
                    if (contact != null)
                    {
                        context.Contacts.Remove(contact);
                        await context.SaveChangesAsync();
                    }
                }
            }
        public async Task<IContact> GetContactByID(int Id) => ((IContact)await context.Contacts.FirstOrDefaultAsync(x => x.ID == Id));

        public async void ChangeContact(int id, Contact contact)
        {
            using (var context = new DataContext())
            {
                Contact concreteContact = await context.Contacts.FirstOrDefaultAsync(x => x.ID == id);
                concreteContact.Name = contact.Name;
                concreteContact.Surname = contact.Surname;
                concreteContact.FatherName = contact.FatherName;
                concreteContact.TelephoneNumber = contact.TelephoneNumber;
                concreteContact.ResidenceAdress = contact.ResidenceAdress;
                concreteContact.Description = contact.Description;
                await context.SaveChangesAsync();
            }
        }

        public async Task<Contact> Details(int id)
        {
            IContact concreteContact = await GetContactByID(id);
            return (Contact)concreteContact;
        }

        public async Task<string> CreateRole(RoleModel model)
        {
            string createResponse = string.Empty;
            try
            {
                if (!await _roleManager.RoleExistsAsync(model.roleName))
                {
                    await _roleManager.CreateAsync(new IdentityRole()
                    {
                        Name = model.roleName,
                        NormalizedName = model.roleName
                    });
                    createResponse = "Роль успешно добавлена";
                }
                else
                {
                    createResponse = "Роль уже существует";
                }
            }
            catch (Exception)
            {
                createResponse = "Ошибка выполнения";
            }
            return createResponse;
        }

        public async Task<string> AddRoleToUser(RoleModel model)
        {
            string createResponse = string.Empty;
            try
            {
                var user = await _userManager.FindByNameAsync(model.userName);
                if (await _roleManager.RoleExistsAsync(model.roleName))
                {
                    createResponse += "Роль доступна для добавления";
                    if (user != null)
                    {
                        await _userManager.AddToRoleAsync(user, model.roleName);
                        createResponse += "Пользователь указан верно";
                        createResponse += "Роль успешно добавлена";
                    }
                    else
                    {
                        createResponse += "Пользователь отсутствует";
                    }
                }
                else
                {
                    createResponse += "Ошибка: указанная роль не существует";
                    if (user != null)
                    {
                        createResponse += "Пользователь указан верно";
                    }
                    else
                    {
                        createResponse += "Пользователь отсутствует";
                    }
                }
            }
            catch (Exception)
            {
                createResponse += "Ошибка выполнения";
            }
            return createResponse;
        }

        public async Task<string> RemoveUserRole(RoleModel model)
        {
            string createResponse = string.Empty;
            try
            {
                var user = await _userManager.FindByNameAsync(model.userName);
                if (await _roleManager.RoleExistsAsync(model.roleName))
                {
                    createResponse += "Роль доступна для удаления";
                    IdentityRole? concreteRole = context.Roles.FirstOrDefault(p => p.Name == model.roleName);

                    IdentityUserRole<string>? someUserRole = context.UserRoles.FirstOrDefault(p => p.UserId == user.Id && p.RoleId == concreteRole.Id);
                    if (user != null)
                    {
                        createResponse += "Пользователь указан верно";
                        if (someUserRole != null)
                        {
                            await _userManager.RemoveFromRoleAsync(user, model.roleName);
                            createResponse += "Роль успешно удалена";
                        }
                        else
                        {
                            createResponse += "Роль отсутствует у указанного пользователя";
                        }
                    }
                    else
                    {
                        createResponse += "Пользователь отсутствует";
                    }
                }
                else
                {
                    createResponse += "Ошибка: указанная роль не существует";
                    if (user != null)
                    {
                        createResponse += "Пользователь указан верно";
                    }
                    else
                    {
                        createResponse += "Пользователь отсутствует";
                    }
                }
            }
            catch (Exception)
            {
                createResponse += "Ошибка выполнения";
            }
            return createResponse;

        }

        public async Task<string> RemoveUser(RoleModel model)
        {
            string createResponse = string.Empty;
            try
            {
                var user = await _userManager.FindByNameAsync(model.userName);
                if(user!= null)
                {
                    await _userManager.DeleteAsync(user);
                    createResponse = "Пользователь успешно удален";
                }
                else
                {
                    createResponse = "Пользователь отсутствует";
                }
            }
            catch
            {
                createResponse = "Ошибка";
            }
            return createResponse;
        }

        public async Task<TokenResponseModel> Login(UserLoginProp loginData)
        {
            User newUser = new User()
            {
                UserName = loginData.UserName
            };
            User? user = await context.Users.FirstOrDefaultAsync(p => p.UserName == newUser.UserName);

            if (user is null)
            {
                return null;
            }
            else
            {
                var passwordHasher = new PasswordHasher<string>();
                var passwordVerificationResult = passwordHasher.VerifyHashedPassword(null, user.PasswordHash, loginData.Password);
                switch (passwordVerificationResult)
                {
                    case PasswordVerificationResult.Failed:
                        return null;
                }
            }
            string id = user.Id;
            IdentityUserRole<string> userRole = await context.UserRoles.FirstOrDefaultAsync(p => p.UserId == id);
            if (userRole != null)
            {
                string roleId = userRole.RoleId;

                var jwt = GenerateJwtToken(user.UserName, roleId);

                var response = new TokenResponseModel
                {
                    access_token = jwt,
                    username = user.UserName
                };
                return (response);
            }
            else
            {
                return null;
            }
        }

        private string GenerateJwtToken(string userName, string roleId)
        {
            if (roleId == "1")
            {
                var claims = new List<Claim> {
                            new Claim(ClaimTypes.Name, userName),
                            new Claim(ClaimTypes.Role, "Admin")
                        };
                var jwt = new JwtSecurityToken(
                issuer: Configuration["Jwt:Issuer"]!,
                audience: Configuration["Jwt:Audience"]!,
                claims: claims,
                expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(Configuration["Jwt:Secret"]!)
                    ),
                    SecurityAlgorithms.HmacSha256));
                return new JwtSecurityTokenHandler().WriteToken(jwt);
            }
            else
            {
                var claims = new List<Claim> {
                            new Claim(ClaimTypes.Name, userName),
                            new Claim(ClaimTypes.Role, "User")
                        };
                var jwt = new JwtSecurityToken(
                issuer: Configuration["Jwt:Issuer"]!,
                audience: Configuration["Jwt:Audience"]!,
                claims: claims,
                expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(Configuration["Jwt:Secret"]!)
                    ),
                    SecurityAlgorithms.HmacSha256));
                return new JwtSecurityTokenHandler().WriteToken(jwt);
            }
        }

        /// </summary>
        /// <param name="loginData"></param>
        /// <returns></returns>
        public async Task<TokenResponseModel> Register(UserRegistration registrData)
        {
            var user = new User { UserName = registrData.LoginProp };
            var createResult = await _userManager.CreateAsync(user, registrData.Password);
            var addRoleResult = await _userManager.AddToRoleAsync(user, "User");
            var jwt = GenerateJwtToken(user.UserName, "2");

            var response = new TokenResponseModel
            {
                access_token = jwt,
                username = user.UserName
            };

            if (createResult.Succeeded && addRoleResult.Succeeded)
            {
                return response;
            }
            else
            {
                return null;
            }
        }

        public async Task<TokenResponseModel> AdminRegister(UserRegistration registrData)
        {
            var user = new User { UserName = registrData.LoginProp };
            var createResult = await _userManager.CreateAsync(user, registrData.Password);
            var addRoleResult = await _userManager.AddToRoleAsync(user, "User");
            var jwt = GenerateJwtToken(user.UserName, "2");

            var response = new TokenResponseModel
            {
                access_token = jwt,
                username = user.UserName
            };
            if (createResult.Succeeded && addRoleResult.Succeeded)
            {
                return response;
            }
            else
            {
                return null;
            }
        }
            //    public IActionResult Login(UserLoginProp loginData)
            //    {
            //        using (var context = new DataContext())
            //        {
            //            User newUser = new User()
            //            {
            //                UserName = loginData.UserName
            //            };

        //            User? user = context.Users.FirstOrDefault(p => p.UserName == newUser.UserName);

        //            if (user is null)
        //            {
        //                return Unauthorized();
        //            }
        //            else
        //            {
        //                var passwordHasher = new PasswordHasher<string>();
        //                var passwordVerificationResult = passwordHasher.VerifyHashedPassword(null, user.PasswordHash, loginData.Password);
        //                switch (passwordVerificationResult)
        //                {
        //                    case PasswordVerificationResult.Failed:
        //                        return Results.Unauthorized();
        //                }
        //            }
        //            var jwt = GenerateJwtToken(user.UserName);

        //            var response = new TokenResponseModel
        //            {
        //                access_token = jwt,
        //                username = user.UserName
        //            };
        //            return Ok(response);
        //        }
        //        return Unauthorized();
        //    }

        //    private string GenerateJwtToken(string userName)
        //    {
        //        var claims = new List<Claim> {
        //                        new Claim(ClaimTypes.Name, userName),
        //                        new Claim(ClaimTypes.Role, "Admin")
        //                    };

        //        var jwt = new JwtSecurityToken(
        //            issuer: Configuration["Jwt:Issuer"]!,
        //            audience: Configuration["Jwt:Audience"]!,
        //            claims: claims,
        //            expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
        //            signingCredentials: new SigningCredentials(
        //                new SymmetricSecurityKey(
        //                    Encoding.UTF8.GetBytes(Configuration["Jwt:Secret"]!)
        //                ),
        //                SecurityAlgorithms.HmacSha256));
        //        return new JwtSecurityTokenHandler().WriteToken(jwt);
        //    }

        //}

        //public class TokenResponseModel
        //{
        //    public string access_token { get; set; }
        //    public string username { get; set; }
        //}
    }
}
 
