using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Project21API_Db.AuthContactApp;
using Project21API_Db.Models;
using System.Collections.Generic;

namespace Project21API_Db.ContextFolder
{
    public class DataContext : IdentityDbContext<User>
    {
        public DbSet<Contact> Contacts { get; set; }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer(
                @"Server=(localdb)\MSSQLLocalDB;
                  DataBase=Project21APIDBTest34;
                  Trusted_Connection=True;");
        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);
        }

        private void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                new IdentityRole() { Id = "1", Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin" },
                new IdentityRole() { Id = "2", Name = "User", ConcurrencyStamp = "2", NormalizedName = "User" }
                );

            string password = "12345Qq!";
            var passwordHasher = new PasswordHasher<User>();
            string hashedPassword = passwordHasher.HashPassword(null, password);
            string passwordUser = "12345Qq!!";
            var passwordHasherUser = new PasswordHasher<User>();
            string hashedPasswordUser = passwordHasherUser.HashPassword(null, passwordUser);

            builder.Entity<User>().HasData
                (
                new User() {Id = "1", UserName = "Admin321", PasswordHash = hashedPassword, NormalizedUserName = "ADMIN321", Email = "Admin@mail.ru"},
                new User() {Id = "2", UserName = "User123", PasswordHash = hashedPasswordUser, NormalizedUserName = "USER123", Email = "User123@mail.ru" }
                );

            builder.Entity<IdentityUserRole<string>>().HasData
                (
                new IdentityUserRole<string> { UserId = "1", RoleId = "1" },
                new IdentityUserRole<string> { UserId = "2", RoleId = "2" }
                );
        }
    }
}
