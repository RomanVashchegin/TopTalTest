using Backend.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Backend.DbContext
{
    public class SecurityContext: IdentityDbContext<User>
    {
        public SecurityContext(DbContextOptions<SecurityContext> options): base(options) { }
    }
}
