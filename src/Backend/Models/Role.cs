using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace Backend.Models
{
    public class Role: IdentityRole
    {
        string Description { get; set; }
    }
}
