using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace Backend.Models
{
    public class User: IdentityUser
    {
        string BillingAddress { get; set; }
        string ShippingAddress { get; set; }
    }
}
