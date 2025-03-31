using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var googleOAuth = builder.Configuration.GetSection("GoogleOAuth");

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
})
.AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
{
    options.ClientId = googleOAuth["ClientId"];
    options.ClientSecret = googleOAuth["ClientSecret"];
    options.CallbackPath = "/signin-google";
    options.SaveTokens = true;
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
        ValidAudience = builder.Configuration["JwtSettings:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:SecretKey"]!))
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseSession();

// Google Login Route
app.MapGet("/", async (HttpContext context) =>
{
    await context.ChallengeAsync(GoogleDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = "/profile"
    });
});

app.MapGet("/profile", async (HttpContext context) =>
{
    var user = context.User;
    if (!user.Identity.IsAuthenticated)
    {
        return Results.Unauthorized();
    }

    var claims = user.Claims.Select(c => new { c.Type, c.Value });
    return Results.Json(new { Message = "Authenticated", Claims = claims });
}).RequireAuthorization();

app.MapGet("/signin-google", async (HttpContext context) =>
{
    var result = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    if (result.Succeeded)
    {
        var user = result.Principal;
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.FindFirst(ClaimTypes.NameIdentifier)?.Value!),
            new Claim(JwtRegisteredClaimNames.Email, user.FindFirst(ClaimTypes.Email)?.Value!)
        };

        var jwt = new JwtSecurityToken(
            issuer: builder.Configuration["JwtSettings:Issuer"],
            audience: builder.Configuration["JwtSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(60),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:SecretKey"]!)),
                SecurityAlgorithms.HmacSha256)
        );

        var token = new JwtSecurityTokenHandler().WriteToken(jwt);
        return Results.Json(new { token });
    }

    return Results.Unauthorized();
});

app.MapGet("/protected-route", (HttpContext context) =>
{
    var user = context.User;
    if (user.Identity?.IsAuthenticated ?? false)
    {
        return Results.Json(new { message = "Welcome, authenticated user!" });
    }
    return Results.Unauthorized();
}).RequireAuthorization(JwtBearerDefaults.AuthenticationScheme);

app.Run();