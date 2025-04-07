using AuthLib;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("https://localhost:7197");

var config = builder.Configuration;

builder.Services.AddSingleton<JWTService>(sp =>
    new JWTService(
        Environment.GetEnvironmentVariable("JWT_SECRET_KEY") ?? config["JwtSettings:SecretKey"],
        builder.Configuration["JwtSettings:Issuer"],
        builder.Configuration["JwtSettings:Audience"]
    ));

builder.Services.AddSingleton<SpiceDBService>(sp =>
    new SpiceDBService(
        Environment.GetEnvironmentVariable("SPICEDB_ENDPOINT") ?? config["SpiceDB:Endpoint"],
        Environment.GetEnvironmentVariable("SPICEDB_API_TOKEN") ?? config["SpiceDB:ApiToken"]
    ));

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.Name = "myApp.auth";
})
.AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
{
    options.ClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? config["GoogleOAuth:ClientId"];
    options.ClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") ?? config["GoogleOAuth:ClientSecret"];
    options.CallbackPath = "/signin-google";
    options.SaveTokens = true;
});

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Welcome to AuthCore!!!!!");

app.MapGet("/login", async (HttpContext context, JWTService jwtService) =>
{
    if (!context.User.Identity.IsAuthenticated)
    {
        return Results.Unauthorized();
    }

    var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var email = context.User.FindFirst(ClaimTypes.Email)?.Value;

    if (string.IsNullOrEmpty(userId))
    {
        return Results.Unauthorized();
    }

    var jwtToken = jwtService.GenerateToken(userId);

    return Results.Ok(new { Token = jwtToken });
});

app.MapGet("/login-google", async (HttpContext context) =>
{
    await context.ChallengeAsync(GoogleDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = "/login"
    });
});

app.MapGet("/signin-google", async (HttpContext context) =>
{
    var result = await context.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

    if (!result.Succeeded)
    {
        var failure = result.Failure?.Message ?? "Unknown reason";
        return Results.Unauthorized();
    }

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Principal);

    var claims = result.Principal?.Identities.FirstOrDefault()?.Claims
        .Select(claim => new { claim.Type, claim.Value });

    return Results.Ok(claims);
});

app.MapGet("/check-permission", async (
    HttpContext context,
    string resource,
    string permission,
    SpiceDBService spiceDBService,
    JWTService jwtService) =>
{
    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

    if (!jwtService.ValidateToken(token))
    {
        return Results.Unauthorized();
    }
    var handler = new JwtSecurityTokenHandler();
    var jwtToken = handler.ReadJwtToken(token);
    var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == "nameid")?.Value;


    var hasPermission = await spiceDBService.CheckPermissionAsync(userId, resource, permission);

    Console.WriteLine("has permission: " + hasPermission);

    return hasPermission ? Results.Ok("Permission granted") : Results.Unauthorized();
});


app.Run();