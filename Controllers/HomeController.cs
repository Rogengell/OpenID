using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using OAuth.Models;

namespace OAuth.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly IHttpClientFactory _clientFactory;
    private readonly string clientSecret = "osBnRG3qgAyk83F57EZK6WkFeWbE1lCV";
    public record AuthorizationResponse(string state, string code);
    private readonly string clientId = "mvc-client";
    private readonly string callback  = "http://localhost:5141/callback";

    public HomeController(ILogger<HomeController> logger, IHttpClientFactory clientFactory)
    {
        _logger = logger;
        _clientFactory = clientFactory;
    }

    public IActionResult Index()
    {
        return View();
    }

    [HttpGet("/login")]
    public async Task<IActionResult> LoginAsync()
    {
        var http = _clientFactory.CreateClient();
        var config = await http.GetFromJsonAsync<OpenIdConfig>(
            "http://localhost:8080/realms/master/.well-known/openid-configuration");

        var state = GenerateCodeVerifierAndState();
        var codeVerifier = GenerateCodeVerifierAndState();
        var codeVerifierBase64 = GenerateCodeChallenge(codeVerifier);
        
        var parameters = new Dictionary<string, string?>
        {
            { "client_id", clientId },
            { "scope", "openid email phone address profile" },
            { "response_type", "code" },
            { "redirect_uri", callback },
            { "prompt", "login" },
            { "state", state },
            { "code_challenge_method", "S256" },
            { "code_challenge", codeVerifierBase64 }
        };
        var authorizationUri = QueryHelpers.AddQueryString(config.authorization_endpoint, parameters);

        HttpContext.Session.SetString("auth_state", state);
        HttpContext.Session.SetString(state, codeVerifier);

        return Redirect(authorizationUri);
    }

    [HttpGet("/callback")]
    public async Task<IActionResult> Callback(AuthorizationResponse query)
    {
        string? storedState = HttpContext.Session.GetString("auth_state");

        var (state, code) = query;
        
        if (state != storedState)
        {
            return Unauthorized("State mismatch.");
        }

        string? codeVerifier = HttpContext.Session.GetString(state);

        var httpKey = _clientFactory.CreateClient();
        var configKey = await httpKey.GetFromJsonAsync<OpenIdConfig>(
            "http://localhost:8080/realms/master/.well-known/openid-configuration");

        var parameters = new Dictionary<string, string?>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", callback },
            { "code_verifier", codeVerifier },
            { "client_id", clientId },
            { "client_secret", clientSecret }
        };

        var responseToken =
            await new HttpClient().PostAsync(configKey.token_endpoint, new FormUrlEncodedContent(parameters));

        var payloadToken = await responseToken.Content.ReadFromJsonAsync<TokenResponse>();

        if (payloadToken == null || string.IsNullOrEmpty(payloadToken.id_token))
        {
            return Unauthorized("Failed to obtain ID token.");
        }

        var response = await new HttpClient().GetAsync(configKey.jwks_uri);
        var keys = await response.Content.ReadAsStringAsync();
        var jwks = Microsoft.IdentityModel.Tokens.JsonWebKeySet.Create(keys);
        jwks.SkipUnresolvedJsonWebKeys = false;

        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadToken(payloadToken.id_token) as JwtSecurityToken;

        if (jsonToken == null)
        {
            return Unauthorized("Invalid ID token.");
        }

        var key = jwks.Keys.FirstOrDefault(k => k.Kid == jsonToken.Header.Kid);
        if (key == null)
        {
            return Unauthorized("Public key not found for ID token.");
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = configKey.issuer,
            ValidateAudience = true,
            ValidAudience = clientId,
            ValidateLifetime = true,
            IssuerSigningKey = key
        };

        try
        {
            var principal = handler.ValidateToken(payloadToken.id_token, validationParameters, out var validatedToken);
        }
        catch (SecurityTokenException)
        {
            return Unauthorized("Token validation failed.");
        }

        var http = new HttpClient
        {
            DefaultRequestHeaders =
            {
                { "Authorization", "Bearer " + payloadToken.access_token }
            }
        };
        var responseUser = await http.GetAsync(configKey.userinfo_endpoint);
        var content = await responseUser.Content.ReadFromJsonAsync<KeycloakUserInfo?>();

        string userName = content.Name ?? content.PreferredUsername ?? "Unknown User";
        HttpContext.Session.SetString("UserId", content.Sub);
        HttpContext.Session.SetString("UserName", userName);

        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    public static string GenerateCodeVerifierAndState()
    {
        const int length = 64; // safe length between 43–128
        const string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

        var result = new StringBuilder(length);
        var byteBuffer = new byte[sizeof(uint)];

        using (var rng = RandomNumberGenerator.Create())
        {
            while (result.Length < length)
            {
                rng.GetBytes(byteBuffer);
                uint num = BitConverter.ToUInt32(byteBuffer, 0);
                var idx = num % (uint)allowedChars.Length;
                result.Append(allowedChars[(int)idx]);
            }
        }

        return result.ToString();
    }

    public static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(codeVerifier);
        var hash = sha256.ComputeHash(bytes);
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
public class OpenIdConfig
{
    public string authorization_endpoint { get; set; } = string.Empty;
    public string token_endpoint { get; set; } = string.Empty;
    public string userinfo_endpoint { get; set; } = string.Empty;
    public string jwks_uri { get; set; } = string.Empty;
    public string issuer { get; set; } = string.Empty;
}

public class TokenResponse
{
    public string access_token { init; get; }
    public int expires_in { init; get; }
    public string id_token { init; get; }
    public string scope { init; get; }
    public string token_type { init; get; }
    public string refresh_token { init; get; }
}

public class KeycloakUserInfo
{
    public string Sub { get; set; }           
    public string Name { get; set; }            
    public string PreferredUsername { get; set; } 
    public string GivenName { get; set; }    
    public string FamilyName { get; set; }       
    public string Email { get; set; }         
}
