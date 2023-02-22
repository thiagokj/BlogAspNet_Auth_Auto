# BlogAspNet

Projeto para revisão de conceito e aprendizado,
continuação do projeto [BlogAspNet](https://github.com/thiagokj/BlogAspNet_Validations)

Alguns exemplos iniciais sobre Autenticação e Autorização.

## Requisitos

```Csharp
dotnet add package Microsoft.AspNetCore.Authentication
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

## Autenticação e Autorização

**Autenticação:** Identifica quem é o usuário.
**Autorização:** Define o que é permitido pelo usuário.

Nas novas aplicações Web E APIs, o usuário não fica logado. É feita uma autenticação a cada requisição.

Resumo do processo:

1. Temos um Endpoint (Url) onde são informadas as credenciais para autenticação (Ex: usuario e senha).
1. As credenciais são transformadas em um Token (string longa encriptada).
1. E o Token é enviado de volta para tela.

A API faz o processo de verificar o Token com uma chave de acesso, decodificando a informação
e devolvendo para o usuário, conforme sua autorização de acesso.

O padrão de mercado é a utilização do Token JWT (pronuncia JÓTI), que é a notação para Json Web Token.

```Csharp
namespace BlogAspNet;
public static class Configuration
{
    // Chave codificada. Deve ser protegida e guardada no servidor.
    public static string JwtKey { get; set; } = "AquiDeveSerInformadaUmaChaveCodificada";
}
```

O próximo passo é criar um Serviço de Token para quem precisar gerar tokens.

```Csharp
public class TokenService
{
public string GenerateToken(User user)
{
// Manipulador de token
var tokenHandler = new JwtSecurityTokenHandler();

        // Retorna um array de bytes para passar ao tokenHandler
        var key = Encoding.ASCII.GetBytes(Configuration.JwtKey);

        // Contém as informações do token
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            // Geramos acumulos de afirmações sobre um usuário
            // com um objeto chave e valor do tipo Claim.
            Subject = new ClaimsIdentity(new Claim[]
            {
                new (ClaimTypes.Name,"thiago"), // User.Identity.Name
                new (ClaimTypes.Role,"admin"), // User.IsInRole
                new ("possoPassar","qualquerValor")
            }),
            // Tempo de expiração para novo login do usuario
            Expires = DateTime.UtcNow.AddHours(8),
            // Forma de assinatura das credenciais,
            // passando uma chave simétrica unica e exclusiva
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature
            )
        };

        // Cria o token baseado nas configurações de geração
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

}
```

Agora é necessário um controlador para gerenciar a criação do Token

```Csharp
[ApiController]
public class AccountController : ControllerBase
{
    [HttpPost("v1/login")]
    public IActionResult Login()
    {
        var tokenService = new TokenService();
        var token = tokenService.GenerateToken(null);

        return Ok(token);
    }
}
```

## Injeção de Dependência e Inversão de Controle

Note que o haverão outros métodos que vão depender do tokenService. Então aproveitamos a
técnica de **injeção de dependência** para informar ao Controller sobre essa dependência.

O código pode ser alterado para essa forma:

```Csharp
public class AccountController : ControllerBase
{
    // Cria a dependencia para ser resolvida posteriormente.
    private readonly TokenService _tokenService;
    public AccountController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    [HttpPost("v1/login")]
    public IActionResult Login()
    {
        var token = _tokenService.GenerateToken(null);

        return Ok(token);
    }...
```

E a declaração da dependência pode ser resumida com a chamada [FromServices]:

```Csharp
public class AccountController : ControllerBase
{
    [HttpPost("v1/login")]
    // Sempre que o prefixo [FromServices] for declarado, significa que o
    // método depende desse serviço.
    public IActionResult Login([FromServices] TokenService tokenService)
    {
        var token = tokenService.GenerateToken(null);
        return Ok(token);
    }
}
```

## AddScoped, AddTransient e AddSingleton

O padrão utilizado por esses métodos é o padrão de injeção de dependência,
que é uma técnica para gerenciar a criação e resolução de dependências entre diferentes
partes de uma aplicação. A injeção de dependência ajuda a tornar o código mais modular,
flexível e testável, permitindo que os serviços sejam facilmente substituídos e testados
em isolamento.

```Csharp
// Gerenciamento do ciclo de vida de serviços.
// Cria uma nova instancia a cada chamada do serviço.
builder.Services.AddTransient();

// Cria uma instância que dura até o fim de uma transação do serviço.
builder.Services.AddScoped();

// Cria somente uma instância na memória até que a aplicação seja encerreda.
builder.Services.AddSingleton();
```

# Configurando autenticação e autorização

Para fazer debug de tokens, pode ser utilizada a ferramenta [JWT IO](https://jwt.io/).

Configure a aplicação para fazer a autenticação e autorização, seguindo sempre essa ordem.

```Csharp
app.UseAuthentication();
app.UseAuthorization();
```

No builder, declare as configurações para autenticar apenas uma API:

```Csharp
var key = Encoding.ASCII.GetBytes(Configuration.JwtKey);
builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x =>
{
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});
```

Para fazer testes, crie métodos com as anotações permitindo ou restringindo o acesso
com base no token.

```Csharp
[AllowAnonymous] // Anotação para não exigir autenticação e gerar token
[HttpPost("v1/login")]
public IActionResult Login([FromServices] TokenService tokenService)
{
    var token = tokenService.GenerateToken(null);
    return Ok(token);
}

[Authorize(Roles = "user")] // Anotação exige token com permissão para o perfil de usuário
[HttpGet("v1/user")]
public IActionResult GetUser() => Ok(User.Identity.Name);

[Authorize(Roles = "author")]
[HttpGet("v1/author")]
public IActionResult GetAuthor() => Ok(User.Identity.Name);
```

Para tratamento de senhas, o ideal é utilizar um pacote que preve encriptação, salt e hashes.
Toda lógica de segurança deve ser aplicada para mitigar os riscos de acesso indevido e vazamentos.
Adicione ao projeto o pacote **dotnet add package SecureIdentity**

```Csharp
[HttpPost("v1/accounts/")]
    public async Task<IActionResult> Post(
        [FromBody] RegisterViewModel model,
        [FromServices] BlogDataContext context
    )
    {
        // Verifica se o modelo é valido
        if (!ModelState.IsValid)
            return BadRequest(new ResultViewModel<string>(ModelState.GetErrors()));
        
        var user = new User
        {
            Name = model.Name,
            Email = model.Email,
            Slug = model.Email.Replace("@", "-").Replace(".", "-")
        };

        // Gera uma senha aleatória e faz o hash único (codifica).
        var password = PasswordGenerator.Generate(25);
        user.PasswordHash = PasswordHasher.Hash(password);

        try
        {
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            return Ok(new ResultViewModel<dynamic>(new
            {
                user = user.Email,
                password
            }));
        }
        catch (DbUpdateException)
        {
            return StatusCode(400,
                new ResultViewModel<string>("A84F2X - Email já cadastrado."));
        }
        catch
        {
            return StatusCode(500,
                new ResultViewModel<string>("512XX - Falha interna do servidor."));
        }
    }
```

# Implementando uma ApiKey

Para consumir a api por outras aplicações, sem a necessidade de realizar novos logins após
a expiração de um token de acesso, pode ser criada uma chave API para acesso seguro.

Para isso, deve ser criado um **Attribute**. Os atributos no C# são as **decorations**(anotações)
que declaramos acima de classes e métodos.

```Csharp
public static class Configuration
{
...
    /*
        Chave secreta de autenticação para liberar o acesso a API, sem a necessidade de
        passar pelos métodos de autorização. Deve se tomar todas as medidas de segurança,
        evitando o vazamento dessa chave.
    */
    public static string ApiKeyName = "chave_api";
    public static string ApiKey = "AsudhauidhuiAHDiuhadui";
}
```

```Csharp
// Define o atributo personalizado
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class ApiKeyAttribute : Attribute, IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        // Se não houver a api na configuração, retorna erro.
        if (!context.HttpContext.Request.Query.TryGetValue(Configuration.ApiKeyName, out var extractedApiKey))
        {
            context.Result = new ContentResult()
            {
                StatusCode = 401,
                Content = "ApiKey não encontrada"
            };
            return;
        }

        // Se a chave informada não for a esperada, não permite o acesso.
        if (!Configuration.ApiKey.Equals(extractedApiKey))
        {
            context.Result = new ContentResult()
            {
                StatusCode = 403,
                Content = "Acesso não autorizado"
            };
            return;
        }

        await next();
    }
}
```