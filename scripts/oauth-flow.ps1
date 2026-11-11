<#
.SYNOPSIS
    对 mcp-auth 服务器运行完整的 OAuth 2.1 授权码流程，然后用得到的访问令牌调用
    MCP 工具。

.DESCRIPTION
    整个过程都不需要浏览器：
      1. 发现：授权服务器元数据（RFC 8414）与受保护资源元数据（RFC 9728）
      2. 可选的动态客户端注册（RFC 7591）
      3. PKCE（S256）的 verifier 与 challenge
      4. 使用演示用户进行表单登录
      5. GET /oauth2/authorize -> 302 跳转到携带 ?code=... 的重定向 URI
      6. POST /oauth2/token，带上 client_id + code_verifier（公开客户端，无密钥）
      7. POST /mcp：initialize -> tools/list -> tools/call
      8. 反面校验：缺少令牌、被篡改的令牌，以及作用域过小的令牌

.EXAMPLE
    pwsh -File scripts/oauth-flow.ps1

.EXAMPLE
    pwsh -File scripts/oauth-flow.ps1 -Register
    # 注册一个全新的客户端（随机回环端口），而不是使用预注册的 mcp-cli
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://localhost:8080',
    [string]$User = 'user',
    [string]$Password = 'password',
    [string]$ClientId = 'mcp-cli',
    [string]$RedirectUri = 'http://127.0.0.1:8080/callback',
    [string]$Scope = 'mcp.tools.read mcp.tools.call',
    [switch]$Register
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step($message) {
    Write-Host "`n=== $message ===" -ForegroundColor Cyan
}

function ConvertTo-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# Invoke-WebRequest 无法在不抛异常的情况下交出 302 的 Location 响应头，而指向回环回调地址的
# 重定向在另一端并没有监听者。一个带 cookie 容器、关闭了自动重定向的简易 HttpClient
# 正好满足协议所需。
function New-NoRedirectClient {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(20)
    return $client
}

function Send-FormPost($client, [string]$uri, [hashtable]$fields) {
    $form = [System.Collections.Generic.Dictionary[string, string]]::new()
    foreach ($key in $fields.Keys) { $form[$key] = [string]$fields[$key] }
    $content = [System.Net.Http.FormUrlEncodedContent]::new($form)
    return $client.PostAsync($uri, $content).GetAwaiter().GetResult()
}

function Get-AccessToken {
    param(
        [string]$RequestedScope,
        [string]$Resource
    )

    $verifierBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
    $codeVerifier = ConvertTo-Base64Url $verifierBytes
    $challengeBytes = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
    $codeChallenge = ConvertTo-Base64Url $challengeBytes

    $client = New-NoRedirectClient

    # 登录：CSRF 令牌与会话绑定，所以必须先从表单里抓取出来。
    $loginPage = $client.GetStringAsync("$BaseUrl/login").GetAwaiter().GetResult()
    $csrf = [regex]::Match($loginPage, 'name="_csrf"[^>]*value="([^"]+)"').Groups[1].Value
    if (-not $csrf) { throw 'Could not find the CSRF token on the login page.' }
    $loginResponse = Send-FormPost $client "$BaseUrl/login" @{
        username = $User; password = $Password; _csrf = $csrf
    }
    $loginLocation = if ($loginResponse.Headers.Location) { $loginResponse.Headers.Location.ToString() } else { '' }
    if ($loginLocation -like '*error*') { throw "Login failed, redirected to $loginLocation" }
    Write-Host "login        : $([int]$loginResponse.StatusCode) -> $loginLocation"

    $authorizeUrl = "$BaseUrl/oauth2/authorize?" + (@(
            'response_type=code',
            "client_id=$([uri]::EscapeDataString($ClientId))",
            "redirect_uri=$([uri]::EscapeDataString($RedirectUri))",
            "scope=$([uri]::EscapeDataString($RequestedScope))",
            "state=$([guid]::NewGuid())",
            "code_challenge=$codeChallenge",
            'code_challenge_method=S256',
            "resource=$([uri]::EscapeDataString($Resource))"
        ) -join '&')

    $authorizeResponse = $client.GetAsync($authorizeUrl).GetAwaiter().GetResult()
    $location = if ($authorizeResponse.Headers.Location) { $authorizeResponse.Headers.Location.ToString() } else { '' }
    if (-not $location) {
        throw "Expected a redirect with an authorization code, got $([int]$authorizeResponse.StatusCode)"
    }
    if ($location -match 'error=') { throw "Authorization failed: $location" }
    $code = [regex]::Match($location, 'code=([^&]+)').Groups[1].Value
    if (-not $code) { throw "No authorization code in the redirect: $location" }
    Write-Host "authorize    : code=$($code.Substring(0, 12))... (PKCE challenge $($codeChallenge.Substring(0, 12))...)"

    $tokenResponse = Invoke-RestMethod -Uri "$BaseUrl/oauth2/token" -Method Post -Body @{
        grant_type    = 'authorization_code'
        code          = $code
        redirect_uri  = $RedirectUri
        client_id     = $ClientId
        code_verifier = $codeVerifier
    } -ContentType 'application/x-www-form-urlencoded'

    $claims = ConvertFrom-JwtPayload $tokenResponse.access_token
    Write-Host "token        : scope='$($tokenResponse.scope)' aud='$($claims.aud -join ',')' sub='$($claims.sub)'"

    return [pscustomobject]@{
        Token  = $tokenResponse.access_token
        Claims = $claims
        Scope  = $tokenResponse.scope
    }
}

function ConvertFrom-JwtPayload([string]$jwt) {
    $payload = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

function Read-McpResponse($response) {
    # Streamable HTTP 传输要么以纯 JSON 应答，要么以 SSE 流应答。
    $contentType = $response.Headers['Content-Type'] -join ';'
    $text = if ($contentType -match 'text/event-stream') {
        ($response.Content -split "`n" |
            Where-Object { $_ -like 'data:*' } |
            ForEach-Object { $_.Substring(5).Trim() } |
            Where-Object { $_ }) -join ''
    }
    else {
        $response.Content
    }
    if (-not $text) { return $null }
    return ($text | ConvertFrom-Json)
}

function Invoke-Mcp {
    param(
        [string]$Method,
        $Params,
        [string]$SessionId,
        [string]$Token = $script:AccessToken
    )
    $payload = @{ jsonrpc = '2.0'; id = (Get-Random); method = $Method }
    if ($null -ne $Params) { $payload.params = $Params }
    $body = $payload | ConvertTo-Json -Depth 10

    $headers = @{
        Authorization          = "Bearer $Token"
        'MCP-Protocol-Version' = '2025-06-18'
        Accept                 = 'application/json, text/event-stream'
    }
    if ($SessionId) { $headers['Mcp-Session-Id'] = $SessionId }

    $response = Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -Body $body -ContentType 'application/json' `
        -Headers $headers -UseBasicParsing -SkipHttpErrorCheck
    return @{ Response = $response; Payload = (Read-McpResponse $response) }
}

# ---------------------------------------------------------------- 发现
Write-Step '1. Discovery'
$asMetadata = Invoke-RestMethod -Uri "$BaseUrl/.well-known/oauth-authorization-server"
Write-Host "issuer                : $($asMetadata.issuer)"
Write-Host "authorization_endpoint: $($asMetadata.authorization_endpoint)"
Write-Host "registration_endpoint : $($asMetadata.registration_endpoint)"
Write-Host "PKCE methods          : $($asMetadata.code_challenge_methods_supported -join ', ')"

$prm = Invoke-RestMethod -Uri "$BaseUrl/.well-known/oauth-protected-resource/mcp"
Write-Host "resource              : $($prm.resource)"
Write-Host "authorization_servers : $($prm.authorization_servers -join ', ')"
Write-Host "scopes_supported      : $($prm.scopes_supported -join ', ')"

# ---------------------------------------------------------------- 可选的注册
if ($Register) {
    Write-Step '2. Dynamic client registration (RFC 7591)'
    $registrationRequest = @{
        client_name                = 'oauth-flow.ps1 client'
        redirect_uris              = @($RedirectUri)
        grant_types                = @('authorization_code', 'refresh_token')
        response_types             = @('code')
        token_endpoint_auth_method = 'none'
        scope                      = $Scope
    } | ConvertTo-Json
    $registered = Invoke-RestMethod -Uri "$BaseUrl/oauth2/register" -Method Post -Body $registrationRequest `
        -ContentType 'application/json'
    $ClientId = $registered.client_id
    Write-Host "client_id : $ClientId"
    Write-Host "scope     : $($registered.scope)"
}
else {
    Write-Step "2. Using the pre-registered client '$ClientId' (pass -Register to try DCR)"
}

# ---------------------------------------------------------------- 真正的流程
Write-Step '3. Authorization code + PKCE'
$principal = Get-AccessToken -RequestedScope $Scope -Resource $prm.resource
$script:AccessToken = $principal.Token

Write-Step '4. MCP initialize'
$init = Invoke-Mcp -Method 'initialize' -Params @{
    protocolVersion = '2025-06-18'
    capabilities    = @{}
    clientInfo      = @{ name = 'oauth-flow.ps1'; version = '1.0.0' }
}
$sessionId = $init.Response.Headers['Mcp-Session-Id'] -join ''
Write-Host "status      : $($init.Response.StatusCode)"
Write-Host "server      : $($init.Payload.result.serverInfo.name) $($init.Payload.result.serverInfo.version)"
Write-Host "MCP session : $(if ($sessionId) { $sessionId } else { '(stateless)' })"

Write-Step '5. tools/list'
$list = Invoke-Mcp -Method 'tools/list' -Params @{} -SessionId $sessionId
$list.Payload.result.tools | ForEach-Object { Write-Host ("  - {0}: {1}" -f $_.name, $_.description) }

Write-Step '6. tools/call echo'
$call = Invoke-Mcp -Method 'tools/call' -Params @{ name = 'echo'; arguments = @{ text = 'hello from oauth-flow.ps1' } } -SessionId $sessionId
Write-Host "result: $(($call.Payload.result.content | ForEach-Object { $_.text }) -join '')"

Write-Step '7. tools/call whoami'
$who = Invoke-Mcp -Method 'tools/call' -Params @{ name = 'whoami'; arguments = @{} } -SessionId $sessionId
Write-Host "result: $(($who.Payload.result.content | ForEach-Object { $_.text }) -join '')"

# ---------------------------------------------------------------- 反面校验
Write-Step '8. Negative checks'

$noToken = Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -Body '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' `
    -ContentType 'application/json' -UseBasicParsing -SkipHttpErrorCheck
Write-Host "no token             -> $($noToken.StatusCode) $($noToken.Headers['WWW-Authenticate'] -join '')"

# 改动 aud 声明：签名不再匹配，因此这里验证的是篡改检测，而不是受众绑定。
# 签名有效时的受众绑定由集成测试覆盖——那里的测试能用服务器自己的密钥签名。
$parts = $script:AccessToken.Split('.')
$tamperedClaims = $principal.Claims.PSObject.Copy()
$tamperedClaims.aud = @('http://localhost:8080/other-mcp')
$tamperedSegment = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes(($tamperedClaims | ConvertTo-Json -Compress)))
$tamperedToken = "$($parts[0]).$tamperedSegment.$($parts[2])"
$tampered = Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -Body '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' `
    -ContentType 'application/json' -Headers @{ Authorization = "Bearer $tamperedToken" } `
    -UseBasicParsing -SkipHttpErrorCheck
Write-Host "tampered token       -> $($tampered.StatusCode)"

# 同一用户、同一客户端，但令牌只被授予了读作用域。
$readOnly = Get-AccessToken -RequestedScope 'mcp.tools.read' -Resource $prm.resource
$readInit = Invoke-Mcp -Method 'initialize' -Token $readOnly.Token -Params @{
    protocolVersion = '2025-06-18'
    capabilities    = @{}
    clientInfo      = @{ name = 'oauth-flow.ps1'; version = '1.0.0' }
}
$readSession = $readInit.Response.Headers['Mcp-Session-Id'] -join ''
$allowed = Invoke-Mcp -Method 'tools/call' -Token $readOnly.Token -SessionId $readSession `
    -Params @{ name = 'now'; arguments = @{} }
Write-Host "read scope -> now    -> tool result: $(($allowed.Payload.result.content | ForEach-Object { $_.text }) -join '')"
$denied = Invoke-Mcp -Method 'tools/call' -Token $readOnly.Token -SessionId $readSession `
    -Params @{ name = 'add'; arguments = @{ a = 2; b = 3 } }
Write-Host "read scope -> add    -> isError: $($denied.Payload.result.isError) / $(($denied.Payload.result.content | ForEach-Object { $_.text }) -join '')"

Write-Host "`nDONE." -ForegroundColor Green
