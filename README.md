# mcp-auth

一个**用 OAuth 2.1 保护 MCP Server** 的完整可运行示例：单进程内同时扮演 **MCP 资源服务器**（Streamable HTTP，`/mcp`）和 **OAuth 2.1 授权服务器**（Spring Authorization Server），不依赖任何外部 IdP。

- 技术栈：Spring Boot **4.1.2** / Spring Security **7.1.x** / Spring AI **2.0.2**（MCP server webmvc，Streamable HTTP）/ Java **21**
- MCP 安全细节：`org.springaicommunity:mcp-server-security:0.1.14`
- 已实测：发现文档、PKCE 授权码流程、动态客户端注册、`aud` 绑定、scope 级授权、401 挑战、7 个集成测试、端到端脚本

---

## 1. 协议全景

MCP 的授权规范不是"给接口加个 Bearer 头"那么简单，它规定了资源服务器与授权服务器如何被发现、客户端如何自助注册、令牌如何绑定到资源。完整链路：

```
MCP Client (Inspector / Cursor / Claude)
   │
   │ ① POST /mcp            （无令牌）
   │◄── 401 + WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"
   │
   │ ② GET /.well-known/oauth-protected-resource/mcp        RFC 9728
   │◄── { resource, authorization_servers, scopes_supported }
   │
   │ ③ GET /.well-known/oauth-authorization-server          RFC 8414
   │◄── { issuer, authorization_endpoint, token_endpoint, registration_endpoint, S256 }
   │
   │ ④ POST /oauth2/register                                RFC 7591（匿名）
   │◄── { client_id, … }                                     public client + PKCE
   │
   │ ⑤ GET /oauth2/authorize?code_challenge=S256&resource=…  → 登录页 → 302 callback?code=…
   │ ⑥ POST /oauth2/token  (code + code_verifier)            → access_token（JWT）
   │
   ▼
⑦ POST /mcp  Authorization: Bearer <jwt>   → 校验 iss / exp / aud / scope → tools/list、tools/call
```

### 规范要求 → 本项目实现位置

| MCP 授权规范要求 | 实现 | 代码 |
|---|---|---|
| 资源元数据（RFC 9728），含 `resource`、`authorization_servers`、`scopes_supported` | Spring Security 7.1 原生 `protectedResourceMetadata(...)` + 社区 configurer | [`McpResourceServerConfig`](src/main/java/com/example/mcpauth/config/McpResourceServerConfig.java) |
| 401 必须带 `resource_metadata` 供客户端引导 | `BearerResourceMetadataTokenAuthenticationEntryPoint` | 同上 |
| 令牌绑定到资源（RFC 8707 语义） | 令牌 `aud` = `app.security.resource-uris` 全量，资源服务器命中任一即通过 | `mcpTokenCustomizer` / `AudienceValidator` |
| 授权码 + PKCE（S256），公开客户端（`none`） | `ClientSettings.requireProofKey(true)`，隐式/密码模式关闭 | [`AuthorizationServerConfig`](src/main/java/com/example/mcpauth/config/AuthorizationServerConfig.java) |
| 动态客户端注册（RFC 7591），无需人工开户 | `clientRegistrationEndpoint(...).openRegistrationAllowed(true)`，`InMemoryRegisteredClientRepository.save()` | 同上 |
| 回环地址任意端口回调（RFC 8252 §7.3） | 默认重定向校验器已放行 `127.0.0.1:<任意端口>` | 同上 |
| 会话不得跨用户共享 | `sessionBinding(...)`：`Mcp-Session-Id` 绑定到认证主体 | [`McpResourceServerConfig`](src/main/java/com/example/mcpauth/config/McpResourceServerConfig.java) |
| 工具级最小权限 | `scope` → `SCOPE_*` 权限 → `@PreAuthorize` | [`McpTools`](src/main/java/com/example/mcpauth/mcp/McpTools.java) |

---

## 2. 快速开始

前置：Java 21、Maven 3.9+。

```powershell
# 构建 + 跑测试
mvn -B clean verify

# 启动（8080 端口）
java -jar target/mcp-auth-0.0.1-SNAPSHOT.jar
# 或
mvn spring-boot:run
```

打开 <http://localhost:8080> 可看到端点列表。演示用户：`user` / `password`。

> **Maven 镜像说明**：这台机器的全局 `settings.xml` 把所有下载都指向内网 Nexus（`maven.teld.cn`），在外部网络不可达。项目内的
> [`.mvn/settings.xml`](.mvn/settings.xml) + [`.mvn/maven.config`](.mvn/maven.config) 把镜像改成阿里云公共仓库，
> 只对本项目生效；回到内网后删掉 `.mvn/` 即可恢复全局配置。

### 一条命令验证全链路

```powershell
pwsh -File scripts/oauth-flow.ps1
# 或让脚本自己走一遍动态客户端注册：
pwsh -File scripts/oauth-flow.ps1 -Register
```

脚本会依次打印：发现文档 → PKCE → 表单登录 → 授权码 → 令牌 claims → `initialize` → `tools/list` → `tools/call` → 三类拒绝场景（无令牌 / 被篡改令牌 / scope 不足）。

### 手工验证发现端点

```powershell
curl.exe http://localhost:8080/.well-known/oauth-protected-resource/mcp
# {"resource":"http://localhost:8080/mcp","authorization_servers":["http://localhost:8080"],
#  "scopes_supported":["mcp.tools.read","mcp.tools.call"], …}

curl.exe http://localhost:8080/.well-known/oauth-authorization-server
# {"issuer":"http://localhost:8080", … "registration_endpoint":"http://localhost:8080/oauth2/register",
#  "code_challenge_methods_supported":["S256"], …}

curl.exe -i -X POST http://localhost:8080/mcp -H "Content-Type: application/json" `
  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}'
# HTTP/1.1 401
# WWW-Authenticate: Bearer resource_metadata=http://localhost:8080/.well-known/oauth-protected-resource/mcp
```

---

## 3. 端点

| 端点 | 说明 |
|---|---|
| `POST/GET/DELETE /mcp` | MCP Streamable HTTP，需 `Authorization: Bearer <jwt>` |
| `/.well-known/oauth-protected-resource[/mcp]` | RFC 9728 资源元数据（匿名） |
| `/.well-known/oauth-authorization-server` | RFC 8414 授权服务器元数据（匿名） |
| `/.well-known/openid-configuration`、`/oauth2/jwks` | OIDC 发现、签名公钥 |
| `POST /oauth2/register` | RFC 7591 动态客户端注册（匿名，开放注册） |
| `GET /oauth2/authorize` | 授权端点，`code_challenge_method=S256` 必需 |
| `POST /oauth2/token` | 令牌端点（`authorization_code` / `refresh_token`） |
| `POST /oauth2/revoke`、`/oauth2/introspect` | 撤销、自省 |
| `GET /login` | 演示登录页 |

Scope：`mcp.tools.read`（`echo`/`now`/`whoami`）、`mcp.tools.call`（`add`）。

### 配置项（`app.security.*`）

| 键 | 作用 |
|---|---|
| `issuer` | `iss`、AS 元数据、PRM 里的 `authorization_servers`；必须与客户端实际访问的地址一致 |
| `resource-uris` | MCP 端点的可接受地址集合。全部写入令牌 `aud`，资源服务器命中任一即放行；第一项作为 PRM 的 `resource`。跨机接入时把 LAN IP / 域名加进来 |
| `scopes` | 对外声明的 scope，同时用于 DCR 的 scope 收敛 |
| `demo-user` | 登录页的演示账号 |
| `refresh-token-max-lifetime` | refresh token 链的**绝对**寿命（从首次签发算起）。轮换会重置单个 token 的 TTL，没有这个上限就等于永不过期；`0` 表示不限制 |
| `clients` | 预置的公开客户端（`client-id` / `client-name` / `redirect-uris` / 可选 `scopes`）。不写 `scopes` 表示授予全部；支持动态注册的客户端无需在此登记 |
| `app.login.dingtalk.*` | 钉钉登录（`client-id` / `client-secret` / 三个端点 / `user-name-attribute`）。`client-id` 为空即整体关闭，项目仍可用本地演示账号跑 |

```yaml
app:
  security:
    issuer: http://localhost:8080
    resource-uris:
      - http://localhost:8080/mcp
      - http://127.0.0.1:8080/mcp
    scopes: [mcp.tools.read, mcp.tools.call]
    clients:
      - client-id: mcp-cli
        client-name: mcp-auth CLI client
        redirect-uris:
          - http://127.0.0.1:8080/callback
          - http://localhost:6274/oauth/callback
```

---

## 4. 接入真实 MCP 客户端

### 两种接法

| 形态 | 适用 | 配置内容 |
|---|---|---|
| **直连**（推荐） | 客户端支持远程 MCP + OAuth | 一行 URL，无需 token / secret，客户端自动完成 401 → 资源元数据 → 动态注册 → 浏览器登录 |
| **stdio 桥接** | 客户端只支持本地 stdio 进程 | 用 `mcp-remote` 起本地代理，由它替客户端走 OAuth |

共用常量：URL `http://localhost:8080/mcp`（`http://127.0.0.1:8080/mcp` 同样可用），scope 会自动带 `mcp.tools.read mcp.tools.call`，首次连接时用 `user` / `password` 登录。

### MCP Inspector

```powershell
npx @modelcontextprotocol/inspector
```

Transport 选 **Streamable HTTP**，URL 填 `http://localhost:8080/mcp` → Connect。预置客户端里已包含它的回调 `http://localhost:6274/oauth/callback`。

### Claude Code

```powershell
claude mcp add --transport http mcp-auth http://localhost:8080/mcp
claude mcp list      # 确认已注册
```

在会话里输入 `/mcp` 选择 `mcp-auth` 触发授权，浏览器完成登录后令牌由 Claude Code 缓存并自动刷新。

### Cursor

`~/.cursor/mcp.json`（全局）或 `<repo>/.cursor/mcp.json`（项目级）：

```json
{
  "mcpServers": {
    "mcp-auth": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### VS Code（GitHub Copilot agent）

`.vscode/mcp.json`：

```json
{
  "servers": {
    "mcp-auth": {
      "type": "http",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

注意 VS Code 的 `"oauth": { "clientId": "..." }` 一旦写了就必须给 clientId（走预注册而非动态注册）：在 [`application.yml`](src/main/resources/application.yml) 的 `app.security.clients` 里加一个对应 redirect URI 的条目，再把该 clientId 填进配置。参考：[VS Code MCP 配置文档](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)。

### 其他客户端（Cline / Windsurf / Roo / Copilot CLI / Codex / Gemini CLI）

基本都是同一套 JSON，差异只在顶层键名和 `type` 取值：

```jsonc
{
  "mcpServers": {            // VS Code 原生格式用 "servers"
    "mcp-auth": {
      "type": "http",        // 有的客户端叫 "streamableHttp" / "streamable-http"
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### Claude Desktop（只支持 stdio，走 `mcp-remote` 桥接）

`%APPDATA%\Claude\claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "mcp-auth": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:8080/mcp"]
    }
  }
}
```

`mcp-remote` 用随机回环端口回调 —— 这正是动态注册放行"任意回环端口"的原因。

---

## 5. 代码地图

```
src/main/java/com/example/mcpauth/
├─ McpAuthApplication.java          启动类
├─ config/
│  ├─ McpAuthProperties.java        app.security.* 配置（issuer / resource-uris / scopes / 用户 / 静态客户端）
│  ├─ AuthorizationServerConfig.java  链①：授权服务器 + JWK + 令牌生成器 + aud 绑定 + DCR 定制
│  ├─ McpResourceServerConfig.java    链②：/mcp 资源服务器 + JWT 校验 + PRM + 401 挑战 + scope 权限
│  ├─ DefaultSecurityConfig.java      链③：落地页与表单登录
│  └─ DemoUserConfig.java             演示用户（换成 LDAP/DB/SSO 只需替换此 bean）
├─ mcp/
│  ├─ McpTools.java                 4 个工具，带 @PreAuthorize scope 约束
│  └─ McpToolConfiguration.java     把工具注册进 MCP server
└─ web/HomeController.java          端点导航页
scripts/oauth-flow.ps1              端到端协议演示脚本
src/test/java/…/McpAuthIntegrationTests.java   7 个黑盒集成测试
```

三条 filter chain 的顺序是刻意的：授权服务器（`/oauth2/**` 等）→ MCP 资源服务器（`/mcp` 与 PRM 路径，无状态）→ 其余（会话 + 表单登录）。

---

## 6. 关键设计取舍

1. **资源服务器不用 `issuer-uri` 自指**
   授权服务器与资源服务器同进程，用 `issuer-uri` 会在启动时向自己发 HTTP 请求。这里直接用共享的 `JWKSource` 构造 `NimbusJwtDecoder`，并单独配置签发者校验。
2. **`aud` 是一组地址，而不是请求里推导出来的那一个**
   `app.security.resource-uris` 里的所有地址都会写进令牌的 `aud`，资源服务器只要命中其中一个就放行。这样客户端把回环地址写成 `localhost` 还是 `127.0.0.1` 都能用；同时它仍然比"信任请求 URL"更严格——只有本部署声明过的地址才被接受。多资源场景再改成按 `resource` 参数映射。
3. **替换了 DCR 的 scope 校验**
   Spring Security 默认拒绝带 `scope` 的注册请求（`scope must not be set during Dynamic Client Registration`），而 MCP 客户端会按 PRM 里的 `scopes_supported` 带上 scope。这里保留重定向 URI / JWKS URI 校验，仅替换 scope 规则，并在转换阶段把 scope 收敛到服务端支持集合（未申请则授予全部）。见 [`AuthorizationServerConfig#dynamicClientRegistrationValidator`](src/main/java/com/example/mcpauth/config/AuthorizationServerConfig.java)。
4. **只引入 `mcp-server-security`，授权服务器侧用原生 7.1 能力**
   Spring Security 7.1 已原生提供 RFC 9728 与 RFC 7591，社区模块的 `McpServerOAuth2Configurer` 解决了资源服务器侧的 `aud` 校验、PRM 内容与 401 挑战；授权服务器侧则显式写出来，避免多一层"黑盒 + 写时覆盖"的配置顺序问题。
5. **公开客户端的 refresh token 是刻意绕过的框架默认值**
   Spring Security 不给"授权码模式的公开客户端"发 refresh token（`OAuth2RefreshTokenGenerator` 直接返回 null），而 MCP 客户端 100% 是公开客户端、access token 只有 5 分钟 —— 不补这一块，客户端每 5 分钟就要重新走一次浏览器。这里用两个小扩展补上：
   - `refreshTokensForPublicClients(...)`：在生成器层面补发，TTL 仍取客户端 `TokenSettings`
   - `PublicClientRefreshTokenAuthenticationConverter/Provider`：让只有 `client_id` 的刷新请求能通过令牌端点认证（用哨兵凭据严格区分，不会顺手绕过 PKCE）
   安全取舍：公开客户端的 refresh token 是纯 bearer 凭证，靠**轮换**（`reuseRefreshTokens(false)`）发现盗用，靠**绝对寿命**（`refresh-token-max-lifetime`）限制总时长。

---

## 7. 上生产前必须改的地方

| 现状（示例） | 生产做法 |
|---|---|
| RSA 密钥每次启动随机生成 | 从 KMS / 密钥库加载固定 JWK，多副本共享 |
| 注册客户端、授权记录存内存（重启即失） | `JdbcRegisteredClientRepository` + `JdbcOAuth2AuthorizationService`（建表脚本见 Spring Authorization Server 文档） |
| 演示用户 `user/password`、`{noop}` 明文 | 接企业 IdP（OIDC/SAML）、BCrypt/Argon2、MFA |
| 开放注册（任何人可注册客户端） | 加注册准入校验（如客户端元数据白名单、租户绑定、限流） |
| HTTP 明文 | 全链路 HTTPS（MCP 规范要求非回环必须 TLS），`issuer` 用 https |
| 访问令牌 5 分钟、无撤销联动 | 缩短 TTL + 自省/吊销、刷新令牌轮换、审计日志 |
| 无 CORS / 无限流 | 仅对可信来源开 CORS；对 `/mcp` 与 `/oauth2/*` 限流 |
| `sessionBinding` 仅内存默认实现 | 多副本时换成共享存储的 `McpSessionBindingRepository` |

---

## 8. 排查手册

| 现象 | 原因 / 处理 |
|---|---|
| 登录后 `/oauth2/authorize` 返回 `error=invalid_request&error_description=OAuth 2.0 Parameter: principal` | 会话里没有认证主体，通常是登录失败（注意 `UserDetailsService` 是否被覆盖）。本项目用 `DemoUserConfig` 显式定义用户。 |
| 客户端注册成功但授权时报 `invalid_scope` | 请求的 scope 不在 `app.security.scopes` 里，或客户端注册时带了服务端不支持的 scope（会被收敛为服务端支持的集合）。 |
| `/mcp` 一直 401，令牌看起来没问题 | 检查令牌 `aud` 是否包含 `app.security.resource-uris` 里的某一项。客户端用的地址如果不在列表里（换了端口、LAN IP、公网域名），要先把它加进配置。 |
| 401 里没有 `resource_metadata` | `/mcp` 未走 `McpResourceServerConfig` 这条链（检查 `securityMatcher`）。 |
| `mvn` 卡在下载 / 连接超时 | 全局 `settings.xml` 指向不可达内网 Nexus，见第 2 节的 `.mvn/` 说明。 |
| 端口被占用导致 `mvn package` 报 `Unable to rename …jar` | 先停掉正在运行的实例（Windows 会锁住 jar 文件）。 |

---

## 9. 扩展：登录接入钉钉（可选）

只把**用户登录**交给钉钉，MCP 侧完全不变：令牌仍由本应用签发，PRM / DCR / `aud` / scope 一律照旧，MCP 客户端不知道钉钉的存在。

### 为什么需要适配层

钉钉是 OAuth 2.0，但**不是 OpenID Connect**，有三处和 Spring 默认实现不一致：

| 环节 | 标准做法 | 钉钉 |
|---|---|---|
| 发现 | `issuer-uri` + discovery | 无 discovery，端点要写死 |
| 换票请求 | 表单 `client_id` / `client_secret` / `grant_type` | **JSON** `clientId` / `clientSecret` / `grantType` |
| 用户信息 | `Authorization: Bearer` | **`x-acs-dingtalk-access-token`** 头 + `/v1.0/contact/users/me` |
| 强制参数 | — | `prompt=consent`，且 `scope` 只支持 `openid` 或 `openid corpid` |

所以用两个自定义实现替换默认的：`DingTalkTokenResponseClient`、`DingTalkUserService`。

### 配置步骤

1. 在 [钉钉开发者后台](https://open-dev.dingtalk.com) 创建企业内部应用，拿到 AppKey / AppSecret
2. 「开发配置 → 安全设置 → 重定向URL」填 `http://localhost:8080`（生产换 HTTPS 域名）
3. 申请权限点：`Contact.User.Read`（`Contact.User.mobile` 才能拿完整手机号）
4. 设环境变量并启动：

```powershell
$env:DINGTALK_CLIENT_ID="dingxxxxxxxx"
$env:DINGTALK_CLIENT_SECRET="xxxxxxxx"
java -jar target/mcp-auth-0.0.1-SNAPSHOT.jar
```

5. 打开 <http://localhost:8080/login>，除了账号密码表单，会多出「使用钉钉登录」

回调地址固定为 `{baseUrl}/login/oauth2/code/dingtalk`，由 `ClientRegistration` 的 `redirect-uri` 模板决定。

### 验证结果（实测）

```
/login                          -> 200，页面含「使用钉钉登录」
/oauth2/authorization/dingtalk  -> 302 https://login.dingtalk.com/oauth2/auth
                                     ?prompt=consent&response_type=code
                                     &client_id=dingfakekey&scope=openid&state=...
                                     &redirect_uri=http://localhost:8081/login/oauth2/code/dingtalk
                                     &nonce=...&code_challenge=...&code_challenge_method=S256
```

Spring 会自动附加 `nonce` 与 PKCE 参数，钉钉侧忽略未知参数即可。适配层本身由 `DingTalkLoginAdapterTests` 用本地 stub server 覆盖（真实请求形状 + 响应映射），不需要钉钉账号。

### 实现中踩到的两个坑

1. **授权服务器的 `securityMatcher("/oauth2/**")` 会吞掉 `/oauth2/authorization/dingtalk`**
   那个 URL 属于 `oauth2Login` 的重定向端点，被 AS 链接走后返回 404，登录无法发起。现在 AS 链用 `NegatedRequestMatcher` 显式排除这个前缀。
2. **登录页不能用 `String.formatted()` 渲染**
   CSS 里的 `width:100%` 会被当成格式符，抛 `UnknownFormatConversionException: ';'`。改用 `String.replace` 占位符替换。

### 不配置钉钉时

`app.login.dingtalk.client-id` 为空 → 整个配置类不加载（`@ConditionalOnExpression`），登录页只显示账号密码表单并提示"钉钉登录未启用"。项目因此可以完全离线运行。
