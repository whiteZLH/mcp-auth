package com.example.mcpauth.web;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.mcpauth.config.McpAuthProperties;

/**
 * 面向人的落地页：列出开发者接入客户端时需要用到的各个端点。
 */
@RestController
public class HomeController {

    private final McpAuthProperties properties;

    public HomeController(McpAuthProperties properties) {
        this.properties = properties;
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    String home() {
        String scopes = String.join(", ", properties.scopes());
        return """
                <!doctype html>
                <html lang="en">
                <head><meta charset="utf-8"><title>mcp-auth</title>
                  <style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.55}
                  code{background:#f2f3f5;padding:.15rem .35rem;border-radius:4px}
                  td{padding:.25rem .75rem .25rem 0;vertical-align:top}</style>
                </head>
                <body>
                  <h1>mcp-auth</h1>
                  <p>An MCP server (Streamable HTTP) protected by OAuth 2.1, with the authorization server
                     running in the same process.</p>

                  <h2>Endpoints</h2>
                  <table>
                    <tr><td><code>%1$s</code></td><td>MCP endpoint — requires <code>Authorization: Bearer &lt;jwt&gt;</code></td></tr>
                    <tr><td><code>%2$s/.well-known/oauth-protected-resource/mcp</code></td><td>RFC 9728 protected resource metadata</td></tr>
                    <tr><td><code>%2$s/.well-known/oauth-authorization-server</code></td><td>RFC 8414 authorization server metadata</td></tr>
                    <tr><td><code>%2$s/oauth2/register</code></td><td>RFC 7591 dynamic client registration</td></tr>
                    <tr><td><code>%2$s/oauth2/authorize</code></td><td>Authorization endpoint (PKCE S256 required)</td></tr>
                    <tr><td><code>%2$s/oauth2/token</code></td><td>Token endpoint</td></tr>
                    <tr><td><code>%2$s/oauth2/jwks</code></td><td>Signing keys</td></tr>
                  </table>

                  <h2>Scopes</h2>
                  <p><code>%3$s</code></p>

                  <h2>Demo user</h2>
                  <p><code>user</code> / <code>password</code> — log in at <a href="/login">/login</a>.</p>
                </body>
                </html>
                """.formatted(properties.primaryResourceUri(), properties.issuer(), scopes);
    }
}
