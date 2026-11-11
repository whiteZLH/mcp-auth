package com.example.mcpauth.web;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.mcpauth.login.DingTalkUserService;

/**
 * 登录页：演示账号表单，外加在配置了钉钉登录时出现的钉钉入口。
 *
 * <p>替换掉 Spring Security 自动生成的页面，好让第二个入口更容易被发现 ——
 * {@code /oauth2/authorization/dingtalk} 正是 {@code oauth2Login} 过滤器监听的 URL，
 * 它据此发起跳转到钉钉的重定向。
 *
 * <p>占位符用 {@link String#replace} 而不是 {@code formatted} 替换：CSS 中含有字面量
 * {@code %} 字符，{@code String.format} 会试图解释它们。
 */
@RestController
public class LoginPageController {

    private static final String TEMPLATE = """
            <!doctype html>
            <html lang="zh-CN">
            <head><meta charset="utf-8"><title>登录 - mcp-auth</title>
              <style>
                body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem;line-height:1.6}
                h1{font-size:1.25rem;margin-bottom:1.5rem}
                label{display:block;font-size:.85rem;color:#555;margin:.75rem 0 .25rem}
                input{width:100%;padding:.5rem;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}
                button{width:100%;margin-top:1.25rem;padding:.6rem;border:0;border-radius:6px;background:#1a73e8;color:#fff;font-size:.95rem;cursor:pointer}
                a.dingtalk{display:block;margin-top:1rem;padding:.6rem;border:1px solid #1a73e8;border-radius:6px;color:#1a73e8;text-align:center;text-decoration:none}
                .hint{font-size:.8rem;color:#777;margin-top:1rem}
                code{background:#f2f3f5;padding:.1rem .3rem;border-radius:4px}
              </style>
            </head>
            <body>
              <h1>登录</h1>
              <form method="post" action="/login">
                <input type="hidden" name="_csrf" value="{{csrf}}"/>
                <label for="username">用户名</label>
                <input id="username" name="username" autocomplete="username" autofocus/>
                <label for="password">密码</label>
                <input id="password" name="password" type="password" autocomplete="current-password"/>
                <button type="submit">登录</button>
              </form>
              {{dingtalk}}
            </body>
            </html>
            """;

    private static final String DINGTALK_BUTTON = """
            <a class="dingtalk" href="/oauth2/authorization/dingtalk">使用钉钉登录</a>
            <p class="hint">跳转到钉钉授权页，登录后自动回到这里继续完成 MCP 授权。</p>
            """;

    private static final String DINGTALK_DISABLED = """
            <p class="hint">钉钉登录未启用：设置 <code>app.login.dingtalk.client-id</code> /
               <code>client-secret</code> 后重启即可。</p>
            """;

    private final ObjectProvider<DingTalkUserService> dingTalkUserService;

    public LoginPageController(ObjectProvider<DingTalkUserService> dingTalkUserService) {
        this.dingTalkUserService = dingTalkUserService;
    }

    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    String login(CsrfToken csrfToken) {
        boolean dingTalkEnabled = this.dingTalkUserService.getIfAvailable() != null;
        return TEMPLATE
                .replace("{{csrf}}", csrfToken.getToken())
                .replace("{{dingtalk}}", dingTalkEnabled ? DINGTALK_BUTTON : DINGTALK_DISABLED);
    }
}
