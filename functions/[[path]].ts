export const onRequest: PagesFunction<{ PASSWORD: string }> = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);

  // 1. 如果你在 Cloudflare 没设置 PASSWORD 变量，直接放行（防止你忘记配置时网站瘫痪）
  const password = env.PASSWORD;
  if (!password) {
    return context.next();
  }

  const cookie = request.headers.get("Cookie") || "";
  const authCookie = `oneip_auth=${password}`;

  // 2. 处理登录表单提交
  if (request.method === "POST" && url.pathname === "/login") {
    try {
      const formData = await request.formData();
      const inputPassword = formData.get("password");

      if (inputPassword === password) {
        // 密码正确，写入 Cookie (有效期 30 天)，并重定向回首页
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `oneip_auth=${password}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`
          }
        });
      }
    } catch (e) {
      // 忽略解析错误
    }
    return new Response("密码错误，请返回重试", { status: 401, headers: { "content-type": "text/plain;charset=utf-8" } });
  }

  // 3. 检查浏览器 Cookie 是否带有正确的密码凭证
  if (cookie.includes(authCookie)) {
    // 验证通过，放行请求，加载你的 one-ip 页面或 API
    return context.next();
  }

  // 4. 未登录拦截：返回精美的固定密码输入框页面
  return new Response(
    `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>one-ip · 访问验证</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .box { background: #1e293b; padding: 35px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 320px; text-align: center; }
  h2 { margin-bottom: 20px; font-size: 20px; color: #38bdf8; }
  input { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #334155; border-radius: 6px; background: #0f172a; color: #fff; box-sizing: border-box; font-size: 14px; outline: none; }
  input:focus { border-color: #38bdf8; }
  button { width: 100%; padding: 12px; background: #3b82f6; border: none; border-radius: 6px; color: white; font-size: 14px; font-weight: bold; cursor: pointer; transition: background 0.2s; }
  button:hover { background: #2563eb; }
</style>
</head>
<body>
<div class="box">
  <h2>🔒 one-ip 私人工具</h2>
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="请输入固定访问密码" required autofocus />
    <button type="submit">进入系统</button>
  </form>
</div>
</body>
</html>`,
    {
      headers: { "content-type": "text/html;charset=utf-8" }
    }
  );
};
