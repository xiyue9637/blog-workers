// worker.js
import { sha256 } from 'js-sha256';

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'xiyue777';
const BAN_MESSAGE = '您的账号已被管理员封禁,请联系 linyi8100@gmail.com 解封';

// 初始化管理员账户
async function initAdmin(env) {
  const adminKey = `users/${ADMIN_USERNAME}`;
  const existing = await env.BLOG_KV.get(adminKey);
  if (!existing) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(ADMIN_PASSWORD, salt);
    
    await env.BLOG_KV.put(adminKey, JSON.stringify({
      passwordHash,
      salt: Array.from(salt),
      avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=admin',
      banned: false,
      role: 'admin',
      createdAt: new Date().toISOString()
    }));
  }
}

// 密码哈希函数
async function hashPassword(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  
  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );
  
  return Array.from(new Uint8Array(derivedKey))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// JWT 验证
function verifyToken(token, secret) {
  try {
    const [header, payload, signature] = token.split('.');
    const data = `${header}.${payload}`;
    const hash = sha256.hmac.create(secret).update(data).hex();
    return hash === signature;
  } catch {
    return false;
  }
}

// 获取用户信息
async function getUser(env, username) {
  const user = await env.BLOG_KV.get(`users/${username}`);
  return user ? JSON.parse(user) : null;
}

// 权限检查
function checkPermission(user, targetUser, postId, commentId) {
  if (!user) return { allowed: false, reason: '未登录' };
  if (user.banned) return { allowed: false, reason: BAN_MESSAGE };
  
  // 管理员拥有所有权限
  if (user.role === 'admin') return { allowed: true };
  
  // 普通用户权限检查
  if (targetUser && user.username !== targetUser) {
    return { allowed: false, reason: '无权操作他人账户' };
  }
  
  if (postId) {
    const postKey = `posts/${postId}`;
    const post = env.BLOG_KV.get(postKey);
    if (!post || post.author !== user.username) {
      return { allowed: false, reason: '无权操作他人帖子' };
    }
  }
  
  if (commentId) {
    const commentKey = `comments/${commentId}`;
    const comment = env.BLOG_KV.get(commentKey);
    if (!comment || comment.author !== user.username) {
      return { allowed: false, reason: '无权操作他人评论' };
    }
  }
  
  return { allowed: true };
}

// 主处理函数
export default {
  async fetch(request, env) {
    // 初始化管理员
    await initAdmin(env);
    
    const url = new URL(request.url);
    const { pathname } = url;
    
    // 处理 OPTIONS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,DELETE',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization'
        }
      });
    }
    
    // 静态资源
    if (pathname === '/') {
      return new Response(indexHTML, {
        headers: { 'Content-Type': 'text/html' }
      });
    }
    
    // API 路由
    if (pathname.startsWith('/api/')) {
      const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      };
      
      try {
        // 用户注册
        if (pathname === '/api/register' && request.method === 'POST') {
          const { username, password, avatar } = await request.json();
          
          if (await env.BLOG_KV.get(`users/${username}`)) {
            return new Response(JSON.stringify({ error: '用户名已存在' }), { 
              status: 400, 
              headers 
            });
          }
          
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const passwordHash = await hashPassword(password, salt);
          
          await env.BLOG_KV.put(`users/${username}`, JSON.stringify({
            passwordHash,
            salt: Array.from(salt),
            avatar: avatar || 'https://api.dicebear.com/7.x/avataaars/svg?seed=default',
            banned: false,
            role: 'user',
            createdAt: new Date().toISOString()
          }));
          
          return new Response(JSON.stringify({ success: true }), { headers });
        }
        
        // 用户登录
        if (pathname === '/api/login' && request.method === 'POST') {
          const { username, password } = await request.json();
          const user = await getUser(env, username);
          
          if (!user) {
            return new Response(JSON.stringify({ error: '用户不存在' }), { 
              status: 401, 
              headers 
            });
          }
          
          if (user.banned) {
            return new Response(JSON.stringify({ error: BAN_MESSAGE }), { 
              status: 403, 
              headers 
            });
          }
          
          const salt = new Uint8Array(user.salt);
          const passwordHash = await hashPassword(password, salt);
          
          if (passwordHash !== user.passwordHash) {
            return new Response(JSON.stringify({ error: '密码错误' }), { 
              status: 401, 
              headers 
            });
          }
          
          // 生成 JWT (简化版)
          const payload = JSON.stringify({
            username,
            role: user.role,
            exp: Date.now() + 86400000 // 24小时
          });
          
          const token = btoa(JSON.stringify({ alg: 'HS256' })) + '.' + btoa(payload);
          const signature = sha256.hmac.create(env.SECRET_KEY).update(token).hex();
          return new Response(JSON.stringify({ 
  token: token + '.' + signature,
  role: user.role,
  avatar: user.avatar
}), { headers });
        }
         // 发布帖子
        if (pathname === '/api/posts' && request.method === 'POST') {
          const token = request.headers.get('Authorization')?.split(' ')[1];
          if (!token || !verifyToken(token, env.SECRET_KEY)) {
            return new Response(JSON.stringify({ error: '未授权' }), { 
              status: 401, 
              headers 
            });
          }
          
          const payload = JSON.parse(atob(token.split('.')[1]));
          const user = await getUser(env, payload.username);
          const { allowed, reason } = checkPermission(user, null, null, null);
          
          if (!allowed) {
            return new Response(JSON.stringify({ error: reason }), { 
              status: 403, 
              headers 
            });
          }
          
          const { title, content, type } = await request.json();
          const postId = crypto.randomUUID();
          
          await env.BLOG_KV.put(`posts/${postId}`, JSON.stringify({
            id: postId,
            title,
            content,
            type,
            author: payload.username,
            createdAt: new Date().toISOString()
          }));
          
          return new Response(JSON.stringify({ postId }), { headers });
        }
        
        // 获取所有帖子
        if (pathname === '/api/posts' && request.method === 'GET') {
          const list = await env.BLOG_KV.list({ prefix: 'posts/' });
          const posts = [];
          
          for (const key of list.keys) {
            const post = await env.BLOG_KV.get(key.name, 'json');
            if (post) posts.push(post);
          }
          
          return new Response(JSON.stringify(posts), { headers });
        }
        
        // 删除帖子
        if (pathname.startsWith('/api/posts/') && request.method === 'DELETE') {
          const token = request.headers.get('Authorization')?.split(' ')[1];
          if (!token || !verifyToken(token, env.SECRET_KEY)) {
            return new Response(JSON.stringify({ error: '未授权' }), { 
              status: 401, 
              headers 
            });
          }
          
          const payload = JSON.parse(atob(token.split('.')[1]));
          const user = await getUser(env, payload.username);
          const postId = pathname.split('/').pop();
          
          const { allowed, reason } = checkPermission(user, null, postId, null);
          if (!allowed) {
            return new Response(JSON.stringify({ error: reason }), { 
              status: 403, 
              headers 
            });
          }
          
          // 删除帖子和相关评论
          await env.BLOG_KV.delete(`posts/${postId}`);
          const commentKeys = await env.BLOG_KV.list({ prefix: `comments/${postId}/` });
          
          if (commentKeys.keys.length > 0) {
            await env.BLOG_KV.delete(commentKeys.keys.map(k => k.name));
          }
          
          return new Response(JSON.stringify({ success: true }), { headers });
        }
        
        // 发布评论
        if (pathname.startsWith('/api/posts/') && pathname.endsWith('/comments') && request.method === 'POST') {
          const token = request.headers.get('Authorization')?.split(' ')[1];
          if (!token || !verifyToken(token, env.SECRET_KEY)) {
            return new Response(JSON.stringify({ error: '未授权' }), { 
              status: 401, 
              headers 
            });
          }
          
          const payload = JSON.parse(atob(token.split('.')[1]));
          const user = await getUser(env, payload.username);
          const postId = pathname.split('/')[3];
          
          const { allowed, reason } = checkPermission(user, null, null, null);
          if (!allowed) {
            return new Response(JSON.stringify({ error: reason }), { 
              status: 403, 
              headers 
            });
          }
          
          const { content } = await request.json();
          const commentId = crypto.randomUUID();
          
          await env.BLOG_KV.put(`comments/${postId}/${commentId}`, JSON.stringify({
            id: commentId,
            postId,
            content,
            author: payload.username,
            createdAt: new Date().toISOString()
          }));
          
          return new Response(JSON.stringify({ commentId }), { headers });
        }
        
        // 删除评论
        if (pathname.startsWith('/api/comments/') && request.method === 'DELETE') {
          const token = request.headers.get('Authorization')?.split(' ')[1];
          if (!token || !verifyToken(token, env.SECRET_KEY)) {
            return new Response(JSON.stringify({ error: '未授权' }), { 
              status: 401, 
              headers 
            });
          }
          
          const payload = JSON.parse(atob(token.split('.')[1]));
          const user = await getUser(env, payload.username);
          const [postId, commentId] = pathname.split('/').slice(-2);
          
          const { allowed, reason } = checkPermission(user, null, null, commentId);
          if (!allowed) {
            return new Response(JSON.stringify({ error: reason }), { 
              status: 403, 
              headers 
            });
          }
          
          await env.BLOG_KV.delete(`comments/${postId}/${commentId}`);
          return new Response(JSON.stringify({ success: true }), { headers });
        }
        
        // 封禁用户 (管理员)
        if (pathname === '/api/ban' && request.method === 'POST') {
          const token = request.headers.get('Authorization')?.split(' ')[1];
          if (!token || !verifyToken(token, env.SECRET_KEY)) {
            return new Response(JSON.stringify({ error: '未授权' }), { 
              status: 401, 
              headers 
            });
          }
          
          const payload = JSON.parse(atob(token.split('.')[1]));
          if (payload.role !== 'admin') {
            return new Response(JSON.stringify({ error: '仅管理员可操作' }), { 
              status: 403, 
              headers 
            });
          }
          
          const { username } = await request.json();
          const user = await getUser(env, username);
          
          if (!user || user.role === 'admin') {
            return new Response(JSON.stringify({ error: '无效操作' }), { 
              status: 400, 
              headers 
            });
          }
          
          await env.BLOG_KV.put(`users/${username}`, JSON.stringify({
            ...user,
            banned: true
          }));
          
          return new Response(JSON.stringify({ success: true }), { headers });
        }
        
        // 解封用户 (管理员)
        if (pathname === '/api/unban' && request.method === 'POST') {
          const token = request.headers.get('Authorization')?.split(' ')[1];
          if (!token || !verifyToken(token, env.SECRET_KEY)) {
            return new Response(JSON.stringify({ error: '未授权' }), { 
              status: 401, 
              headers 
            });
          }
          
          const payload = JSON.parse(atob(token.split('.')[1]));
          if (payload.role !== 'admin') {
            return new Response(JSON.stringify({ error: '仅管理员可操作' }), { 
              status: 403, 
              headers 
            });
          }
          
          const { username } = await request.json();
          const user = await getUser(env, username);
          
          if (!user || user.role === 'admin') {
            return new Response(JSON.stringify({ error: '无效操作' }), { 
              status: 400, 
              headers 
            });
          }
          
          await env.BLOG_KV.put(`users/${username}`, JSON.stringify({
            ...user,
            banned: false
          }));
          
          return new Response(JSON.stringify({ success: true }), { headers });
        }
        
        return new Response(JSON.stringify({ error: 'API 未实现' }), { 
          status: 404, 
          headers 
        });
      } catch (error) {
        console.error('API Error:', error);
        return new Response(JSON.stringify({ 
          error: '服务器内部错误',
          details: error.message 
        }), { 
          status: 500, 
          headers 
        });
      }
    }
    
    return new Response('Not Found', { status: 404 });
  }
};

// 前端 HTML (内联在 worker.js 中)
const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>渐变贴吧</title>
  <style>
    :root {
      --primary: #6a11cb;
      --secondary: #2575fc;
      --blur: 12px;
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      transition: background 0.5s ease;
    }
    
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      min-height: 100vh;
      padding: 20px;
      color: #333;
      overflow-x: hidden;
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    
    header {
      text-align: center;
      padding: 30px 0;
      margin-bottom: 30px;
    }
    
    h1 {
      font-size: 3.5rem;
      background: linear-gradient(to right, #fff, #e0e0e0);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-shadow: 0 2px 10px rgba(0,0,0,0.2);
      margin-bottom: 10px;
    }
    
    .subtitle {
      color: rgba(255, 255, 255, 0.8);
      font-size: 1.2rem;
      max-width: 600px;
      margin: 0 auto;
    }
    
    .card {
      background: rgba(255, 255, 255, 0.85);
      border-radius: 20px;
      backdrop-filter: blur(var(--blur));
      -webkit-backdrop-filter: blur(var(--blur));
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
      padding: 25px;
      margin-bottom: 30px;
      overflow: hidden;
    }
    
    .card h2 {
      color: var(--primary);
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 2px solid rgba(106, 17, 203, 0.2);
    }
    
    .form-group {
      margin-bottom: 20px;
    }
    
    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 600;
      color: var(--primary);
    }
    
    input, textarea, select {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e0e0e0;
      border-radius: 10px;
      font-size: 16px;
      transition: all 0.3s;
    }
    
    input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: var(--secondary);
      box-shadow: 0 0 0 3px rgba(37, 117, 252, 0.2);
    }
    
    button {
      background: linear-gradient(to right, var(--primary), var(--secondary));
      color: white;
      border: none;
      padding: 12px 25px;
      border-radius: 50px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
      box-shadow: 0 4px 15px rgba(106, 17, 203, 0.3);
    }
    
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 7px 20px rgba(106, 17, 203, 0.4);
    }
    
    button:active {
      transform: translateY(0);
    }
    
    .post {
      background: white;
      border-radius: 15px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
      border-left: 4px solid var(--secondary);
    }
    
    .post-header {
      display: flex;
      align-items: center;
      margin-bottom: 15px;
    }
    
    .avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      object-fit: cover;
      margin-right: 12px;
      border: 2px solid var(--secondary);
    }
    
    .author {
      font-weight: 600;
      color: var(--primary);
    }
    
    .post-title {
      font-size: 1.5rem;
      margin: 10px 0;
      color: #2c3e50;
    }
    
    .post-content {
      line-height: 1.6;
      color: #444;
      margin-bottom: 15px;
    }
    
    .comment {
      background: #f8f9fa;
      padding: 12px 15px;
      border-radius: 10px;
      margin-top: 10px;
      border-left: 3px solid var(--primary);
    }
    
    .comment-header {
      display: flex;
      align-items: center;
      margin-bottom: 5px;
    }
    
    .comment-author {
      font-weight: 600;
      color: var(--secondary);
      margin-right: 8px;
    }
    
    .comment-time {
      color: #777;
      font-size: 0.85rem;
    }
    
    .controls {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    
    .btn-delete {
      background: #ff4757;
      padding: 6px 12px;
      font-size: 0.9rem;
    }
    
    .auth-section {
      display: flex;
      gap: 15px;
      margin-top: 10px;
    }
    
    .user-info {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    .error {
      color: #ff4757;
      background: #ffeaa7;
      padding: 10px;
      border-radius: 8px;
      margin: 15px 0;
      display: none;
    }
    
    .tabs {
      display: flex;
      margin-bottom: 20px;
      border-bottom: 1px solid #e0e0e0;
    }
    
    .tab {
      padding: 12px 25px;
      cursor: pointer;
      font-weight: 600;
      color: #777;
    }
    
    .tab.active {
      color: var(--primary);
      border-bottom: 3px solid var(--primary);
    }
    
    .tab-content {
      display: none;
    }
    
    .tab-content.active {
      display: block;
    }
    
    @media (max-width: 768px) {
      h1 {
        font-size: 2.5rem;
      }
      
      .card {
        padding: 20px 15px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>渐变贴吧</h1>
      <p class="subtitle">一个丝滑流畅、实时模糊渐变的博客社区</p>
    </header>

    <div class="auth-section" id="authSection">
      <!-- 动态生成登录/注册/用户信息 -->
    </div>

    <div class="tabs">
      <div class="tab active" data-tab="posts">全部帖子</div>
      <div class="tab" data-tab="create">发帖</div>
    </div>

    <div id="postsTab" class="tab-content active">
      <div class="card">
        <h2>最新帖子</h2>
        <div id="postsContainer">
          <!-- 帖子将动态加载到这里 -->
        </div>
      </div>
    </div>

    <div id="createTab" class="tab-content">
      <div class="card">
        <h2>发布新帖</h2>
        <div class="form-group">
          <label for="postTitle">标题</label>
          <input type="text" id="postTitle" placeholder="输入帖子标题">
        </div>
        <div class="form-group">
          <label for="postType">类型</label>
          <select id="postType">
            <option value="text">纯文字</option>
            <option value="图文">图文</option>
          </select>
        </div>
        <div class="form-group">
          <label for="postContent">内容</label>
          <textarea id="postContent" rows="6" placeholder="分享你的想法..."></textarea>
        </div>
        <button id="submitPost">发布帖子</button>
        <div class="error" id="postError"></div>
      </div>
    </div>

    <div id="registerModal" class="card" style="display:none;">
      <h2>注册账号</h2>
      <div class="form-group">
        <label for="regUsername">用户名</label>
        <input type="text" id="regUsername" placeholder="输入用户名">
      </div>
      <div class="form-group">
        <label for="regPassword">密码</label>
        <input type="password" id="regPassword" placeholder="输入密码">
      </div>
      <div class="form-group">
        <label for="regAvatar">头像直链 (可选)</label>
        <input type="url" id="regAvatar" placeholder="https://example.com/avatar.jpg">
      </div>
      <button id="registerBtn">注册账号</button>
      <div class="error" id="regError"></div>
      <p>已有账号? <a href="#" id="showLogin">去登录</a></p>
    </div>

    <div id="loginModal" class="card">
      <h2>登录账号</h2>
      <div class="form-group">
        <label for="loginUsername">用户名</label>
        <input type="text" id="loginUsername" placeholder="输入用户名">
      </div>
      <div class="form-group">
        <label for="loginPassword">密码</label>
        <input type="password" id="loginPassword" placeholder="输入密码">
      </div>
      <button id="loginBtn">登录</button>
      <div class="error" id="loginError"></div>
      <p>没有账号? <a href="#" id="showRegister">去注册</a></p>
    </div>
  </div>

  <script>
    // 全局状态
    const state = {
      token: localStorage.getItem('token'),
      username: localStorage.getItem('username'),
      role: localStorage.getItem('role'),
      avatar: localStorage.getItem('avatar')
    };

    // DOM 元素
    const elements = {
      authSection: document.getElementById('authSection'),
      postsContainer: document.getElementById('postsContainer'),
      postTitle: document.getElementById('postTitle'),
      postType: document.getElementById('postType'),
      postContent: document.getElementById('postContent'),
      submitPost: document.getElementById('submitPost'),
      postError: document.getElementById('postError'),
      loginUsername: document.getElementById('loginUsername'),
      loginPassword: document.getElementById('loginPassword'),
      loginBtn: document.getElementById('loginBtn'),
      loginError: document.getElementById('loginError'),
      regUsername: document.getElementById('regUsername'),
      regPassword: document.getElementById('regPassword'),
      regAvatar: document.getElementById('regAvatar'),
      registerBtn: document.getElementById('registerBtn'),
      regError: document.getElementById('regError'),
      showRegister: document.getElementById('showRegister'),
      showLogin: document.getElementById('showLogin'),
      registerModal: document.getElementById('registerModal'),
      loginModal: document.getElementById('loginModal'),
      tabs: document.querySelectorAll('.tab'),
      tabContents: document.querySelectorAll('.tab-content')
    };

    // 初始化
    function init() {
      setupEventListeners();
      updateAuthUI();
      loadPosts();
      
      // 渐变动画
setInterval(() => {
  const hue = Math.floor(Math.random() * 360);
  // 使用字符串拼接代替模板字符串
  document.documentElement.style.setProperty('--primary', 'hsl(' + hue + ', 70%, 50%)');
  document.documentElement.style.setProperty('--secondary', 'hsl(' + ((hue + 60) % 360) + ', 70%, 50%)');
}, 5000);
    }
    // 设置事件监听
    function setupEventListeners() {
      // 切换标签
      elements.tabs.forEach(tab => {
        tab.addEventListener('click', () => {
          elements.tabs.forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          
          const tabName = tab.getAttribute('data-tab');
          elements.tabContents.forEach(content => {
            content.classList.remove('active');
            if (content.id === \`\${tabName}Tab\`) {
              content.classList.add('active');
            }
          });
        });
      });

      // 登录
      elements.loginBtn.addEventListener('click', async () => {
        const username = elements.loginUsername.value;
        const password = elements.loginPassword.value;
        
        if (!username || !password) {
          showError(elements.loginError, '请填写完整信息');
          return;
        }
        
        try {
          const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });
          
          const data = await response.json();
          
          if (response.ok) {
            state.token = data.token;
            state.username = username;
            state.role = data.role;
            state.avatar = data.avatar;
            
            localStorage.setItem('token', data.token);
            localStorage.setItem('username', username);
            localStorage.setItem('role', data.role);
            localStorage.setItem('avatar', data.avatar);
            
            updateAuthUI();
            clearError(elements.loginError);
            elements.loginUsername.value = '';
            elements.loginPassword.value = '';
          } else {
            showError(elements.loginError, data.error || '登录失败');
          }
        } catch (error) {
          showError(elements.loginError, '网络错误，请重试');
        }
      });

      // 注册
      elements.registerBtn.addEventListener('click', async () => {
        const username = elements.regUsername.value;
        const password = elements.regPassword.value;
        const avatar = elements.regAvatar.value;
        
        if (!username || !password) {
          showError(elements.regError, '请填写完整信息');
          return;
        }
        
        try {
          const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, avatar })
          });
          
          const data = await response.json();
          
          if (response.ok) {
            alert('注册成功！请登录');
            elements.regUsername.value = '';
            elements.regPassword.value = '';
            elements.regAvatar.value = '';
            clearError(elements.regError);
            showLoginModal();
          } else {
            showError(elements.regError, data.error || '注册失败');
          }
        } catch (error) {
          showError(elements.regError, '网络错误，请重试');
        }
      });

      // 发布帖子
      elements.submitPost.addEventListener('click', async () => {
        const title = elements.postTitle.value;
        const content = elements.postContent.value;
        const type = elements.postType.value;
        
        if (!title || !content) {
          showError(elements.postError, '标题和内容不能为空');
          return;
        }
        
        try {
          const response = await fetch('/api/posts', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': \`Bearer \${state.token}\`
            },
            body: JSON.stringify({ title, content, type })
          });
          
          const data = await response.json();
          
          if (response.ok) {
            elements.postTitle.value = '';
            elements.postContent.value = '';
            clearError(elements.postError);
            loadPosts();
          } else {
            showError(elements.postError, data.error || '发帖失败');
          }
        } catch (error) {
          showError(elements.postError, '网络错误，请重试');
        }
      });

      // 切换注册/登录模态框
      elements.showRegister.addEventListener('click', (e) => {
        e.preventDefault();
        showRegisterModal();
      });
      
      elements.showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        showLoginModal();
      });
    }

    // 加载帖子
    async function loadPosts() {
      try {
        const response = await fetch('/api/posts');
        const posts = await response.json();
        
        let html = '';
        for (const post of posts) {
          // 获取评论
          const commentResponse = await fetch(\`/api/posts/\${post.id}/comments\`);
          const comments = commentResponse.ok ? await commentResponse.json() : [];
          
          html += \`
            <div class="post">
              <div class="post-header">
                <img src="\${post.avatar || 'https://api.dicebear.com/7.x/avataaars/svg?seed=default'}" 
                     alt="\${post.author}" class="avatar">
                <div>
                  <div class="author">\${post.author}</div>
                  <div class="post-time">\${new Date(post.createdAt).toLocaleString()}</div>
                </div>
              </div>
              <h3 class="post-title">\${post.title}</h3>
              <div class="post-content">\${post.content}</div>
              
              <div class="controls">
                \${state.username && (state.role === 'admin' || state.username === post.author) ? 
                  \`<button class="btn-delete" data-post-id="\${post.id}">删除</button>\` : ''}
              </div>
              
              <div class="comments">
                <h4>评论 (\${comments.length})</h4>
                \${comments.map(comment => \`
                  <div class="comment">
                    <div class="comment-header">
                      <span class="comment-author">\${comment.author}</span>
                      <span class="comment-time">\${new Date(comment.createdAt).toLocaleString()}</span>
                    </div>
                    <p>\${comment.content}</p>
                    \${state.username && (state.role === 'admin' || state.username === comment.author) ? 
                      \`<button class="btn-delete" data-comment-id="\${comment.id}" 
                                data-post-id="\${post.id}">删除</button>\` : ''}
                  </div>
                \`).join('')}
                
                <div class="form-group" style="margin-top: 15px;">
                  <textarea class="comment-input" placeholder="发表评论..." 
                            data-post-id="\${post.id}" rows="2"></textarea>
                  <button class="submit-comment" data-post-id="\${post.id}">评论</button>
                </div>
              </div>
            </div>
          \`;
        }
        
        elements.postsContainer.innerHTML = html || '<p>还没有帖子，快来发布第一条吧！</p>';
        
        // 添加删除事件
        document.querySelectorAll('.btn-delete').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            const postId = btn.getAttribute('data-post-id');
            const commentId = btn.getAttribute('data-comment-id');
            
            if (postId && !commentId) {
              // 删除帖子
              if (!confirm('确定要删除这个帖子吗？')) return;
              
              const response = await fetch(\`/api/posts/\${postId}\`, {
                method: 'DELETE',
                headers: { 'Authorization': \`Bearer \${state.token}\` }
              });
              
              if (response.ok) {
                loadPosts();
              } else {
                alert('删除失败');
              }
            } else if (commentId) {
              // 删除评论
              if (!confirm('确定要删除这条评论吗？')) return;
              
              const response = await fetch(\`/api/comments/\${postId}/\${commentId}\`, {
                method: 'DELETE',
                headers: { 'Authorization': \`Bearer \${state.token}\` }
              });
              
              if (response.ok) {
                loadPosts();
              } else {
                alert('删除失败');
              }
            }
          });
        });
        
        // 添加评论事件
        document.querySelectorAll('.submit-comment').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            const postId = btn.getAttribute('data-post-id');
            const textarea = document.querySelector(\`.comment-input[data-post-id="\${postId}"]\`);
            const content = textarea.value;
            
            if (!content) {
              alert('评论内容不能为空');
              return;
            }
            
            const response = await fetch(\`/api/posts/\${postId}/comments\`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': \`Bearer \${state.token}\`
              },
              body: JSON.stringify({ content })
            });
            
            if (response.ok) {
              textarea.value = '';
              loadPosts();
            } else {
              alert('评论失败');
            }
          });
        });
      } catch (error) {
        elements.postsContainer.innerHTML = '<p>加载帖子失败，请刷新重试</p>';
      }
    }

    // 更新认证UI
    function updateAuthUI() {
      let html = '';
      
      if (state.token) {
        html = \`
          <div class="user-info">
            <img src="\${state.avatar}" alt="\${state.username}" class="avatar" style="width:40px;height:40px;">
            <div>
              <div>\${state.username} \${state.role === 'admin' ? '(管理员)' : ''}</div>
              <button id="logoutBtn" style="margin-top:5px;padding:3px 10px;font-size:0.9rem;">退出</button>
            </div>
          </div>
        \`;
      } else {
        html = \`
          <button id="loginBtnUI">登录</button>
          <button id="registerBtnUI">注册</button>
        \`;
      }
      
      elements.authSection.innerHTML = html;
      
      if (!state.token) {
        elements.loginModal.style.display = 'block';
        elements.registerModal.style.display = 'none';
      } else {
        document.getElementById('logoutBtn')?.addEventListener('click', logout);
      }
      
      document.getElementById('loginBtnUI')?.addEventListener('click', showLoginModal);
      document.getElementById('registerBtnUI')?.addEventListener('click', showRegisterModal);
    }

    // 显示模态框
    function showLoginModal() {
      elements.loginModal.style.display = 'block';
      elements.registerModal.style.display = 'none';
    }
    
    function showRegisterModal() {
      elements.loginModal.style.display = 'none';
      elements.registerModal.style.display = 'block';
    }

    // 错误处理
    function showError(element, message) {
      element.textContent = message;
      element.style.display = 'block';
    }
    
    function clearError(element) {
      element.textContent = '';
      element.style.display = 'none';
    }

    // 退出登录
    function logout() {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      localStorage.removeItem('role');
      localStorage.removeItem('avatar');
      
      state.token = null;
      state.username = null;
      state.role = null;
      state.avatar = null;
      
      updateAuthUI();
      loadPosts();
    }

    // 初始化应用
    document.addEventListener('DOMContentLoaded', init);
  </script>
</body>
</html>`;