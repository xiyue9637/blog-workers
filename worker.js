// worker.js
// 纯 JavaScript 实现的 SHA-256（无外部依赖）
function sha256(message) {
  // 常量和辅助函数
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  
  function rightRotate(value, bits) {
    return (value >>> bits) | (value << (32 - bits));
  }
  
  // 预处理
  const messageBuffer = new TextEncoder().encode(message);
  const l = messageBuffer.length * 8;
  const N = Math.ceil((l + 65) / 512);
  const M = new Uint32Array(N * 16);
  
  for (let i = 0; i < messageBuffer.length; i++) {
    M[i >> 2] |= messageBuffer[i] << (8 * (3 - (i % 4)));
  }
  
  M[l >>> 5] |= 0x80 << (24 - (l % 32));
  M[N * 16 - 1] = l;
  
  // 哈希计算
  let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  
  for (let i = 0; i < N; i++) {
    const W = new Uint32Array(64);
    for (let t = 0; t < 16; t++) W[t] = M[i * 16 + t];
    for (let t = 16; t < 64; t++) {
      const s0 = rightRotate(W[t-15], 7) ^ rightRotate(W[t-15], 18) ^ (W[t-15] >>> 3);
      const s1 = rightRotate(W[t-2], 17) ^ rightRotate(W[t-2], 19) ^ (W[t-2] >>> 10);
      W[t] = (W[t-16] + s0 + W[t-7] + s1) | 0;
    }
    
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    
    for (let t = 0; t < 64; t++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;
      
      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }
    
    H[0] = (H[0] + a) | 0;
    H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0;
    H[5] = (H[5] + f) | 0;
    H[6] = (H[6] + g) | 0;
    H[7] = (H[7] + h) | 0;
  }
  
  // 格式化输出
  return Array.from(H, h => ('00000000' + h.toString(16)).slice(-8)).join('');
}

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
    const data = header + '.' + payload;
    const hash = sha256(secret + data);
    return hash === signature;
  } catch {
    return false;
  }
}

// 解码 JWT payload
function decodePayload(token) {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

// 获取用户信息
async function getUser(env, username) {
  const user = await env.BLOG_KV.get(`users/${username}`);
  return user ? JSON.parse(user) : null;
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
          
          // 生成 JWT
          const payload = JSON.stringify({
            username,
            role: user.role,
            exp: Date.now() + 86400000 // 24小时
          });
          
          const tokenHeader = btoa(JSON.stringify({ alg: 'HS256' }));
          const tokenPayload = btoa(payload);
          const token = tokenHeader + '.' + tokenPayload;
          const signature = sha256(env.SECRET_KEY + token);
          
          return new Response(JSON.stringify({ 
            token: token + '.' + signature,
            role: user.role,
            avatar: user.avatar
          }), { headers });
        }
        
        // 获取用户信息（用于检查登录状态）
        if (pathname === '/api/user' && request.method === 'GET') {
          const token = request.headers.get('Authorization')?.split(' ')[1];
          if (!token || !verifyToken(token, env.SECRET_KEY)) {
            return new Response(JSON.stringify({ error: '未授权' }), { 
              status: 401, 
              headers 
            });
          }
          
          const payload = decodePayload(token);
          if (!payload) {
            return new Response(JSON.stringify({ error: '无效的令牌' }), { 
              status: 401, 
              headers 
            });
          }
          
          const user = await getUser(env, payload.username);
          if (!user || user.banned) {
            return new Response(JSON.stringify({ 
              error: user?.banned ? BAN_MESSAGE : '用户不存在' 
            }), { 
              status: 403, 
              headers 
            });
          }
          
          return new Response(JSON.stringify({
            username: user.username,
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
          
          const payload = decodePayload(token);
          if (!payload) {
            return new Response(JSON.stringify({ error: '无效的令牌' }), { 
              status: 401, 
              headers 
            });
          }
          
          const user = await getUser(env, payload.username);
          if (!user || user.banned) {
            return new Response(JSON.stringify({ 
              error: user?.banned ? BAN_MESSAGE : '用户不存在' 
            }), { 
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
          
          const payload = decodePayload(token);
          if (!payload) {
            return new Response(JSON.stringify({ error: '无效的令牌' }), { 
              status: 401, 
              headers 
            });
          }
          
          const user = await getUser(env, payload.username);
          if (!user || user.banned) {
            return new Response(JSON.stringify({ 
              error: user?.banned ? BAN_MESSAGE : '用户不存在' 
            }), { 
              status: 403, 
              headers 
            });
          }
          
          const postId = pathname.split('/').pop();
          const post = await env.BLOG_KV.get(`posts/${postId}`, 'json');
          
          if (!post) {
            return new Response(JSON.stringify({ error: '帖子不存在' }), { 
              status: 404, 
              headers 
            });
          }
          
          // 检查权限：管理员或帖子作者
          if (user.role !== 'admin' && post.author !== user.username) {
            return new Response(JSON.stringify({ error: '无权删除此帖子' }), { 
              status: 403, 
              headers 
            });
          }
          
          // 删除帖子和相关评论
          await env.BLOG_KV.delete(`posts/${postId}`);
          const commentKeys = await env.BLOG_KV.list({ prefix: `comments/${postId}/` });
          
          if (commentKeys.keys.length > 0) {
            await Promise.all(commentKeys.keys.map(k => env.BLOG_KV.delete(k.name)));
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
          
          const payload = decodePayload(token);
          if (!payload) {
            return new Response(JSON.stringify({ error: '无效的令牌' }), { 
              status: 401, 
              headers 
            });
          }
          
          const user = await getUser(env, payload.username);
          if (!user || user.banned) {
            return new Response(JSON.stringify({ 
              error: user?.banned ? BAN_MESSAGE : '用户不存在' 
            }), { 
              status: 403, 
              headers 
            });
          }
          
          const postId = pathname.split('/')[3];
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
          
          const payload = decodePayload(token);
          if (!payload) {
            return new Response(JSON.stringify({ error: '无效的令牌' }), { 
              status: 401, 
              headers 
            });
          }
          
          const user = await getUser(env, payload.username);
          if (!user || user.banned) {
            return new Response(JSON.stringify({ 
              error: user?.banned ? BAN_MESSAGE : '用户不存在' 
            }), { 
              status: 403, 
              headers 
            });
          }
          
          const [postId, commentId] = pathname.split('/').slice(-2);
          const comment = await env.BLOG_KV.get(`comments/${postId}/${commentId}`, 'json');
          
          if (!comment) {
            return new Response(JSON.stringify({ error: '评论不存在' }), { 
              status: 404, 
              headers 
            });
          }
          
          // 检查权限：管理员或评论作者
          if (user.role !== 'admin' && comment.author !== user.username) {
            return new Response(JSON.stringify({ error: '无权删除此评论' }), { 
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
          
          const payload = decodePayload(token);
          if (!payload) {
            return new Response(JSON.stringify({ error: '无效的令牌' }), { 
              status: 401, 
              headers 
            });
          }
          
          if (payload.role !== 'admin') {
            return new Response(JSON.stringify({ error: '仅管理员可操作' }), { 
              status: 403, 
              headers 
            });
          }
          
          const { username } = await request.json();
          const user = await getUser(env, username);
          
          if (!user || user.role === 'admin' || user.banned) {
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
          
          const payload = decodePayload(token);
          if (!payload) {
            return new Response(JSON.stringify({ error: '无效的令牌' }), { 
              status: 401, 
              headers 
            });
          }
          
          if (payload.role !== 'admin') {
            return new Response(JSON.stringify({ error: '仅管理员可操作' }), { 
              status: 403, 
              headers 
            });
          }
          
          const { username } = await request.json();
          const user = await getUser(env, username);
          
          if (!user || user.role === 'admin' || !user.banned) {
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
    
    // 首页请求 - 返回404，因为前端是独立的
    return new Response('Not Found', { status: 404 });
  }
};