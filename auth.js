/**
 * ไฟล์เดียวจัดการ OAuth ทั้งหมด (login / callback / me / logout) ผ่าน ?action=
 * vercel.json ส่ง path ต่อไปนี้มาที่ไฟล์นี้:
 *   /api/login     -> ?action=login
 *   /login         -> ?action=callback   (ต้องตรงกับ Redirect ที่ตั้งใน Discord เป๊ะๆ)
 *   /api/me        -> ?action=me
 *   /api/logout    -> ?action=logout
 */
import { kv } from '@vercel/kv';
import { randomBytes, randomUUID } from 'crypto';

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return Object.fromEntries(
    header
      .split(';')
      .filter(Boolean)
      .map((c) => {
        const i = c.indexOf('=');
        return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1))];
      })
  );
}

async function doLogin(req, res) {
  const state = randomBytes(16).toString('hex');
  res.setHeader('Set-Cookie', `riko_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);
  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: process.env.DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify guilds.members.read',
    state,
    prompt: 'none'
  });
  res.writeHead(302, { Location: `https://discord.com/oauth2/authorize?${params.toString()}` });
  res.end();
}

async function doCallback(req, res) {
  const { code, state, error } = req.query;
  const cookies = parseCookies(req);

  if (error) return res.redirect(302, '/?auth=error');
  if (!code || !state || state !== cookies.riko_oauth_state) {
    return res.redirect(302, '/?auth=state_mismatch');
  }

  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.DISCORD_REDIRECT_URI
      })
    });
    if (!tokenRes.ok) throw new Error('token_exchange_failed: ' + (await tokenRes.text()));
    const token = await tokenRes.json();

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });
    if (!userRes.ok) throw new Error('user_fetch_failed');
    const user = await userRes.json();

    let role = 'none';
    const guildId = process.env.DISCORD_GUILD_ID;
    if (guildId) {
      const memberRes = await fetch(`https://discord.com/api/users/@me/guilds/${guildId}/member`, {
        headers: { Authorization: `Bearer ${token.access_token}` }
      });
      if (memberRes.ok) {
        const roles = (await memberRes.json()).roles || [];
        if (roles.includes(process.env.DISCORD_ROLE_ADMIN)) role = 'admin';
        else if (roles.includes(process.env.DISCORD_ROLE_MEMBER)) role = 'member';
      }
    }

    const avatar = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${user.avatar.startsWith('a_') ? 'gif' : 'png'}?size=128`
      : `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(user.id) >> 22n) % 6n)}.png`;

    const profile = { id: user.id, name: user.global_name || user.username, handle: '@' + user.username, avatar, role };

    const sessionId = randomUUID();
    await kv.set(`session:${sessionId}`, profile, { ex: 60 * 60 * 24 * 7 });

    res.setHeader('Set-Cookie', [
      `riko_session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
      `riko_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
    ]);
    res.redirect(302, '/?auth=ok');
  } catch (e) {
    console.error(e);
    res.redirect(302, '/?auth=error');
  }
}

async function doMe(req, res) {
  const sid = parseCookies(req).riko_session;
  if (!sid) return res.status(200).json({ loggedIn: false });
  const profile = await kv.get(`session:${sid}`);
  if (!profile) return res.status(200).json({ loggedIn: false });
  res.status(200).json({ loggedIn: true, user: profile });
}

async function doLogout(req, res) {
  const sid = parseCookies(req).riko_session;
  if (sid) await kv.del(`session:${sid}`);
  res.setHeader('Set-Cookie', `riko_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  res.status(200).json({ ok: true });
}

export default async function handler(req, res) {
  switch (req.query.action) {
    case 'login': return doLogin(req, res);
    case 'callback': return doCallback(req, res);
    case 'me': return doMe(req, res);
    case 'logout': return doLogout(req, res);
    default: return res.status(404).json({ error: 'unknown action' });
  }
}
