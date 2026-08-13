/**
 * 대인라 판매 대시보드 - HTTP Basic 인증
 *
 * 아이디/비밀번호는 코드에 넣지 않고 Cloudflare Pages의
 * 암호화 환경변수(SITE_USER / SITE_PASS)에서 읽어온다.
 * Cloudflare 대시보드 > Workers & Pages > dil-f5e53b6063 > Settings > Variables and Secrets
 */

const REALM = 'Daeinla Sales Dashboard';

function unauthorized() {
  return new Response('인증이 필요합니다. (Authentication required)', {
    status: 401,
    headers: {
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;

  const expectedUser = env.SITE_USER;
  const expectedPass = env.SITE_PASS;

  // 환경변수가 없으면 열어두지 않고 차단(fail-closed)
  if (!expectedUser || !expectedPass) {
    return new Response('로그인 설정이 완료되지 않았습니다. (SITE_USER / SITE_PASS 미설정)', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }

  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Basic ')) return unauthorized();

  let decoded;
  try {
    decoded = atob(header.slice(6).trim());
  } catch (e) {
    return unauthorized();
  }

  const sep = decoded.indexOf(':');
  if (sep < 0) return unauthorized();

  const user = decoded.slice(0, sep);
  const pass = decoded.slice(sep + 1);

  if (user !== expectedUser || pass !== expectedPass) return unauthorized();

  const response = await next();
  const out = new Response(response.body, response);
  out.headers.set('Cache-Control', 'no-store');
  return out;
}
