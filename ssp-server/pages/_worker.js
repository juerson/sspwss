const URLS = [
  'https://www.bilibili.com',
  'https://www.nicovideo.jp',
  'https://tv.naver.com',
  'https://www.hotstar.com',
  'https://www.netflix.com',
  'https://www.dailymotion.com',
  'https://www.youtube.com',
  'https://www.hulu.com',
  'https://fmovies.llc',
  'https://hdtodayz.to',
  'https://radar.cloudflare.com',
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    if (request.headers.get("Upgrade") !== "websocket") {
      if (pathname === "/") {
        const redirectUrl = URLS[Math.floor(Math.random() * URLS.length)];
        return Response.redirect(redirectUrl, 301);
      } else if (pathname === "/cf") {
        return new Response(JSON.stringify(request.cf), { status: 200 });
      }
      return new Response("404 Not Found", { status: 404 });
    }
    const id = env.MY_DURABLE_OBJECT.idFromName(pathname);
	const stub = env.MY_DURABLE_OBJECT.get(id);
	return await stub.fetch(request);
  },
};