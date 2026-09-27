// A deliberately tiny router. Roughly 35 lines, no dependencies, nothing hidden.
//
// This is provided so you don't spend hackathon time writing routing plumbing.
// Read it once — it is the whole story of how a request becomes a handler call.

const PARAM = /^:(.+)$/;

export function createRouter() {
  const routes = [];

  function add(method, pattern, handler) {
    routes.push({ method, segments: split(pattern), handler });
  }

  // Returns { handler, params } or null. First match wins, so register
  // specific paths before parameterised ones if they could overlap.
  function match(method, pathname) {
    const parts = split(pathname);

    for (const r of routes) {
      if (r.method !== method || r.segments.length !== parts.length) continue;

      const params = {};
      let ok = true;

      for (let i = 0; i < r.segments.length; i++) {
        const seg = r.segments[i];
        const param = PARAM.exec(seg);
        if (param) {
          params[param[1]] = decodeURIComponent(parts[i]);
        } else if (seg !== parts[i]) {
          ok = false;
          break;
        }
      }

      if (ok) return { handler: r.handler, params, pattern: r.segments.length ? '/' + r.segments.join('/') : '/' };
    }

    return null;
  }

  return {
    get: (p, h) => add('GET', p, h),
    post: (p, h) => add('POST', p, h),
    patch: (p, h) => add('PATCH', p, h),
    delete: (p, h) => add('DELETE', p, h),
    match,
    get routes() { return routes; },
  };
}

function split(path) {
  return path.split('/').filter(Boolean);
}
