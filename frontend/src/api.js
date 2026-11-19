export const API_BASE = import.meta.env.VITE_API_URL || ''

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export async function api(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase()
  const retries = ['GET', 'HEAD', 'OPTIONS'].includes(method) ? 2 : 0
  for (let attempt = 0; ; attempt += 1) {
    let res
    try {
      res = await fetch(`${API_BASE}${path}`, options)
    } catch (e) {
      if (attempt < retries) {
        await sleep(400 * (attempt + 1))
        continue
      }
      throw new Error(`Network error for ${path}: ${e.message || e}`)
    }
    if (res.ok) return res.json()
    let detail = ''
    try {
      const body = await res.json()
      detail = body.detail || JSON.stringify(body)
    } catch {
      try { detail = (await res.text()).slice(0, 300) } catch { /* empty body */ }
    }
    if ([502, 503, 504].includes(res.status) && attempt < retries) {
      await sleep(400 * (attempt + 1))
      continue
    }
    throw new Error(`${res.status} ${res.statusText || 'Request failed'} for ${path}: ${detail || 'no response body'}`)
  }
}

export function href(path) {
  return `${API_BASE}${path}`
}
