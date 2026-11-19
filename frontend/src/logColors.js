const includes = (text, words) => words.some((word) => text.includes(word))

export function logLevel(message) {
  const text = String(message ?? '').toLowerCase()
  if (!text) return 'dim'
  if (includes(text, ['critical', 'fatal', 'traceback', 'error:', '[error]', 'exception:'])) return 'critical'
  if (includes(text, [
    'warning', 'warn:', 'already installed', 'already cloned', 'skipped',
    'manual required', 'not found', 'unavailable', 'retry', 'retrying',
  ])) return 'low'
  if (includes(text, [
    'failed', 'failure', 'denied', 'refused', 'unauthorized', 'forbidden',
    'timeout', 'timed out', '502', '503', '504', 'high',
  ])) return 'high'
  if (includes(text, [
    'installed ', 'updated ', 'completed', 'complete', 'verified',
    'ready at', 'synced', 'success', 'passed', 'job finished',
  ])) return 'ok'
  if (/^\[\d+\/\d+\]/.test(text) || includes(text, [
    'install', 'update', 'download', 'pull', 'clon', 'running', 'process',
    'prepar', 'starting', 'started', 'sync', 'git ', 'sdkmanager',
  ])) return 'work'
  if (includes(text, [
    'info', 'http ', 'head ', 'version', 'source', 'official', 'pypi',
    'github', 'repository', 'repo', 'from ', '→', '$ ',
  ])) return 'info'
  return 'dim'
}

export function levelForStatus(status, action = '') {
  const value = String(status ?? '').toLowerCase()
  const verb = String(action ?? '').toLowerCase()
  if (['running', 'processing', 'installing', 'updating', 'pulling'].includes(value)) return value
  if (value === 'queued') return 'queued'
  if (['completed', 'done', 'passed', 'ok', 'installed', 'updated'].includes(value)) return 'ok'
  if (['failed', 'error', 'critical'].includes(value)) return 'critical'
  if (['skipped', 'warn', 'warning', 'low'].includes(value)) return 'low'
  if (verb.includes('install')) return 'installing'
  if (verb.includes('update')) return 'updating'
  if (verb.includes('pull')) return 'pulling'
  return value || 'dim'
}

export function bannerClass(level) {
  return `banner ${['critical', 'ok', 'work', 'low', 'high', 'info'].includes(level) ? level : 'info'}`
}
