import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import { bannerClass, levelForStatus, logLevel } from '../logColors.js'
import ToolAccess from './ToolAccess.jsx'

const ACTIVE = ['queued', 'running']

export default function ToolManager() {
  const [catalog, setCatalog] = useState(null)
  const [jobs, setJobs] = useState([])
  const [installed, setInstalled] = useState([])
  const [message, setMessage] = useState('')
  const [messageLevel, setMessageLevel] = useState('info')
  const jobsRef = useRef([])

  const load = useCallback(async () => {
    try {
      const [catalogData, jobData, inventory] = await Promise.all([
        api('/api/tools/catalog'),
        api('/api/tools/jobs'),
        api('/api/tools/installed'),
      ])
      const previous = jobsRef.current
      jobsRef.current = jobData
      const finished = previous.find(
        (old) => ACTIVE.includes(old.status)
          && !ACTIVE.includes(jobData.find((job) => job.job_id === old.job_id)?.status || 'completed'),
      )
      setCatalog(catalogData)
      setJobs(jobData)
      setInstalled(inventory.tools || [])
      if (finished) {
        const current = jobData.find((job) => job.job_id === finished.job_id) || finished
        setMessage(`${finished.tool_id} ${finished.action}: ${current.status}. ${current.detail || ''}`.trim())
        setMessageLevel(levelForStatus(current.status, current.action))
      }
    } catch (e) {
      setMessage(e.message)
      setMessageLevel('critical')
    }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (!jobs.some((job) => ACTIVE.includes(job.status))) return undefined
    const timer = setInterval(load, 1000)
    return () => clearInterval(timer)
  }, [jobs, load])

  useEffect(() => {
    const onDone = (event) => {
      const detail = event.detail || {}
      setMessage(
        `${detail.tool_id || 'tool job'} ${detail.action || ''}: ${detail.status}. ${detail.detail || ''}`.trim(),
      )
      setMessageLevel(levelForStatus(detail.status, detail.action))
      void load()
    }
    window.addEventListener('apkpt:job-done', onDone)
    return () => window.removeEventListener('apkpt:job-done', onDone)
  }, [load])

  const start = async (path, label) => {
    try {
      const job = await api(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      })
      setMessage(`${label}: job ${job.job_id} is ${job.status}. ${job.detail || ''}`)
      setMessageLevel(job.level || levelForStatus(job.status, job.job?.action))
      setJobs((current) => [job, ...current.filter((item) => item.job_id !== job.job_id)])
      window.dispatchEvent(new CustomEvent('apkpt:job', {
        detail: {
          job_id: job.job_id,
          tool_id: job.tool_id || label,
          action: job.action || '',
          status: job.status,
          detail: job.detail || '',
        },
      }))
    } catch (e) {
      setMessage(e.message)
      setMessageLevel('critical')
    }
  }

  const openWeb = async (toolId) => {
    try {
      const result = await api(`/api/tools/web/${encodeURIComponent(toolId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      })
      await load()
      const install = typeof result.installed === 'boolean'
        ? result.installed
          ? `installed${result.version ? ` ${result.version}` : ''}`
          : 'not installed'
        : ''
      const parts = [`${toolId} web UI: ${result.status || 'done'}`]
      if (install) parts.push(install)
      if (result.detail) parts.push(result.detail)
      if (result.url) parts.push(result.url)
      setMessage(parts.join(' · '))
      setMessageLevel(
        result.level
        || (result.status === 'error' || result.status === 'failed' ? 'critical'
          : result.status === 'skipped' ? 'low' : 'ok'),
      )
    } catch (e) {
      setMessage(e.message)
      setMessageLevel('critical')
    }
  }

  const syncDb = async () => {
    try {
      const result = await api('/api/tools/installed/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      })
      await load()
      setMessage(`Installed-software database synced: ${result.added || 0} new record(s).`)
      setMessageLevel('ok')
    } catch (e) {
      setMessage(e.message)
      setMessageLevel('critical')
    }
  }

  const tools = catalog?.tools || []
  const running = jobs.filter((job) => ACTIVE.includes(job.status)).length
  const policy = catalog?.source_policy || {}
  const emulator = catalog?.emulator || {}

  return (
    <div>
      <div className="eyebrow">Administration</div>
      <h1>Tools &amp; emulator manager</h1>
      <div className="banner info">
        {catalog?.enabled
          ? 'Enabled · For authorized security testing only. Installs change local system state.'
          : 'Disabled — set APKPT_TOOL_MANAGER=1 and restart the server to run jobs.'}
      </div>
      {message && <div className={bannerClass(messageLevel)}>{message}</div>}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 18 }}>
        <button className="btn primary" onClick={() => start('/api/tools/install-all', 'install all')}>Install / update all</button>
        <button className="btn" onClick={() => start('/api/tools/update-all', 'update all')}>Update all</button>
        <button className="btn" onClick={() => start('/api/tools/all/verify_all', 'verify all')}>Verify sources</button>
        <button className="btn" onClick={() => start('/api/tools/emulator/install', 'emulator')}>Install emulator</button>
        <button className="btn" onClick={syncDb}>Sync installed DB</button>
        <button className="btn" onClick={() => openWeb('mobsf')}>Open MobSF</button>
        <a className="btn" href="/tools/dashboard">Installed software HTML</a>
        <button className="btn" onClick={load}>Refresh</button>
      </div>
      <div className="mgrid">
        <div className="mc">
          <h3>Jobs ({jobs.length}, {running} active)</h3>
          {jobs.length ? jobs.map((job) => (
            <div className="mc" key={job.job_id} style={{ marginBottom: 10, background: '#0a1425' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                <div>
                  <strong>{job.tool_id}</strong>{' '}
                  <span className="muted small">{job.action} · {job.job_id}</span>
                  <div className="small">{job.detail || ''}</div>
                </div>
                <span className={`pill ${levelForStatus(job.status, job.action)}`}>{job.status}</span>
              </div>
              <pre>
                {(job.logs || []).slice(-40).map((line, index) => (
                  <span className={`op-line op-${logLevel(line)}`} key={index}>{line}{'\n'}</span>
                ))}
              </pre>
            </div>
          )) : <div className="empty">No tool jobs yet.</div>}
        </div>
        <div className="mc">
          <h3>Source policy</h3>
          <p className="muted small">
            Official HTTPS hosts only; redirects to other hosts are rejected. Manual/licensed tools are never auto-installed.
          </p>
          <div className="chips">{(policy.allowed_hosts || catalog?.allowed_hosts || []).map((host) => <span className="chip" key={host}>{host}</span>)}</div>
          <h4>Operating system</h4>
          {Object.entries(catalog?.os || {}).map(([key, value]) => (
            <div className="kv" key={key}><span>{key}</span><span className="wrap">{String(value)}</span></div>
          ))}
          <h4>Emulator needs</h4>
          {Object.entries(emulator.needs || {}).map(([key, value]) => (
            <div className="kv" key={key}><span>{key.replaceAll('_', ' ')}</span><span className="wrap">{String(value)}</span></div>
          ))}
          <p className="muted small">{(emulator.requirements || []).join(' · ')} Emulator setup does not launch or modify a device.</p>
        </div>
      </div>
      <h3 style={{ marginTop: 22 }}>Installed software database</h3>
      {installed.length ? (
        <div className="tw">
          <table>
            <thead><tr><th>Tool</th><th>Version</th><th>Executable</th><th>Setup / archive</th><th>Web UI</th><th>Job</th></tr></thead>
            <tbody>
              {installed.map((record) => (
                <tr key={record.tool_id}>
                  <td><strong>{record.name}</strong><div className="muted small mono">{record.tool_id}</div></td>
                  <td className="mono small">{record.version || '—'}</td>
                  <td className="mono small wrap">{record.executable_path || '—'}</td>
                  <td className="mono small wrap">{record.setup_path || '—'}</td>
                  <td>
                    {record.web_url && <a className="btn compact" href={record.web_url} target="_blank" rel="noreferrer">Direct link</a>}{' '}
                    <button className="btn compact" onClick={() => openWeb(record.tool_id)}>Open (gated)</button>
                  </td>
                  <td className="mono small">{record.job_id || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <div className="empty">No installed software recorded yet. Run an install job or sync the catalog.</div>}
      <ToolAccess
        tools={tools}
        groups={catalog?.groups || []}
        onStart={start}
        onWeb={openWeb}
        onMessage={(text, level = 'info') => {
          setMessage(text)
          setMessageLevel(level)
        }}
      />
      <details className="advanced-table">
        <summary>Detailed catalog table</summary>
        <div className="tw">
          <table>
            <thead><tr><th>Tool</th><th>Category</th><th>Status</th><th>Version</th><th>Method</th><th>Notes</th></tr></thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={tool.id}>
                  <td><strong>{tool.name}</strong><div className="small muted">{tool.description}</div>
                    <div className="small"><a href={tool.source_url} target="_blank" rel="noreferrer">{tool.source_url}</a></div></td>
                  <td>{tool.category}</td>
                  <td><span className={`pill ${tool.installed ? 'completed' : 'skipped'}`}>{tool.installed ? 'installed' : 'missing'}</span></td>
                  <td className="mono small">{tool.version || '—'}</td>
                  <td>{tool.method}</td>
                  <td>{tool.invasive && <span className="pill error">invasive</span>}
                    {tool.install_note && <div className="small muted">{tool.install_note}</div>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  )
}
