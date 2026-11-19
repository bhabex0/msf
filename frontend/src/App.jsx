import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './api.js'
import UploadPanel from './components/UploadPanel.jsx'
import ScanList from './components/ScanList.jsx'
import ResultView from './components/ResultView.jsx'
import ToolManager from './components/ToolManager.jsx'
import MiniShell from './components/MiniShell.jsx'
import LiveJobTerminal from './components/LiveJobTerminal.jsx'

export default function App() {
  const [health, setHealth] = useState(null)
  const [scans, setScans] = useState([])
  const [activeId, setActiveId] = useState(null)
  const [record, setRecord] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [view, setView] = useState('scan')
  const timer = useRef(null)

  const loadScans = useCallback(async () => {
    try {
      const list = await api('/api/scans')
      setScans(list)
      return list
    } catch (e) {
      setError(e.message)
      return []
    }
  }, [])

  useEffect(() => {
    api('/api/health').then(setHealth).catch((e) => setError(e.message))
    loadScans().then((list) => {
      if (list.length) setActiveId((current) => current || list[0].scan_id)
    })
  }, [loadScans])

  const loadRecord = useCallback(async (id) => {
    try {
      const data = await api(`/api/scans/${id}`)
      setRecord(data)
      setError('')
      return data
    } catch (e) {
      setError(e.message)
      return null
    }
  }, [])

  useEffect(() => {
    if (timer.current) clearInterval(timer.current)
    if (!activeId) {
      setRecord(null)
      return
    }
    loadRecord(activeId)
    timer.current = setInterval(async () => {
      const data = await loadRecord(activeId)
      if (data && !['queued', 'running'].includes(data.status)) {
        clearInterval(timer.current)
        loadScans()
      }
    }, 1200)
    return () => clearInterval(timer.current)
  }, [activeId, loadRecord, loadScans])

  const handleUpload = async (file) => {
    setBusy(true)
    setError('')
    try {
      const form = new FormData()
      form.append('file', file)
      const result = await api('/api/scans', { method: 'POST', body: form })
      await loadScans()
      setView('scan')
      setActiveId(result.scan_id)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const handleDelete = async (id) => {
    try {
      await api(`/api/scans/${id}`, { method: 'DELETE' })
      if (activeId === id) {
        setActiveId(null)
        setRecord(null)
      }
      await loadScans()
    } catch (e) {
      setError(e.message)
    }
  }

  const running = record && ['queued', 'running'].includes(record.status)

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">APK</div>
          <div>
            <div className="brand-title">Pentest Platform</div>
            <div className="brand-sub">SAST · SCA · DAST</div>
          </div>
        </div>

        <UploadPanel onUpload={handleUpload} busy={busy} />

        <div className="scan-list-title">
          <span>Scan history</span>
          <button className="icon-btn" onClick={loadScans} title="Refresh">↻</button>
        </div>
        <ScanList
          scans={scans}
          activeId={view === 'scan' ? activeId : null}
          onSelect={(id) => { setView('scan'); setActiveId(id) }}
          onDelete={handleDelete}
        />
        <button className="btn" onClick={() => setView('tools')}>Tools &amp; emulator manager</button>
        <a className="btn" href="/tools/dashboard">Installed software dashboard</a>

        <div className="engine-status">
          <div className="engine-title">Engine status</div>
          {health ? (
            <>
              <StatusRow label="SAST" on={health.engines.sast} />
              <StatusRow label="SCA" on={health.engines.sca} />
              <StatusRow label="DAST" on={health.engines.dast} />
              <StatusRow label="OSV lookup" on={health.engines.sca_online} />
              <StatusRow label="PKI analysis" on={health.engines.pki} />
              <StatusRow label="Medical" on={health.engines.medical} />
              <StatusRow label="Toolchain" on={health.engines.toolchain} />
              <StatusRow label="Tool manager" on={health.engines.tool_manager} />
              <div className="tool-line">
                {health.tools.map((t) => (
                  <span key={t.name} className={t.available ? 'tool on' : 'tool'} title={t.name}>
                    {t.name}
                  </span>
                ))}
              </div>
              <div className="tool-line">
                {(health.toolchain || []).map((t) => (
                  <span key={`advanced-${t.name}`} className={t.available ? 'tool on' : 'tool'} title={t.detail || t.name}>
                    {t.name}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <div className="muted">Connecting…</div>
          )}
        </div>
      </aside>

      <main className="main">
        {error && <div className="banner error" onClick={() => setError('')}>{error}</div>}
        {view === 'tools' ? (
          <ToolManager />
        ) : !activeId && !record ? (
          <Welcome />
        ) : running ? (
          <div className="progress-panel">
            <div className="spinner" />
            <h2>Scanning APK…</h2>
            <p className="muted">{record.stage || 'starting'}</p>
            <div className="progress"><div style={{ width: `${record.progress || 0}%` }} /></div>
            <p className="muted">{record.progress || 0}%</p>
          </div>
        ) : record ? (
          <ResultView record={record} />
        ) : null}
      </main>
      <MiniShell />
      <LiveJobTerminal />
    </div>
  )
}

function StatusRow({ label, on }) {
  return (
    <div className="status-row">
      <span className={`dot ${on ? 'on' : ''}`} />
      <span>{label}</span>
      <span className="status-value">{on ? 'on' : 'off'}</span>
    </div>
  )
}

function Welcome() {
  return (
    <div className="welcome">
      <div className="welcome-icon">◇</div>
      <h1>Upload an APK to begin</h1>
      <p>
        The platform unpacks the APK, inspects the manifest and DEX strings, matches vulnerable
        components, and — when a device is connected — runs dynamic checks. Reports are generated
        as self-contained HTML and JSON.
      </p>
      <div className="welcome-grid">
        <div><strong>Static analysis</strong><span>Permissions, exported components, debuggable flags, secrets, TLS bypasses, WebView and crypto issues.</span></div>
        <div><strong>Composition analysis</strong><span>Detect bundled libraries and match known vulnerabilities using an offline database and OSV.dev.</span></div>
        <div><strong>Dynamic analysis</strong><span>adb-driven install/launch/logcat checks, with optional Frida hooks and proxy capture.</span></div>
      </div>
      <p className="muted small">For authorized security testing only. Heuristic findings require manual verification.</p>
    </div>
  )
}
