import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import { levelForStatus } from '../logColors.js'

const DONE = ['completed', 'failed', 'skipped']

export default function LiveJobTerminal() {
  const [job, setJob] = useState(null)
  const [lines, setLines] = useState([])
  const activeRef = useRef(null)
  const jobMetaRef = useRef(null)
  const pollRef = useRef(null)
  const hideRef = useRef(null)
  const logRef = useRef(null)

  const close = useCallback(() => {
    if (pollRef.current) clearTimeout(pollRef.current)
    if (hideRef.current) clearTimeout(hideRef.current)
    pollRef.current = null
    hideRef.current = null
    activeRef.current = null
    setJob(null)
    setLines([])
  }, [])

  const poll = useCallback(async (jobId) => {
    if (activeRef.current !== jobId) return
    try {
      const data = await api(`/api/tools/jobs/${encodeURIComponent(jobId)}`)
      if (activeRef.current !== jobId) return
      setJob((current) => (current ? { ...current, status: data.status, detail: data.detail } : current))
      const logs = data.logs || []
      setLines((current) => {
        if (logs.length <= current.length) return current
        return [...current, ...logs.slice(current.length).map((line) => ({ text: String(line), level: 'work' }))]
      })
      if (DONE.includes(data.status)) {
        setLines((current) => [
          ...current,
          { text: `[${data.status}] ${data.detail || ''}`.trim(), level: levelForStatus(data.status, data.action) },
        ])
        const meta = jobMetaRef.current || {}
        window.dispatchEvent(new CustomEvent('apkpt:job-done', {
          detail: {
            job_id: jobId,
            tool_id: meta.tool_id || 'tool job',
            action: meta.action || '',
            status: data.status,
            detail: data.detail || '',
          },
        }))
        hideRef.current = setTimeout(close, 3000)
        return
      }
    } catch (e) {
      if (activeRef.current !== jobId) return
      setLines((current) => [...current, { text: `poll error: ${e.message}`, level: 'critical' }])
      hideRef.current = setTimeout(close, 3000)
      return
    }
    pollRef.current = setTimeout(() => poll(jobId), 700)
  }, [close])

  useEffect(() => {
    const onStart = (event) => {
      const detail = event.detail || {}
      if (!detail.job_id) return
      if (pollRef.current) clearTimeout(pollRef.current)
      if (hideRef.current) clearTimeout(hideRef.current)
      activeRef.current = detail.job_id
      jobMetaRef.current = {
        tool_id: detail.tool_id || 'tool job',
        action: detail.action || '',
      }
      setJob({
        job_id: detail.job_id,
        tool_id: detail.tool_id || 'tool job',
        action: detail.action || '',
        status: detail.status || 'queued',
        detail: detail.detail || '',
      })
      setLines([])
      poll(detail.job_id)
    }
    window.addEventListener('apkpt:job', onStart)
    return () => {
      window.removeEventListener('apkpt:job', onStart)
      if (pollRef.current) clearTimeout(pollRef.current)
      if (hideRef.current) clearTimeout(hideRef.current)
    }
  }, [poll])

  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape' && job) close()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [close, job])

  if (!job) return null

  return (
    <div className="auto-term open" role="region" aria-label="Live tool job terminal" aria-live="polite">
      <div className="at-head">
        <span>
          <span className="at-dot" aria-hidden="true" />
          <strong>{job.tool_id}</strong> <span className="muted small">{job.action} · {job.status}</span>
        </span>
        <button type="button" onClick={close} title="Hide live terminal">×</button>
      </div>
      <pre className="at-log" ref={logRef}>
        {lines.length
          ? lines.map((line, index) => (
              <span className={`at-line op-${line.level}`} key={index}>{line.text}{'\n'}</span>
            ))
          : <span className="at-line op-dim">Waiting for job output…</span>}
      </pre>
      <div className="at-foot">For authorized security testing only · closes automatically when the job finishes</div>
    </div>
  )
}
