import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import { levelForStatus, logLevel } from '../logColors.js'

export default function MiniShell() {
  const [open, setOpen] = useState(false)
  const [pinned, setPinned] = useState(false)
  const [command, setCommand] = useState('')
  const [lines, setLines] = useState([
    { text: 'shell ready · type help for allowed commands', cls: 'dim' },
  ])

  const logRef = useRef(null)
  const shellRootRef = useRef(null)
  const inputRef = useRef(null)
  const hideRef = useRef(null)
  const jobRef = useRef(null)
  const lastLogRef = useRef(0)
  const pollRef = useRef(null)
  const historyRef = useRef([])
  const historyIndexRef = useRef(0)

  const push = useCallback((text, cls = 'auto') => {
    const incoming = String(text ?? '').split(/\r?\n/).map((line) => {
      let level = cls
      if (!cls || cls === 'auto') level = logLevel(line)
      else if (cls === 'err') level = 'critical'
      return { line, cls: level }
    })
    setLines((current) => [...current, ...incoming].slice(-300))
  }, [])

  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  const scheduleHide = useCallback(() => {
    if (hideRef.current) clearTimeout(hideRef.current)
    hideRef.current = null
    if (!open || pinned || jobRef.current) return
    hideRef.current = setTimeout(() => setOpen(false), 30000)
  }, [open, pinned])

  useEffect(() => {
    scheduleHide()
    return () => {
      if (hideRef.current) clearTimeout(hideRef.current)
      if (pollRef.current) clearTimeout(pollRef.current)
    }
  }, [scheduleHide])

  const toggle = useCallback((next) => {
    setOpen(next)
    if (next) setTimeout(() => inputRef.current?.focus(), 0)
  }, [])

  const pollJob = useCallback(async (jobId) => {
    if (jobRef.current !== jobId) return
    if (pollRef.current) clearTimeout(pollRef.current)
    pollRef.current = null
    try {
      const job = await api(`/api/tools/jobs/${encodeURIComponent(jobId)}`)
      const logs = job.logs || []
      if (logs.length > lastLogRef.current) {
        push(logs.slice(lastLogRef.current).join('\n'))
        lastLogRef.current = logs.length
      }
      if (['completed', 'failed', 'skipped'].includes(job.status)) {
        push(`[${job.status}] ${job.detail || ''}`.trim(), levelForStatus(job.status, job.action))
        jobRef.current = null
        scheduleHide()
        return
      }
    } catch (e) {
      push(`job poll error: ${e.message}`, 'err')
      jobRef.current = null
      scheduleHide()
      return
    }
    pollRef.current = setTimeout(() => pollJob(jobId), 1000)
  }, [push, scheduleHide])

  const run = useCallback(async () => {
    const text = command.trim()
    if (!text) return
    setCommand('')
    historyRef.current.push(text)
    historyIndexRef.current = historyRef.current.length
    push(`$ ${text}`, 'dim')
    scheduleHide()
    try {
      const result = await api('/api/tools/shell', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: text, confirm: true }),
      })
      if (result.clear) setLines([])
      if (result.output) push(result.output, result.level || logLevel(result.output))
      if (result.job_id) {
        jobRef.current = result.job_id
        lastLogRef.current = 0
        pollJob(result.job_id)
        window.dispatchEvent(new CustomEvent('apkpt:job', {
          detail: {
            job_id: result.job_id,
            tool_id: result.tool_id || text,
            action: result.action || '',
            status: result.status,
            detail: result.detail || '',
          },
        }))
      }
    } catch (e) {
      push(`error: ${e.message}`, 'err')
    }
    scheduleHide()
  }, [command, pollJob, push, scheduleHide])

  const clear = () => {
    setLines([])
    push('terminal cleared', 'dim')
  }

  const onKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      run()
    } else if (e.key === 'Escape') {
      e.preventDefault()
      setOpen(false)
    } else if (e.key === 'ArrowUp' && historyRef.current.length) {
      e.preventDefault()
      historyIndexRef.current = Math.max(0, historyIndexRef.current - 1)
      setCommand(historyRef.current[historyIndexRef.current] || '')
    } else if (e.key === 'ArrowDown' && historyRef.current.length) {
      e.preventDefault()
      historyIndexRef.current = Math.min(historyRef.current.length, historyIndexRef.current + 1)
      setCommand(historyRef.current[historyIndexRef.current] || '')
    }
    scheduleHide()
  }

  useEffect(() => {
    const onGlobalKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === '`') {
        e.preventDefault()
        toggle(!open)
      }
    }
    document.addEventListener('keydown', onGlobalKey)
    return () => document.removeEventListener('keydown', onGlobalKey)
  }, [open, toggle])

  // Clicking anywhere outside the shell hides it; the shell tab and panel
  // remain interactive. Pinning or a running job keeps it open.
  useEffect(() => {
    if (!open) return undefined
    const onOutside = (e) => {
      if (pinned || jobRef.current) return
      if (shellRootRef.current?.contains(e.target)) return
      setOpen(false)
    }
    document.addEventListener('pointerdown', onOutside)
    return () => document.removeEventListener('pointerdown', onOutside)
  }, [open, pinned])

  return (
    <div className="mini-shell" ref={shellRootRef}>
      {open && (
        <div className="shell-panel open" role="region" aria-label="Tool shell">
          <div className="shell-head">
            <span><strong>shell</strong> <span className="muted small">allowlisted · gated</span></span>
            <span>
              <button type="button" onClick={() => setPinned((value) => !value)} title="Keep open">
                {pinned ? 'unpin' : 'pin'}
              </button>
              <button type="button" onClick={clear} title="Clear terminal">clear</button>
              <button type="button" onClick={() => setOpen(false)} title="Hide shell">×</button>
            </span>
          </div>
          <pre className="shell-log" ref={logRef}>
            {lines.map((line, index) => (
              <div className={`shell-line op-line op-${line.cls}`} key={index}>{line.line || '\u00a0'}</div>
            ))}
          </pre>
          <div className="shell-input-row">
            <input
              ref={inputRef}
              className="shell-input"
              value={command}
              onChange={(e) => { setCommand(e.target.value); scheduleHide() }}
              onKeyDown={onKeyDown}
              onMouseMove={scheduleHide}
              placeholder="apktool install · install all · help"
              autoComplete="off"
              spellCheck="false"
              aria-label="Shell command"
            />
            <button type="button" className="btn compact" onClick={run}>Run</button>
          </div>
          <div className="shell-hint">
            help · status · jobs · sync · open mobsf · ↑/↓ history · click outside hides · click ›_ shell opens · Esc hides · auto-hides after 30s · drag corner to resize
            <br />green work/success · blue info · yellow low · orange high · red critical · authorized use only
          </div>
        </div>
      )}
      <button type="button" className="shell-tab" onClick={() => toggle(!open)} title="Toggle shell">
        ›_ shell
      </button>
    </div>
  )
}
