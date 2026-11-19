import React from 'react'

const STATUS_LABELS = {
  completed: 'done',
  running: 'scanning',
  queued: 'queued',
  failed: 'failed',
}

export default function ScanList({ scans, activeId, onSelect, onDelete }) {
  if (!scans.length) return <div className="empty-list">No scans yet</div>
  return (
    <div className="scan-list">
      {scans.map((s) => (
        <div
          key={s.scan_id}
          className={`scan-item ${activeId === s.scan_id ? 'active' : ''}`}
          onClick={() => onSelect(s.scan_id)}
        >
          <div className="scan-item-main">
            <div className="scan-name" title={s.filename}>{s.filename}</div>
            <div className="scan-meta">
              <span className={`pill ${s.status}`}>{STATUS_LABELS[s.status] || s.status}</span>
              {s.package && <span className="scan-package" title={s.package}>{s.package}</span>}
            </div>
          </div>
          <div className="scan-score" title={`${s.total_findings} findings`}>
            {s.status === 'completed' ? s.risk_score : '—'}
          </div>
          <button
            className="delete-btn"
            title="Delete scan"
            onClick={(e) => { e.stopPropagation(); onDelete(s.scan_id) }}
          >
            ×
          </button>
        </div>
      ))}
    </div>
  )
}
