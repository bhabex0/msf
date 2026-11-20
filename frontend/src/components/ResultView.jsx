import React, { useMemo, useState } from 'react'
import { api, href } from '../api.js'
import SequenceRail from './SequenceRail.jsx'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const TABS = [
  'Findings', 'Components', 'Advanced', 'PKI', 'Bluetooth', 'Chains', 'Medical', 'Toolchain', 'Lab',
  'Live', 'Policy', 'Dynamic', 'Tools', 'Metadata', 'Report',
]

export default function ResultView({ record }) {
  const [tab, setTab] = useState('Findings')
  const [severity, setSeverity] = useState('all')
  const [query, setQuery] = useState('')
  const [browserStatus, setBrowserStatus] = useState('')

  const allFindings = useMemo(
    () => [...(record.findings || []), ...(record.sca_findings || [])],
    [record],
  )
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return allFindings
      .filter((f) => severity === 'all' || f.severity === severity)
      .filter((f) => !q || `${f.title} ${f.description} ${f.id} ${f.component || ''}`.toLowerCase().includes(q))
      .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
  }, [allFindings, severity, query])

  const s = record.summary || {}
  const m = record.manifest || {}
  const id = record.scan_id

  return (
    <div className="result">
      <div className="result-head">
        <div>
          <div className="eyebrow">Scan report</div>
          <h1>{m.package || record.filename}</h1>
          <div className="result-sub">
            <span>{record.filename}</span>
            <span>v{m.version_name || '?'} ({m.version_code ?? '?'})</span>
            <span>target SDK {m.target_sdk ?? '?'}</span>
            <span className="mono">{record.sha256?.slice(0, 16)}…</span>
          </div>
        </div>
        <div className={`risk-badge ${(s.risk_label || '').toLowerCase()}`}>
          <div className="risk-score">{s.risk_score ?? 0}<small>/100</small></div>
          <div className="risk-label">{s.risk_label || 'Unknown'} risk</div>
        </div>
      </div>

      <SequenceRail record={record} />

      <div className="stats">
        {SEVERITIES.map((sev) => (
          <div key={sev} className={`stat ${sev}`}>
            <div className="stat-num">{s[sev] ?? 0}</div>
            <div className="stat-label">{sev}</div>
          </div>
        ))}
        <div className="stat total">
          <div className="stat-num">{s.total ?? allFindings.length}</div>
          <div className="stat-label">total</div>
        </div>
      </div>

      <div className="sec-head"><span className="idx">02</span> Report sections <span className="muted small">{TABS.length} views</span></div>
      <div className="tabs">
        {TABS.map((t) => (
          <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>{t}</button>
        ))}
      </div>

      <div className="tab-content">
        {tab === 'Findings' && (
          <>
            <div className="toolbar">
              <input
                placeholder="Search findings…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <div className="severity-filters">
                <button className={severity === 'all' ? 'active' : ''} onClick={() => severity !== 'all' && setSeverity('all')}>all</button>
                {SEVERITIES.map((sev) => (
                  <button key={sev} className={`${sev} ${severity === sev ? 'active' : ''}`} onClick={() => setSeverity(sev)}>
                    {sev} <em>{s[sev] ?? 0}</em>
                  </button>
                ))}
              </div>
            </div>
            <div className="findings">
              {filtered.length ? filtered.map((f, i) => <FindingCard key={`${f.id}-${i}`} f={f} />) : (
                <div className="empty-state">No findings match this filter.</div>
              )}
            </div>
          </>
        )}

        {tab === 'Components' && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Component</th><th>Version</th><th>Source</th><th>Evidence</th></tr></thead>
              <tbody>
                {(record.components || []).length ? record.components.map((c, i) => (
                  <tr key={i}>
                    <td><strong>{c.name}</strong></td>
                    <td>{c.version || <span className="muted">unknown</span>}</td>
                    <td>{c.source}</td>
                    <td className="mono small">{c.evidence}</td>
                  </tr>
                )) : <tr><td colSpan="4" className="empty-state">No known components detected.</td></tr>}
              </tbody>
            </table>
            {record.sca_meta?.online_lookup && (
              <p className="muted small">OSV.dev online lookup enabled · {record.sca_meta.online_results ?? 0} advisory matches.</p>
            )}
          </div>
        )}

        {tab === 'Advanced' && <AdvancedPanel record={record} />}
        {tab === 'PKI' && <PkiPanel record={record} />}
        {tab === 'Bluetooth' && <BluetoothPanel record={record} />}
        {tab === 'Chains' && <ChainsPanel record={record} />}
        {tab === 'Medical' && <MedicalPanel record={record} />}
        {tab === 'Toolchain' && <ToolchainPanel record={record} />}
        {tab === 'Lab' && <LabPanel record={record} />}
        {tab === 'Live' && (
          <GenericTable
            headers={['Check', 'Status', 'Detail']}
            rows={(record.live_checks || []).map((c) => [c.name, c.status, c.detail])}
            empty="Live checks are disabled."
          />
        )}
        {tab === 'Policy' && (
          <div className="meta-card">
            <h3>Release policy: {(record.policy?.status || 'not_evaluated').toUpperCase()}</h3>
            <GenericTable
              headers={['Severity', 'Allowed', 'Found']}
              rows={Object.entries(record.policy?.actual || {}).map(([k, v]) => [k, record.policy?.thresholds?.[k], v])}
            />
            <pre>{JSON.stringify(record.policy?.thresholds || {}, null, 2)}</pre>
            {(record.policy?.violations || []).map((v, i) => (
              <div key={i} className="remediation"><strong>{v.severity}:</strong> {v.message}</div>
            ))}
          </div>
        )}

        {tab === 'Dynamic' && (
          <div>
            <div className="banner info">
              DAST status: <strong>{record.dast_status}</strong>
              {record.dast_info?.device_model ? ` · ${record.dast_info.device_model} · Android ${record.dast_info.android_version}` : ''}
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
                <tbody>
                  {(record.dast_checks || []).map((c, i) => (
                    <tr key={i}>
                      <td>{c.name}</td>
                      <td><span className={`pill ${c.status}`}>{c.status}</span></td>
                      <td>{c.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {record.dast_info?.logcat_excerpt && (
              <details className="log-details">
                <summary>Logcat excerpt</summary>
                <pre>{record.dast_info.logcat_excerpt}</pre>
              </details>
            )}
          </div>
        )}

        {tab === 'Tools' && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Tool</th><th>Available</th><th>Executed</th><th>Detail</th></tr></thead>
              <tbody>
                {(record.tools || []).map((t, i) => (
                  <tr key={i}>
                    <td><strong>{t.name}</strong></td>
                    <td>{t.available ? 'yes' : 'no'}</td>
                    <td>{t.ran ? 'yes' : 'no'}</td>
                    <td>{t.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'Metadata' && (
          <div className="metadata-grid">
            <div className="meta-card">
              <h3>Manifest</h3>
              <KeyValue label="Package" value={m.package} />
              <KeyValue label="Version" value={`${m.version_name || '?'} (${m.version_code ?? '?'})`} />
              <KeyValue label="Min SDK" value={m.min_sdk} />
              <KeyValue label="Target SDK" value={m.target_sdk} />
              <KeyValue label="Debuggable" value={String(m.debuggable)} />
              <KeyValue label="Allow backup" value={String(m.allow_backup)} />
              <KeyValue label="Cleartext" value={String(m.uses_cleartext_traffic)} />
              <KeyValue label="SHA-256" value={record.sha256} mono />
              <h4>Permissions ({(m.permissions || []).length})</h4>
              <div className="chips">
                {(m.permissions || []).map((p, i) => <span className="chip" key={i}>{p}</span>)}
              </div>
            </div>
            <div className="meta-card">
              <h3>Signing certificate</h3>
              <KeyValue label="v1 signature" value={String(record.certificate?.v1_signature)} />
              <KeyValue label="v2/v3 signature" value={String(record.certificate?.v2_or_v3_signature)} />
              {(record.certificate?.signers || []).map((signer, i) => (
                <div key={i} className="signer">
                  <KeyValue label="Subject" value={signer.subject} />
                  <KeyValue label="Issuer" value={signer.issuer} />
                  <KeyValue label="Serial" value={signer.serial_hex} mono />
                  <KeyValue label="Valid until" value={signer.valid_until} />
                </div>
              ))}
              <h4>APK contents ({(record.apk_files || []).length})</h4>
              <div className="file-list">
                {(record.apk_files || []).slice(0, 60).map((f, i) => <div key={i} className="mono">{f}</div>)}
              </div>
            </div>
          </div>
        )}

        {tab === 'Report' && (
          <div className="report-panel">
            <h3>Export report</h3>
            <p className="muted">The HTML report is self-contained and can be shared or printed to PDF.</p>
            <div className="report-actions">
              <a className="btn primary" href={href(`/api/scans/${id}/report.html`)} target="_blank" rel="noreferrer">Open HTML report</a>
              <a className="btn" href={href(`/api/scans/${id}/report.html`)} download={`report-${id}.html`}>Download HTML</a>
              <a className="btn" href={href(`/api/scans/${id}/report.json`)} download={`report-${id}.json`}>Download JSON</a>
              <a className="btn" href={href(`/api/scans/${id}/export/sbom.json`)} download={`sbom-${id}.cdx.json`}>CycloneDX SBOM</a>
              <a className="btn" href={href(`/api/scans/${id}/export/sarif.json`)} download={`report-${id}.sarif`}>SARIF</a>
              <button
                className="btn"
                onClick={async () => {
                  try {
                    const res = await api('/api/lab/open-mobsf', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ scan_id: id }),
                    })
                    setBrowserStatus(res.detail || `${res.status}${res.url ? ` — ${res.url}` : ''}`)
                  } catch (err) {
                    setBrowserStatus(err.message)
                  }
                }}
              >Open MobSF in Chromium</button>
            </div>
            {browserStatus && <p className="muted small">{browserStatus}</p>}
            <pre className="report-json">{JSON.stringify({
              scan_id: id,
              package: m.package,
              summary: s,
              finding_count: allFindings.length,
            }, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  )
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false)
  const evidence = f.evidence || ''
  return (
    <article className={`finding ${f.severity}`}>
      <div className="finding-top" onClick={() => setOpen(!open)}>
        <span className={`sev ${f.severity}`}>{f.severity}</span>
        <div className="finding-title">
          <strong>{f.title}</strong>
          <div className="finding-meta">
            {f.category} · {f.id}
            {f.cwe ? ` · ${f.cwe}` : ''}
            {f.owasp_masvs ? ` · ${f.owasp_masvs}` : ''}
            {f.component ? ` · ${f.component}` : ''}
          </div>
        </div>
        <span className="chevron">{open ? '▾' : '▸'}</span>
      </div>
      {open && (
        <div className="finding-body">
          <p>{f.description}</p>
          {evidence && <pre>{evidence}</pre>}
          <div className="remediation"><strong>Remediation</strong> {f.remediation}</div>
          {!!(f.references || []).length && (
            <div className="references">
              {f.references.map((r, i) => (
                <a key={i} href={r} target="_blank" rel="noreferrer">{r}</a>
              ))}
            </div>
          )}
        </div>
      )}
    </article>
  )
}

function KeyValue({ label, value, mono }) {
  return (
    <div className="kv-row">
      <span>{label}</span>
      <span className={mono ? 'mono wrap' : 'wrap'}>{value ?? '—'}</span>
    </div>
  )
}

function GenericTable({ headers, rows, empty = 'No data available.' }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{headers.map((h) => <th key={h}>{h}</th>)}</tr></thead>
        <tbody>
          {rows.length ? rows.map((row, i) => (
            <tr key={i}>{row.map((cell, j) => <td key={j}>{String(cell ?? '—')}</td>)}</tr>
          )) : <tr><td colSpan={headers.length} className="empty-state">{empty}</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

function AdvancedPanel({ record }) {
  const a = record.advanced || {}
  const nsc = a.network_config_detail || {}
  const apkid = a.apkid || {}
  return (
    <div className="metadata-grid">
      <div className="meta-card">
        <h3>Deep links / App Links</h3>
        <GenericTable
          headers={['Activity', 'Scheme', 'Host', 'Browsable', 'autoVerify']}
          rows={(a.deep_links || []).map((x) => [x.activity, x.scheme, x.host, x.browsable, x.auto_verified])}
          empty="No deep links declared."
        />
      </div>
      <div className="meta-card">
        <h3>Network security config</h3>
        <GenericTable headers={['Property', 'Value']} rows={[
          ['Resources', (nsc.resources || []).join(', ') || 'none'],
          ['User CA trusted', nsc.user_ca_trusted],
          ['Debug user CA', nsc.debug_user_ca_trusted],
          ['Cleartext', nsc.cleartext_enabled],
          ['Pin sets', (nsc.pin_sets || []).length],
          ['Expired pins', (nsc.expired_pins || []).length],
        ]} />
      </div>
      <div className="meta-card">
        <h3>Trackers / SDKs</h3>
        <GenericTable
          headers={['Category', 'Name', 'Evidence']}
          rows={(a.trackers || []).map((t) => [t.category, t.name, t.evidence])}
          empty="No known trackers."
        />
      </div>
      <div className="meta-card">
        <h3>Packer / anti-analysis</h3>
        <pre>{JSON.stringify(apkid, null, 2)}</pre>
      </div>
      <div className="meta-card">
        <h3>Native library hardening</h3>
        <GenericTable
          headers={['Library', 'PIE', 'NX', 'RELRO', 'Canary', 'Stripped']}
          rows={(a.elf_hardening || []).map((l) => [l.name, l.pie, l.nx_stack, l.full_relro, l.canary, l.stripped])}
          empty="No native libraries."
        />
      </div>
      <div className="meta-card">
        <h3>Certificate forensics</h3>
        <GenericTable
          headers={['Subject', 'Algorithm', 'Key size', 'Self-signed', 'Expired']}
          rows={((a.certificate_analysis || {}).signers || []).map((s) => [s.subject, s.signature_algorithm, s.key_size, s.self_signed, s.expired])}
        />
        <h4>Entropy candidates</h4>
        <pre>{JSON.stringify(a.entropy_secrets || [], null, 2)}</pre>
      </div>
    </div>
  )
}

function PkiPanel({ record }) {
  const p = record.pki || {}
  const raw = record.certificate || {}
  const s = p.summary || {}
  const t = p.trust || {}
  const [message, setMessage] = useState('')
  const [lab, setLab] = useState(p.lab || {})

  const signers = p.signers || raw.signers || []
  const summaryRows = [
    ['Status', p.status],
    ['Signers', s.signer_count],
    ['v1 signature', String(s.v1_signature)],
    ['v2/v3 signature', String(s.v2_or_v3_signature)],
    ['v1 only', String(s.v1_only)],
    ['Flags', JSON.stringify(s.flags || {})],
    ['PKI findings', s.finding_count],
  ]
  const certRows = signers.map((x) => [
    x.subject, x.issuer, x.signature_algorithm,
    `${x.public_key_algorithm || 'unknown'}/${x.key_size ?? '?'}`,
    x.sha256_fingerprint, (x.flags || []).join(', ') || 'none',
  ])
  const trustRows = [
    ['Resource', t.resource],
    ['Cleartext permitted', String(t.cleartext_traffic_permitted)],
    ['Pinning configured', String(t.pinning_configured)],
    ['User CA trusted', String(t.user_ca_trusted)],
    ['Domains', JSON.stringify(t.domains || [])],
  ]
  const ca = lab.ca || {}
  const keystore = lab.keystore || {}
  const device = lab.device_installation || {}
  const tools = lab.tools || {}
  const labRows = [
    ['Lab enabled', String(lab.enabled)],
    ['Lab directory', lab.directory],
    ['CA present', String(ca.exists)],
    ['CA subject', ca.details?.subject],
    ['CA SHA-256', ca.details?.sha256_fingerprint],
    ['Proxy CA configured', String(ca.proxy_ca_configured)],
    ['Keystore present', String(keystore.exists)],
    ['Device install by platform', String(device.performed_by_platform)],
    ['keytool', tools.keytool?.path || 'not found'],
    ['openssl', tools.openssl?.path || 'not found'],
    ['apksigner', tools.apksigner?.path || 'not found'],
  ]

  async function run(action) {
    setMessage('Working…')
    try {
      const headers = { 'Content-Type': 'application/json' }
      let result
      if (action === 'status') {
        result = await api('/api/pki/status')
      } else if (action === 'ca-generate') {
        result = await api('/api/pki/ca/generate', { method: 'POST', headers, body: JSON.stringify({ confirm: true }) })
      } else if (action === 'keystore-generate') {
        result = await api('/api/pki/keystore/generate', { method: 'POST', headers, body: JSON.stringify({ confirm: true }) })
      } else if (action === 'ca-import') {
        const pem = document.getElementById('pki-pem')?.value?.trim()
        if (!pem) throw new Error('Paste a PEM certificate first.')
        result = await api('/api/pki/ca/import', { method: 'POST', headers, body: JSON.stringify({ pem_text: pem, confirm: true }) })
      }
      setMessage(result?.detail || `PKI ${action}: ${result?.status}`)
      setLab(await api('/api/pki/status'))
    } catch (e) {
      setMessage(e.message)
    }
  }

  return (
    <div className="metadata-grid">
      <div className="meta-card">
        <h3>Signing summary</h3>
        <GenericTable headers={['Property', 'Value']} rows={summaryRows} />
        <p className="muted small">{p.notice}</p>
        <p className="muted small"><strong>Not a malware/threat detection tool.</strong> PKI observations are informational evidence only and never count as threat findings or release-gate failures.</p>
      </div>
      <div className="meta-card">
        <h3>Certificate chain</h3>
        <GenericTable
          headers={['Subject', 'Issuer', 'Algorithm', 'Key', 'SHA-256 fingerprint', 'Flags']}
          rows={certRows}
          empty="No parsed signing certificate."
        />
      </div>
      <div className="meta-card">
        <h3>TLS trust configuration</h3>
        <GenericTable headers={['Property', 'Value']} rows={trustRows} />
      </div>
      <div className="meta-card">
        <h3>Local lab material</h3>
        <GenericTable headers={['Property', 'Value']} rows={labRows} />
        <div className="toolbar">
          <button onClick={() => run('status')}>Refresh status</button>
          <button className="primary" onClick={() => run('ca-generate')}>Generate local CA</button>
          <button className="primary" onClick={() => run('keystore-generate')}>Generate keystore</button>
        </div>
        <textarea id="pki-pem" rows="3" placeholder="Paste a PEM certificate to import (lab use only)" />
        <button onClick={() => run('ca-import')}>Import PEM certificate</button>
        {message && <p className="muted small">{message}</p>}
        <p className="muted small">Local files only. No CA is installed on a device; invasive operations remain separately gated.</p>
      </div>
    </div>
  )
}

function BluetoothPanel({ record }) {
  const b = record.bluetooth || {}
  const s = b.summary || {}
  const l = b.lab || {}
  const rows = [
    ['Status', b.status],
    ['Permissions', (s.permissions || []).join(', ') || 'none observed'],
    ['BLE APIs', (s.ble_tokens || []).join(', ') || 'none observed'],
    ['Classic APIs', (s.classic_tokens || []).join(', ') || 'none observed'],
    ['Pairing APIs', (s.pairing_tokens || []).join(', ') || 'none observed'],
    ['UUID-like values', (s.uuids || []).join(', ') || 'none observed'],
    ['Bluetooth findings', s.finding_count],
  ]
  const labRows = [
    ['Lab enabled', String(l.enabled)],
    ['Read only', String(l.read_only)],
    ['Radio scan', String(l.device_scanning)],
    ['Pairing / bonding', String(l.pairing_or_bonding)],
    ...Object.entries(l.tools || {}).map(([k, v]) => [
      k, v === null ? 'gated (APKPT_BLUETOOTH_LAB=0)' : v ? 'available' : 'not found',
    ]),
  ]
  return (
    <div className="metadata-grid">
      <div className="meta-card">
        <h3>Bluetooth / BLE evidence</h3>
        <GenericTable headers={['Property', 'Value']} rows={rows} />
        <p className="muted small">{b.notice}</p>
        <p className="muted small"><strong>Not a malware/threat detection tool.</strong> Bluetooth observations are informational evidence only and never count as threat findings or release-gate failures.</p>
      </div>
      <div className="meta-card">
        <h3>Local tooling (read-only)</h3>
        <GenericTable headers={['Property', 'Value']} rows={labRows} />
        <p className="muted small">{l.detail}</p>
      </div>
    </div>
  )
}

function ChainsPanel({ record }) {
  const c = record.compliance || {}
  const coverage = [
    ...Object.entries(c.masvs_v2_categories || {}).map(([k, v]) => [`MASVS-${k}`, v]),
    ...Object.entries(c.owasp_mobile_top10 || {}).filter(([, v]) => v),
  ]
  return (
    <div className="metadata-grid">
      <div className="meta-card">
        <h3>Attack chains</h3>
        <GenericTable
          headers={['Chain', 'Severity', 'Preconditions']}
          rows={(record.attack_chains || []).map((x) => [x.name, x.severity, (x.requires || []).join(', ')])}
          empty="No attack chains identified."
        />
      </div>
      <div className="meta-card">
        <h3>Verification playbook</h3>
        <ol>{(record.playbook || []).map((p, i) => <li key={i}>{p}</li>)}</ol>
      </div>
      <div className="meta-card">
        <h3>Compliance coverage</h3>
        <GenericTable headers={['Category', 'Findings']} rows={coverage} />
      </div>
    </div>
  )
}

function MedicalPanel({ record }) {
  const m = record.medical || {}
  const standards = m.standards || {}
  const rows = [
    ['Status', m.status], ['Domain', m.domain],
    ['PHI indicators', m.phi_present ? 'present' : 'not detected'],
    ['Direct identifiers', (m.direct_identifiers || []).join(', ') || 'none'],
    ['Risk level', m.risk_level],
    ['Framework gaps', standards.gap_count ?? 0],
    ['Review items', standards.review_count ?? 0],
  ]
  return (
    <div className="metadata-grid">
      <div className="meta-card">
        <h3>Medical / PHI overview</h3>
        <GenericTable headers={['Property', 'Value']} rows={rows} />
        <p className="muted small">{m.disclaimer || 'Evidence mapping only; not a certification.'}</p>
      </div>
      <div className="meta-card">
        <h3>Detected indicators (masked)</h3>
        <GenericTable
          headers={['Indicator', 'Category', 'Count', 'Evidence']}
          rows={(m.phi_indicators || []).map((p) => [p.label, p.category, p.count_hint, p.evidence])}
          empty="No medical indicators detected."
        />
      </div>
      <div className="meta-card">
        <h3>Health-related permissions</h3>
        <GenericTable
          headers={['Permission', 'Severity', 'Reason']}
          rows={(m.medical_permissions || []).map((p) => [p.permission, p.severity, p.reason])}
          empty="No health-related permissions detected."
        />
      </div>
      <div className="meta-card">
        <h3>Standards and control evidence</h3>
        <GenericTable
          headers={['Framework control', 'Control ID', 'Status', 'Mapped findings']}
          rows={(standards.controls || []).map((c) => [c.title, c.control, c.status, (c.finding_ids || []).join(', ') || 'review'])}
          empty="No mapped controls."
        />
      </div>
    </div>
  )
}

function ToolchainPanel({ record }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Tool</th><th>Category</th><th>Available</th><th>Executed</th><th>Invasive</th><th>Detail</th></tr></thead>
        <tbody>
          {(record.toolchain || []).length ? record.toolchain.map((t, i) => (
            <tr key={i}>
              <td><strong>{t.name}</strong></td><td>{t.category}</td>
              <td>{t.available ? 'yes' : 'no'}</td><td>{t.ran ? 'yes' : 'no'}</td>
              <td>{t.invasive ? 'yes' : 'no'}</td><td>{t.detail}</td>
            </tr>
          )) : <tr><td colSpan="6" className="empty-state">No toolchain data.</td></tr>}
        </tbody>
      </table>
      <p className="muted small">Third-party hooks execute only when explicitly enabled and installed. Missing prerequisites are recorded as skips.</p>
    </div>
  )
}

function LabPanel({ record }) {
  const [emulatorMessage, setEmulatorMessage] = useState('')
  const lab = record.emulator || {}
  const emu = lab.emulator || {}
  const proxy = lab.proxy || {}
  const patching = lab.patching || {}
  const dast = record.dast_info || {}
  const dastLab = dast.lab || {}
  const rows = [
    ['Authorization', lab.authorization],
    ['Proxy', proxy.configured ? `${proxy.type} @ ${proxy.endpoint}` : 'not configured'],
    ['ADB available', emu.adb_available],
    ['Devices', (emu.devices || []).join(', ') || 'none'],
    ['Emulator available', emu.emulator_available],
    ['CA certificate', lab.ca_installation?.path || 'not configured'],
    ['Invasive allowed', emu.invasive_allowed],
  ]
  const emulatorRows = [
    ['Selected adb serial', dast.selected_serial || 'none'],
    ['Emulator devices', (dastLab.emulator_devices || []).join(', ') || 'none'],
    ['AVD', dastLab.avd || 'default'],
    ['AVD created', String(dastLab.avd_created)],
    ['Launch gated', String(dastLab.launch_gated)],
    ['Plan steps', (dastLab.dast_plan || []).length],
  ]
  async function emulatorAction(action) {
    try {
      const headers = { 'Content-Type': 'application/json' }
      const result = action === 'refresh'
        ? await api('/api/lab/emulator')
        : await api(`/api/lab/emulator/${action}`, {
            method: 'POST', headers, body: JSON.stringify({ confirm: true }),
          })
      setEmulatorMessage(result.detail || `Emulator ${action}: ${result.status}`)
    } catch (error) {
      setEmulatorMessage(error.message)
    }
  }
  return (
    <div className="metadata-grid">
      <div className="meta-card">
        <h3>Interception lab</h3>
        <GenericTable headers={['Property', 'Value']} rows={rows} />
      </div>
      <div className="meta-card">
        <h3>Emulator / DAST readiness</h3>
        <GenericTable headers={['Property', 'Value']} rows={emulatorRows} />
        <div className="toolbar">
          <button onClick={() => emulatorAction('refresh')}>Refresh status</button>
          <button className="primary" onClick={() => emulatorAction('launch')}>Launch local AVD</button>
          <button onClick={() => emulatorAction('stop')}>Stop local AVD</button>
        </div>
        {emulatorMessage && <p className="muted small">{emulatorMessage}</p>}
        <p className="muted small">Launch/stop require APKPT_EMULATOR_AUTO=1 and an explicit confirmed action. No emulator is ever launched automatically.</p>
      </div>
      <div className="meta-card">
        <h3>Emulator DAST plan</h3>
        <GenericTable
          headers={['Step', 'Status', 'Command', 'Detail']}
          rows={(dastLab.dast_plan || []).map((s) => [s.name, s.status, s.command, s.detail])}
          empty="No emulator plan available for this scan."
        />
      </div>
      <div className="meta-card">
        <h3>Generated commands</h3>
        <GenericTable
          headers={['Step', 'Command']}
          rows={(lab.commands || []).map((c) => [c.name, c.command])}
          empty="No lab commands generated."
        />
      </div>
      <div className="meta-card">
        <h3>Network security config notes</h3>
        <ul>{(lab.network_security_notes || []).map((n, i) => <li key={i}>{n}</li>)}</ul>
      </div>
      <div className="meta-card">
        <h3>Patch / instrumentation workflows</h3>
        <GenericTable
          headers={['Workflow', 'Status', 'Available', 'Command']}
          rows={(patching.steps || []).map((s) => [s.name, s.status, s.available ? 'yes' : 'no', s.command])}
          empty="No workflows."
        />
        <p className="muted small">Invasive workflows require explicit opt-in and authentication. They are not silently executed during a scan.</p>
      </div>
    </div>
  )
}
