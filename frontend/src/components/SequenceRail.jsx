import React from 'react'

const count = (value) => Array.isArray(value) ? value.length : Object.keys(value || {}).length

const IDLE = [
  ['01', 'Intake', 'APK queued'],
  ['02', 'Static', 'manifest + dex'],
  ['03', 'SCA', 'dependency graph'],
  ['04', 'Evidence', 'pki · ble'],
  ['05', 'Lab', 'tools + DAST'],
  ['06', 'Report', 'export + gates'],
]

/** Ordered work sequence shown on the welcome screen and on scan reports. */
export default function SequenceRail({ record }) {
  let steps = IDLE.map(([num, label, value]) => ({ num, label, value, state: '' }))
  let caption = ''

  if (record) {
    caption = record.status || ''
    steps = [
      {
        num: '01', label: 'Intake',
        value: record.sha256 ? String(record.sha256).slice(0, 10) : 'no hash',
        state: record.sha256 ? 'done' : 'active',
      },
      {
        num: '02', label: 'Static',
        value: `${count(record.findings)} findings`,
        state: count(record.manifest) > 0 ? 'done' : 'skip',
      },
      {
        num: '03', label: 'SCA',
        value: `${count(record.sca_findings)} advisories`,
        state: count(record.sca_findings) > 0 || count(record.sca_meta) > 0 ? 'done' : 'skip',
      },
      {
        num: '04', label: 'Evidence',
        value: `pki ${count(record.pki)} · ble ${count(record.bluetooth)}`,
        state: count(record.pki) > 0 || count(record.bluetooth) > 0 ? 'done' : 'skip',
      },
      {
        num: '05', label: 'Lab',
        value: `${count(record.tools)} tools · ${count(record.toolchain)} hooks`,
        state: count(record.tools) > 0 || count(record.toolchain) > 0 ? 'done' : 'skip',
      },
      {
        num: '06', label: 'Report',
        value: `${count(record.exports)} exports`,
        state: record.status === 'completed' && count(record.exports) > 0 ? 'done' : 'skip',
      },
    ]
  }

  return (
    <>
      <div className="sec-head">
        <span className="idx">01</span> {record ? 'Analysis sequence' : 'Operation sequence'}
        {caption && <span className="muted small">{caption}</span>}
      </div>
      <div className="seq-rail">
        {steps.map((step) => (
          <div className={`seq-step ${step.state}`} key={step.num}>
            <span className="num">{step.num}</span>
            <span className="lbl">{step.label}</span>
            <span className="val">{step.value}</span>
          </div>
        ))}
      </div>
    </>
  )
}
