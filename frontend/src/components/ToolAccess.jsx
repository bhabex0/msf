import React, { useMemo, useState } from 'react'

const ACTION_ICONS = {
  install: ['↓', 'Install'],
  update: ['↻', 'Update'],
  pull: ['⟲', 'Pull'],
  verify: ['✓', 'Verify'],
}

function ToolCard({ tool, onStart, onWeb, onMessage }) {
  const actions = []
  const reason = tool.install_block_reason || tool.install_note || 'Manual installation only.'
  const blocked = tool.installable === false
  if (blocked) {
    actions.push(
      <span className="tool-act manual" key="manual" title={reason}>
        <span aria-hidden="true">⚠</span>{tool.manual ? 'Manual' : 'Unavailable'}
      </span>,
    )
  }
  for (const action of ['install', 'update', 'pull', 'verify']) {
    if (blocked && action !== 'verify') continue
    if (!blocked && action === 'install' && tool.installed) continue
    if (action === 'pull' && tool.method !== 'git') continue
    const [icon, label] = ACTION_ICONS[action]
    actions.push(
      <button
        type="button"
        className={`tool-act ${action}`}
        key={action}
        title={`${label} ${tool.name}`}
        onClick={() => onStart(`/api/tools/${encodeURIComponent(tool.id)}/${action}`, `${tool.name} ${action}`)}
      >
        <span aria-hidden="true">{icon}</span>{label}
      </button>,
    )
  }
  if (blocked) {
    actions.push(
      <button
        type="button"
        className="tool-act"
        key="why"
        title="Why no auto-install button?"
        onClick={() => onMessage?.(reason, 'info')}
      >
        <span aria-hidden="true">ⓘ</span>Why
      </button>,
    )
  }
  if (tool.web_url) {
    actions.push(
      <a
        className="tool-act web"
        key="web-url"
        href={tool.web_url}
        target="_blank"
        rel="noreferrer"
        title={`Open ${tool.name} directly at ${tool.web_url}`}
      >
        <span aria-hidden="true">↗</span>Open URL
      </a>,
    )
  }
  if (tool.web_open) {
    actions.push(
      <button type="button" className="tool-act web" key="web" title={`Open configured web UI for ${tool.name}`} onClick={() => onWeb(tool.id)}>
        <span aria-hidden="true">↗</span>Web UI
      </button>,
    )
  }
  actions.push(
    <a className="tool-act" key="source" href={tool.source_url} target="_blank" rel="noreferrer" title={`Official source for ${tool.name}`}>
      <span aria-hidden="true">🔗</span>Source
    </a>,
  )

  return (
    <article className={`tool-card ${tool.invasive ? 'invasive' : ''}`}>
      <div className="tc-top">
        <span className="tc-icon" aria-hidden="true">{tool.icon || '•'}</span>
        <div className="tc-title">
          <strong>{tool.name}</strong>
          <small>{tool.id} · v{tool.version || '—'}</small>
        </div>
        <span className={`pill ${tool.installed ? 'completed' : 'skipped'}`}>{tool.installed ? 'installed' : 'missing'}</span>
      </div>
      <div className="tc-desc">{tool.description || ''}</div>
      <div className="tc-meta">
        <span className="chip">{tool.category}</span>
        {blocked && <span className="pill low">{tool.manual ? 'manual' : 'unavailable'}</span>}
        {tool.invasive && <span className="pill high">invasive</span>}
      </div>
      <div className="tc-actions">{actions}</div>
    </article>
  )
}

export default function ToolAccess({ tools = [], groups = [], onStart, onWeb, onMessage }) {
  const [query, setQuery] = useState('')
  const [activeGroup, setActiveGroup] = useState('all')

  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase()
    return tools.filter((tool) => {
      const inGroup = activeGroup === 'all' || tool.group === activeGroup
      const haystack = `${tool.name} ${tool.id} ${tool.category} ${tool.description} ${tool.group_title}`.toLowerCase()
      return inGroup && (!text || haystack.includes(text))
    })
  }, [activeGroup, query, tools])

  const visibleGroups = groups.filter((group) => activeGroup === 'all' || group.id === activeGroup)

  return (
    <div className="tool-access">
      <h3>Tool access <span className="muted small">{filtered.length} shown</span></h3>
      <div className="tool-controls">
        <input
          id="tool-search"
          type="search"
          placeholder="Find a tool…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="Find a tool"
          autoComplete="off"
        />
        {[{ id: 'all', icon: '▦', title: 'All', count: tools.length }, ...groups].map((group) => (
          <button
            type="button"
            className={`tool-filter ${activeGroup === group.id ? 'active' : ''}`}
            key={group.id}
            title={group.title}
            onClick={() => setActiveGroup(group.id)}
          >
            <span aria-hidden="true">{group.icon || '•'}</span> {group.title} <span className="muted">{group.count ?? ''}</span>
          </button>
        ))}
      </div>
      <div className="tool-groups">
        {visibleGroups.map((group) => {
          const items = filtered.filter((tool) => tool.group === group.id)
          if (!items.length) return null
          return (
            <section className="tool-group" key={group.id} data-group={group.id}>
              <div className="tg-head">
                <span className="tg-icon" aria-hidden="true">{group.icon || '•'}</span>
                <div className="tg-title">
                  <strong>{group.order}. {group.title}</strong>
                  <small>{group.hint || ''}</small>
                </div>
                <span className="pill info">{items.length}</span>
              </div>
              <div className="tool-cards">
                {items.map((tool) => <ToolCard key={tool.id} tool={tool} onStart={onStart} onWeb={onWeb} onMessage={onMessage} />)}
              </div>
            </section>
          )
        })}
        {!filtered.length && <div className="empty">No tools match this filter.</div>}
      </div>
    </div>
  )
}
