import React, { useState } from 'react'

export default function UploadPanel({ onUpload, busy }) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState(null)

  const pick = (f) => {
    if (f) setFile(f)
  }

  const submit = () => {
    if (!file || busy) return
    onUpload(file)
    setFile(null)
  }

  return (
    <div className="upload-panel">
      <div
        className={`dropzone ${dragging ? 'dragging' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragging(false)
          pick(e.dataTransfer.files?.[0])
        }}
      >
        <div className="drop-icon">↑</div>
        <div className="drop-text">Drop an APK here</div>
        <label className="browse">
          or browse
          <input
            type="file"
            accept=".apk"
            onChange={(e) => pick(e.target.files?.[0])}
          />
        </label>
      </div>
      {file && (
        <div className="selected-file">
          <span title={file.name}>{file.name}</span>
          <button onClick={submit} disabled={busy}>Scan</button>
        </div>
      )}
    </div>
  )
}
