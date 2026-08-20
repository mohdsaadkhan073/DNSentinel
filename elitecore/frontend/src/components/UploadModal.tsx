import { useRef, useState } from "react";
import { uploadPcap } from "../services/api";
import type { PassiveUploadResult } from "../types/security";
import { CloseIcon, UploadCloudIcon, FileCheckIcon } from "./icons";

export default function UploadModal({ onClose }: { onClose: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [phase, setPhase] = useState<"idle" | "uploading" | "complete" | "error">("idle");
  const [result, setResult] = useState<PassiveUploadResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const pickFile = (f: File | undefined | null) => {
    if (f) setFile(f);
  };

  const analyze = async () => {
    if (!file) return;
    setPhase("uploading");
    setError(null);
    try {
      const res = await uploadPcap(file);
      setResult(res);
      setPhase("complete");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
      setPhase("error");
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal__close" onClick={onClose} aria-label="Close">
          <CloseIcon />
        </button>
        <h3>PCAP / Zeek Upload</h3>
        <div className="modal__label">Drop a capture file for instant forensic analysis</div>

        {phase !== "complete" && (
          <div
            className={`upload-dropzone ${dragOver ? "is-dragover" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              pickFile(e.dataTransfer.files?.[0]);
            }}
            onClick={() => inputRef.current?.click()}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".pcap,.pcapng,.tsv"
              hidden
              onChange={(e) => pickFile(e.target.files?.[0])}
            />
            <UploadCloudIcon className="upload-dropzone__icon" />
            {file ? (
              <div>
                <div className="upload-dropzone__filename">{file.name}</div>
                <div className="upload-dropzone__size">{(file.size / (1024 * 1024)).toFixed(2)} MB</div>
              </div>
            ) : (
              <div className="upload-dropzone__hint">Drag file here or click to browse</div>
            )}
          </div>
        )}

        {phase !== "complete" && (
          <button className="btn btn--primary" disabled={!file || phase === "uploading"} onClick={analyze}>
            {phase === "uploading" ? "Analyzing..." : "Analyze File"}
          </button>
        )}

        {phase === "uploading" && (
          <div className="upload-progress">
            <div className="upload-progress__bar" />
          </div>
        )}

        {phase === "error" && <div className="upload-error">{error}</div>}

        {phase === "complete" && result && (
          <div className="forensic-summary">
            <div className="forensic-summary__banner">
              <FileCheckIcon />
              Analysis complete — {result.filename}
            </div>
            <div className="forensic-grid">
              <div className="forensic-stat">
                <div className="forensic-stat__label">Packets</div>
                <div className="forensic-stat__value">{result.total_packets.toLocaleString()}</div>
              </div>
              <div className="forensic-stat">
                <div className="forensic-stat__label">DNS Queries</div>
                <div className="forensic-stat__value">{result.dns_queries.toLocaleString()}</div>
              </div>
              <div className="forensic-stat">
                <div className="forensic-stat__label">Malicious Domains</div>
                <div className="forensic-stat__value" style={{ color: "var(--red)" }}>{result.malicious_domains}</div>
              </div>
              <div className="forensic-stat">
                <div className="forensic-stat__label">Suspicious Domains</div>
                <div className="forensic-stat__value" style={{ color: "var(--amber)" }}>{result.suspicious_domains}</div>
              </div>
              <div className="forensic-stat">
                <div className="forensic-stat__label">DGA Detected</div>
                <div className="forensic-stat__value">{result.dga_detected}</div>
              </div>
              <div className="forensic-stat">
                <div className="forensic-stat__label">Tunneling</div>
                <div className="forensic-stat__value">{result.tunneling_detected}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
