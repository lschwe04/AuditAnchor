import React, { useState } from 'react';
import { ShieldCheck, AlertTriangle, FileArchive, Trash2 } from 'lucide-react';

export default function ComplianceHub() {
  const [auditStatus, setAuditStatus] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const verifyChain = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/audit/verify', {
        headers: {
          'X-Tenant-ID': 'default-tenant',
          'Authorization': 'Bearer ' + (localStorage.getItem('token') || '')
        }
      });
      const data = await res.json();
      setAuditStatus(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto bg-slate-900 text-slate-100 min-h-screen">
      <header className="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ShieldCheck className="text-emerald-400" /> AuditAnchor Compliance Hub
        </h1>
        <button
          onClick={verifyChain}
          disabled={loading}
          className="bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded font-medium text-sm transition"
        >
          {loading ? 'Prüfe...' : 'Kette verifizieren'}
        </button>
      </header>

      {auditStatus && (
        <div className={`p-4 rounded-lg mb-6 border ${auditStatus.valid ? 'bg-emerald-950/45 border-emerald-800 text-emerald-300' : 'bg-red-950/45 border-red-800 text-red-300'}`}>
          <div className="flex items-center gap-2 font-semibold">
            {auditStatus.valid ? <ShieldCheck /> : <AlertTriangle />}
            <span>Status: {auditStatus.valid ? 'Integrität intakt (WORM/Valid Hash Chain)' : 'INTEGRITY BROKEN!'}</span>
          </div>
          <p className="text-sm mt-1">Geprüfte Events: {auditStatus.total_checked}</p>
          {auditStatus.reason && <p className="text-xs mt-1 text-red-400 font-mono">{auditStatus.reason}</p>}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <h2 className="font-semibold flex items-center gap-2 mb-2"><FileArchive size={18} /> GoBD Export</h2>
          <p className="text-sm text-slate-400 mb-4">Exportiere das vollständige Beweismittel- und Audit-ZIP-Paket.</p>
          <a
            href="/api/v1/evidence/export"
            className="inline-block bg-slate-700 hover:bg-slate-600 text-white text-sm px-4 py-2 rounded"
          >
            ZIP herunterladen
          </a>
        </div>

        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <h2 className="font-semibold flex items-center gap-2 mb-2 text-amber-400"><Trash2 size={18} /> DSGVO Tombstone</h2>
          <p className="text-sm text-slate-400 mb-4">Cryptographic Erasure von Blobs via Tombstone-Marker.</p>
          <span className="text-xs text-slate-500">API Endpoint: POST /api/v1/evidence/tombstone</span>
        </div>
      </div>
    </div>
  );
}
