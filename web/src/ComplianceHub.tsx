import React, { useState, useEffect } from 'react';
import { ShieldCheck, AlertTriangle, FileArchive, Trash2, Building2 } from 'lucide-react';

const MSP_TENANTS = [
  { id: 'tenant-alpha', name: 'Kunde Alpha GmbH' },
  { id: 'tenant-beta', name: 'Beta Logistics AG' },
  { id: 'tenant-gamma', name: 'Gamma Steuerberatung' },
];

export default function ComplianceHub() {
  const [selectedTenant, setSelectedTenant] = useState<string>(
    localStorage.getItem('selected_tenant') || 'tenant-alpha'
  );
  const [auditStatus, setAuditStatus] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    localStorage.setItem('selected_tenant', selectedTenant);
    setAuditStatus(null);
  }, [selectedTenant]);

  const verifyChain = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/audit/verify', {
        headers: {
          'X-Tenant-ID': selectedTenant,
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
      <header className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 border-b border-slate-800 pb-4 gap-4">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ShieldCheck className="text-emerald-400" /> AuditAnchor Compliance Hub
        </h1>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-800 border border-slate-700 px-3 py-1.5 rounded-lg">
            <Building2 size={16} className="text-slate-400" />
            <select
              value={selectedTenant}
              onChange={(e) => setSelectedTenant(e.target.value)}
              className="bg-transparent text-sm text-slate-100 focus:outline-none cursor-pointer"
            >
              {MSP_TENANTS.map((t) => (
                <option key={t.id} value={t.id} className="bg-slate-800 text-slate-100">
                  {t.name} ({t.id})
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={verifyChain}
            disabled={loading}
            className="bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded font-medium text-sm transition"
          >
            {loading ? 'Prüfe...' : 'Kette verifizieren'}
          </button>
        </div>
      </header>

      {auditStatus && (
        <div className={`p-4 rounded-lg mb-6 border ${auditStatus.valid ? 'bg-emerald-950/45 border-emerald-800 text-emerald-300' : 'bg-red-950/45 border-red-800 text-red-300'}`}>
          <div className="flex items-center gap-2 font-semibold">
            {auditStatus.valid ? <ShieldCheck /> : <AlertTriangle />}
            <span>Status ({selectedTenant}): {auditStatus.valid ? 'Integrität intakt (WORM/Valid Hash Chain)' : 'INTEGRITY BROKEN!'}</span>
          </div>
          <p className="text-sm mt-1">Geprüfte Events: {auditStatus.total_checked}</p>
          {auditStatus.reason && <p className="text-xs mt-1 text-red-400 font-mono">{auditStatus.reason}</p>}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <h2 className="font-semibold flex items-center gap-2 mb-2"><FileArchive size={18} /> GoBD Export ({selectedTenant})</h2>
          <p className="text-sm text-slate-400 mb-4">Exportiere das vollständige Beweismittel- und Audit-ZIP-Paket inkl. Verfahrens-Metadaten (meta.txt).</p>
          <a
            href={`/api/v1/evidence/export?tenant_id=${selectedTenant}`}
            className="inline-block bg-slate-700 hover:bg-slate-600 text-white text-sm px-4 py-2 rounded"
          >
            ZIP herunterladen
          </a>
        </div>

        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <h2 className="font-semibold flex items-center gap-2 mb-2 text-amber-400"><Trash2 size={18} /> DSGVO Tombstone</h2>
          <p className="text-sm text-slate-400 mb-4">Cryptographic Erasure von Blobs via Tombstone-Marker (Aktiver Tenant: {selectedTenant}).</p>
          <span className="text-xs text-slate-500">API Endpoint: POST /api/v1/evidence/tombstone (Header: X-Tenant-ID: {selectedTenant})</span>
        </div>
      </div>
    </div>
  );
}
