import { useEffect, useRef, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, RefreshCw, MessageSquare, Download } from 'lucide-react';
import { scansApi, connectScanWS } from '../services/api';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScore } from '../components/RiskScore';
import { AiChat } from '../components/AiChat';

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const wsRef = useRef<WebSocket | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [showChat, setShowChat] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');

  const { data: scan, refetch: refetchScan } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scansApi.get(id!),
    refetchInterval: (data: any) =>
      data?.status === 'running' || data?.status === 'pending' ? 3000 : false,
  });

  const { data: vulns, refetch: refetchVulns } = useQuery({
    queryKey: ['vulnerabilities', id, severityFilter],
    queryFn: () => scansApi.vulnerabilities(id!, severityFilter || undefined),
    enabled: !!id,
  });

  const { data: report } = useQuery({
    queryKey: ['report', id],
    queryFn: () => scansApi.report(id!),
    enabled: scan?.status === 'completed',
    retry: false,
  });

  // WebSocket for live progress
  useEffect(() => {
    if (!id || scan?.status === 'completed' || scan?.status === 'failed') return;

    const cleanup = connectScanWS(
      id,
      (event) => {
        if (event.type === 'scan:progress') {
          const msg = (event.data as any)?.message;
          if (msg) setLogs((prev) => [...prev.slice(-99), msg]);
        }
        if (event.type === 'scan:completed' || event.type === 'scan:failed') {
          refetchScan();
          refetchVulns();
          queryClient.invalidateQueries({ queryKey: ['analytics'] });
        }
        if (event.type === 'scan:vuln_found') {
          const v = event.data as any;
          setLogs((prev) => [...prev.slice(-99), `🚨 Found: ${v.severity} - ${v.title}`]);
          refetchVulns();
        }
      },
      (status) => setWsStatus(status)
    );

    return cleanup;
  }, [id, scan?.status]);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    // Auto-scroll terminal
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const downloadPDF = () => {
    if (!scan) return;
    const doc = new jsPDF();
    
    // Header
    doc.setFontSize(20);
    doc.text('Security Scan Report', 14, 22);
    
    doc.setFontSize(12);
    doc.text(`Target URL: ${scan.target_url}`, 14, 32);
    doc.text(`Date: ${new Date(scan.completed_at || new Date()).toLocaleString()}`, 14, 40);
    doc.text(`Risk Score: ${scan.risk_score || 'N/A'} / 10.0`, 14, 48);

    // Summary
    doc.text(`Critical: ${scan.critical_count} | High: ${scan.high_count} | Medium: ${scan.medium_count} | Low: ${scan.low_count}`, 14, 56);
    
    // Vulnerabilities Table
    if (vulns && vulns.length > 0) {
      const tableColumn = ["Severity", "Title", "CVSS", "Affected URL"];
      const tableRows: any[] = [];

      vulns.forEach((v: any) => {
        tableRows.push([
          v.severity,
          v.title,
          v.cvss_score,
          v.affected_url
        ]);
      });

      autoTable(doc, {
        startY: 65,
        head: [tableColumn],
        body: tableRows,
        styles: { fontSize: 9 },
        headStyles: { fillColor: [79, 70, 229] }, // Indigo-600
        didParseCell: function(data) {
           if (data.section === 'body' && data.column.index === 0) {
               // Color code severity
               if (data.cell.raw === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
               else if (data.cell.raw === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
               else if (data.cell.raw === 'MEDIUM') data.cell.styles.textColor = [202, 138, 4];
               else if (data.cell.raw === 'LOW') data.cell.styles.textColor = [22, 163, 74];
           }
        }
      });
    }

    doc.save(`security-report-${scan.target_url.replace(/https?:\/\//, '').split('/')[0]}.pdf`);
  };

  if (!scan) return <div className="p-6 text-gray-500">Loading...</div>;

  const isRunning = scan.status === 'pending' || scan.status === 'running';

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <Link to="/scans" className="mt-1 text-gray-400 hover:text-gray-600">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-xl font-bold text-gray-900 break-all">{scan.target_url}</h1>
            <div className="mt-1 flex items-center gap-3">
              <StatusBadge status={scan.status} />
              {isRunning && (
                <span className={`text-xs font-semibold ${wsStatus === 'connected' ? 'text-green-500' : wsStatus === 'connecting' ? 'text-yellow-500' : 'text-red-500'}`}>
                  {wsStatus === 'connected' ? '🟢 Live' : wsStatus === 'connecting' ? '🟡 Connecting...' : '🔴 Disconnected'}
                </span>
              )}
              {scan.completed_at && (
                <span className="text-xs text-gray-400">
                  Completed {new Date(scan.completed_at).toLocaleString()}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex gap-2">
          {scan.status === 'completed' && (
            <>
              <button
                onClick={downloadPDF}
                className="flex items-center gap-1.5 rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs font-medium text-gray-700 hover:bg-gray-50"
              >
                <Download className="h-3.5 w-3.5" /> Export PDF
              </button>
              <button
                onClick={() => setShowChat(!showChat)}
                className="flex items-center gap-1.5 rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-2 text-xs font-medium text-indigo-700 hover:bg-indigo-100"
              >
                <MessageSquare className="h-3.5 w-3.5" /> Ask AI
              </button>
            </>
          )}
        </div>
      </div>

      {/* Summary cards */}
      {scan.status === 'completed' && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          {scan.risk_score != null && (
            <div className="col-span-2 sm:col-span-1 flex justify-center rounded-xl border border-gray-200 bg-white p-4">
              <RiskScore score={parseFloat(scan.risk_score)} />
            </div>
          )}
          {[
            { label: 'Critical', count: scan.critical_count, color: 'text-red-600' },
            { label: 'High',     count: scan.high_count,     color: 'text-orange-600' },
            { label: 'Medium',   count: scan.medium_count,   color: 'text-yellow-600' },
            { label: 'Low',      count: scan.low_count,      color: 'text-green-600' },
            { label: 'Total',    count: scan.total_vulns,    color: 'text-gray-800' },
          ].map(({ label, count, color }) => (
            <div key={label} className="flex flex-col items-center justify-center rounded-xl border border-gray-200 bg-white p-4">
              <div className={`text-2xl font-bold ${color}`}>{count}</div>
              <div className="text-xs text-gray-500">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* AI Executive Summary */}
      {report?.executive_summary && (
        <div className="rounded-xl border border-indigo-200 bg-indigo-50 p-5">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-indigo-600">🤖</span>
            <h2 className="text-sm font-semibold text-indigo-900">AI Executive Summary</h2>
            <span className="ml-auto rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-700">
              {report.risk_rating}
            </span>
          </div>
          <p className="text-sm text-indigo-800">{report.executive_summary}</p>
        </div>
      )}

      {/* Hacker Live Terminal */}
      {isRunning && (
        <div className="rounded-xl border border-gray-700 bg-black p-4 shadow-xl">
          <div className="mb-3 flex items-center justify-between border-b border-gray-800 pb-2">
            <div className="flex items-center gap-2">
              <RefreshCw className="h-4 w-4 animate-spin text-green-500" />
              <span className="text-sm font-bold text-green-500 tracking-wider">SECURE-SCAN TERMINAL v2.0</span>
            </div>
            <div className="flex gap-1.5">
              <div className="h-2.5 w-2.5 rounded-full bg-red-500"></div>
              <div className="h-2.5 w-2.5 rounded-full bg-yellow-500"></div>
              <div className="h-2.5 w-2.5 rounded-full bg-green-500"></div>
            </div>
          </div>
          <div className="h-64 overflow-y-auto font-mono text-xs text-green-400 space-y-1 bg-black p-2 rounded">
            {logs.length === 0 ? (
              <div className="text-gray-500 animate-pulse">Initializing connection to target payload...</div>
            ) : (
              logs.map((log, i) => {
                let colorClass = 'text-green-400';
                if (log.includes('🚨 Found') || log.includes('Failed')) colorClass = 'text-red-500 font-bold';
                else if (log.includes('Testing') || log.includes('Scanning')) colorClass = 'text-yellow-400';
                else if (log.includes('Completed') || log.includes('Success')) colorClass = 'text-green-500 font-bold';
                
                return (
                  <div key={i} className="flex">
                    <span className="text-green-600 mr-2 opacity-50">&gt;</span>
                    <span className={colorClass}>
                      {log}
                    </span>
                  </div>
                );
              })
            )}
            <div ref={terminalEndRef} />
            <div className="animate-pulse text-green-500 mt-2">_</div>
          </div>
        </div>
      )}

      {/* AI Chat */}
      {showChat && scan.status === 'completed' && (
        <AiChat scanId={id!} />
      )}

      {/* Vulnerabilities */}
      {(vulns?.length ?? 0) > 0 && (
        <div className="rounded-xl border border-gray-200 bg-white">
          <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
            <h2 className="text-sm font-semibold text-gray-700">
              Vulnerabilities ({vulns.length})
            </h2>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-lg border border-gray-200 px-3 py-1.5 text-xs"
            >
              <option value="">All Severities</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          <div className="divide-y divide-gray-50">
            {vulns.map((vuln: any) => (
              <VulnRow key={vuln.id} vuln={vuln} />
            ))}
          </div>
        </div>
      )}

      {scan.status === 'completed' && (vulns?.length ?? 0) === 0 && !severityFilter && (
        <div className="rounded-xl border border-green-200 bg-green-50 p-6 text-center">
          <div className="text-2xl">✅</div>
          <p className="mt-2 text-sm font-semibold text-green-800">No vulnerabilities found!</p>
          <p className="text-xs text-green-600">The target appears to be well secured for the modules tested.</p>
        </div>
      )}
    </div>
  );
}

function VulnRow({ vuln }: { vuln: any }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="px-6 py-4">
      <button
        className="w-full text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={vuln.severity} size="sm" />
              {vuln.owasp_category && (
                <span className="text-xs text-gray-400">{vuln.owasp_category?.split(' - ')[0]}</span>
              )}
            </div>
            <p className="mt-1 text-sm font-medium text-gray-900">{vuln.title}</p>
            <p className="truncate text-xs text-gray-500">{vuln.affected_url}</p>
          </div>
          <div className="flex-shrink-0 text-right">
            <div className="text-sm font-bold text-gray-700">
              CVSS {parseFloat(vuln.cvss_score).toFixed(1)}
            </div>
            {vuln.cwe_id && (
              <div className="text-xs text-gray-400">CWE-{vuln.cwe_id}</div>
            )}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="mt-4 space-y-4 border-t border-gray-100 pt-4">
          <div>
            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Description</h4>
            <p className="mt-1 text-sm text-gray-700">{vuln.description}</p>
          </div>

          {vuln.ai_explanation && (
            <div className="rounded-lg bg-indigo-50 p-3">
              <h4 className="text-xs font-semibold text-indigo-700 mb-1">🤖 AI Explanation</h4>
              <p className="text-sm text-indigo-900">{vuln.ai_explanation}</p>
            </div>
          )}

          {vuln.ai_business_impact && (
            <div className="rounded-lg bg-orange-50 p-3">
              <h4 className="text-xs font-semibold text-orange-700 mb-1">⚠️ Business Impact</h4>
              <p className="text-sm text-orange-900">{vuln.ai_business_impact}</p>
            </div>
          )}

          {(vuln.ai_remediation_steps?.length > 0 || vuln.remediation) && (
            <div>
              <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
                Remediation
              </h4>
              {vuln.ai_remediation_steps?.length > 0 ? (
                <ol className="mt-1 space-y-1 text-sm text-gray-700 list-decimal list-inside">
                  {vuln.ai_remediation_steps.map((step: string, i: number) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              ) : (
                <p className="mt-1 text-sm text-gray-700 whitespace-pre-wrap">{vuln.remediation}</p>
              )}
            </div>
          )}

          {/* Evidence Details */}
          {vuln.evidence && vuln.evidence.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Raw Evidence</h4>
              {vuln.evidence.map((ev: any, i: number) => (
                <div key={i} className="mt-2 rounded-lg border border-gray-200 bg-gray-50 p-3">
                  <div className="text-xs font-semibold text-gray-700">{ev.description || 'Payload Result'}</div>
                  {ev.request && (
                    <div className="mt-2">
                      <div className="text-[10px] text-gray-500 font-bold uppercase">Request:</div>
                      <pre className="mt-1 overflow-x-auto rounded bg-gray-800 p-2 text-[10px] text-gray-300">
                        {ev.request}
                      </pre>
                    </div>
                  )}
                  {ev.response && (
                    <div className="mt-2">
                      <div className="text-[10px] text-gray-500 font-bold uppercase">Response Extract:</div>
                      <pre className="mt-1 overflow-x-auto rounded bg-gray-800 p-2 text-[10px] text-gray-300">
                        {ev.response}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}


          {vuln.ai_code_example && (
            <div>
              <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Code Example</h4>
              <pre className="mt-1 overflow-x-auto rounded-lg bg-gray-900 p-3 text-xs text-gray-100">
                {vuln.ai_code_example}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending:   'bg-yellow-100 text-yellow-800',
    running:   'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    failed:    'bg-red-100 text-red-800',
  };
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold capitalize ${styles[status] ?? ''}`}>
      {status === 'running' && '⟳ '}{status}
    </span>
  );
}
