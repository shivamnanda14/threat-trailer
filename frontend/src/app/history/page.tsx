import Link from 'next/link';
import { Search, ExternalLink, ShieldAlert } from 'lucide-react';
import { getThreatLogs } from '../actions';

export default async function HistoryPage() {
  const logs = await getThreatLogs();

  return (
    <div className="max-w-[1200px] mx-auto px-8 py-12">
      <header className="mb-8 flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="font-heading text-2xl text-text-primary mb-2">Historical Logs</h1>
          <p className="text-text-secondary text-sm">Review previously detonated payloads stored in your database.</p>
        </div>
      </header>

      <div className="bg-surface-subtle border border-border-subtle overflow-x-auto">
        <table className="w-full text-left border-collapse text-sm min-w-[800px]">
          <thead>
            <tr className="border-b border-border-subtle bg-surface-muted/50 font-heading text-xs uppercase tracking-wider text-text-secondary">
              <th className="p-4 font-medium">Timestamp</th>
              <th className="p-4 font-medium">Target URL</th>
              <th className="p-4 font-medium">Risk Level</th>
              <th className="p-4 font-medium">Network Reqs</th>
              <th className="p-4 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-8 text-center text-text-secondary">No historical threat logs found in database.</td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id} className="border-b border-border-subtle last:border-0 hover:bg-surface-muted/30 transition-colors">
                  <td className="p-4 text-text-secondary whitespace-nowrap">
                    {log.createdAt.toLocaleDateString()}
                  </td>
                  <td className="p-4 text-text-primary truncate max-w-[300px]">{log.url}</td>
                  <td className="p-4">
                    <span className={`inline-flex items-center gap-1.5 px-2 py-1 text-xs font-medium border ${
                      log.riskLevel === 'CRITICAL' ? 'border-red-500/50 text-red-400 bg-red-900/10' :
                      log.riskLevel === 'SUSPICIOUS' ? 'border-orange-500/50 text-orange-400 bg-orange-900/10' :
                      'border-border-subtle text-text-secondary bg-surface-muted'
                    }`}>
                      {log.riskLevel === 'CRITICAL' && <ShieldAlert className="w-3 h-3" />}
                      {log.riskLevel}
                    </span>
                  </td>
                  <td className="p-4 text-text-secondary font-mono">{log.networkReqs}</td>
                  <td className="p-4 text-right">
                    <Link href={`/scan/${log.id}`} className="text-accent hover:text-text-primary transition-colors inline-flex items-center gap-1 text-xs uppercase font-heading tracking-wide">
                      View Report <ExternalLink className="w-3 h-3" />
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}