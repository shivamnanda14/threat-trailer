'use client';

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export default function CopyJsonButton({ data }: { data: any }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button 
      onClick={handleCopy}
      className="flex items-center gap-1.5 px-2 py-1 bg-surface-muted hover:bg-border-subtle text-[10px] uppercase font-bold tracking-widest text-text-primary transition-colors border border-border-subtle rounded-sm"
    >
      {copied ? <Check className="w-3 h-3 text-green-500" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}