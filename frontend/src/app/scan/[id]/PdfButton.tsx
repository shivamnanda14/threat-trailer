'use client';

import { Download } from 'lucide-react';

export default function PdfButton() {
  return (
    <button 
      onClick={() => window.print()}
      className="text-xs font-heading uppercase tracking-widest text-text-secondary hover:text-text-primary transition-colors flex items-center gap-2"
    >
      <Download className="w-4 h-4" /> Save as PDF
    </button>
  );
}