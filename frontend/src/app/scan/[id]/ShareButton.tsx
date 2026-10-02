'use client';

import { useState } from 'react';
import { Share2, Check } from 'lucide-react';

export default function ShareButton({ title, id }: { title: string, id: string }) {
  const [copied, setCopied] = useState(false);

  const handleShare = async () => {
    // Generate the public URL
    const url = `${window.location.origin}/scan/${id}`;
    
    // Try native OS share menu first (works great on mobile/macOS)
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'Threat Trailer Report',
          text: `Check out this threat analysis for: ${title}`,
          url: url,
        });
        return;
      } catch (err) {
        console.log('Share dismissed');
      }
    }
    
    // Fallback: Copy to clipboard
    await navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleShare}
      className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-canvas text-xs font-heading font-semibold uppercase tracking-wider transition-all hover:scale-105 active:scale-95 shadow-lg shadow-accent/20"
    >
      {copied ? <Check className="w-4 h-4" /> : <Share2 className="w-4 h-4" />}
      {copied ? 'Link Copied!' : 'Share Public Report'}
    </button>
  );
}