'use client';

import { Key, Cpu, Save } from 'lucide-react';

export default function SettingsPage() {
  return (
    <div className="max-w-[800px] mx-auto px-8 py-12">
      <header className="mb-12">
        <h1 className="font-heading text-2xl text-text-primary mb-2">Engine Configuration</h1>
        <p className="text-text-secondary text-sm">Manage agent infrastructure, API keys, and model parameters.</p>
      </header>

      <div className="flex flex-col gap-8">
        
        {/* API Credentials */}
        <section className="bg-surface-subtle border border-border-subtle p-8">
          <div className="flex items-center gap-2 text-xs font-heading tracking-wider uppercase text-text-secondary mb-6">
            <Key className="w-4 h-4" /> API Credentials
          </div>
          
          <div className="space-y-6">
            <div>
              <label className="block text-sm text-text-primary mb-2">Google Gemini API Key</label>
              <input 
                type="password" 
                placeholder="AIzaSy..." 
                className="w-full bg-canvas border border-border-subtle px-4 py-2.5 text-sm text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:border-accent transition-colors"
              />
              <p className="text-xs text-text-secondary mt-2">Required for the Forensic Agent to synthesize device impact.</p>
            </div>
            
            <div>
              <label className="block text-sm text-text-primary mb-2">VirusTotal API Key (v3)</label>
              <input 
                type="password" 
                placeholder="Enter VT 64-char key..." 
                className="w-full bg-canvas border border-border-subtle px-4 py-2.5 text-sm text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:border-accent transition-colors"
              />
              <p className="text-xs text-text-secondary mt-2">Required for the OSINT Agent to fetch community telemetry.</p>
            </div>
          </div>
        </section>

        {/* Model Selection */}
        <section className="bg-surface-subtle border border-border-subtle p-8">
          <div className="flex items-center gap-2 text-xs font-heading tracking-wider uppercase text-text-secondary mb-6">
            <Cpu className="w-4 h-4" /> Orchestration Model
          </div>
          
          <div>
            <label className="block text-sm text-text-primary mb-2">Forensic Reasoning Engine</label>
            <select className="w-full bg-canvas border border-border-subtle px-4 py-2.5 text-sm text-text-primary focus:outline-none focus:border-accent transition-colors appearance-none cursor-pointer">
              <option value="gemini-1.5-flash">Gemini 1.5 Flash (Fastest, Default)</option>
              <option value="gemini-1.5-pro">Gemini 1.5 Pro (Deep Reasoning)</option>
              <option value="gemini-3.8-flash">Gemini 3.8 Flash (Latest)</option>
            </select>
            <p className="text-xs text-text-secondary mt-2">Select the underlying LLM powering the threat synthesis. Pro models may incur higher latency.</p>
          </div>
        </section>

        <div className="flex justify-end">
          <button className="bg-accent hover:bg-accent-hover text-text-primary text-sm px-8 py-2.5 font-medium transition-colors inline-flex items-center gap-2">
            <Save className="w-4 h-4" /> Save Configuration
          </button>
        </div>

      </div>
    </div>
  );
}