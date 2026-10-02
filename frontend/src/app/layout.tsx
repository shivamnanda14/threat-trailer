'use client';

import { Space_Grotesk, IBM_Plex_Sans } from 'next/font/google';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ShieldAlert, Activity, Database, Settings, LogIn } from 'lucide-react';
import { ClerkProvider, SignInButton, Show, UserButton } from '@clerk/nextjs';
import './globals.css';

const spaceGrotesk = Space_Grotesk({ subsets: ['latin'], variable: '--font-heading', weight: ['500', '600'] });
const ibmPlex = IBM_Plex_Sans({ subsets: ['latin'], variable: '--font-body', weight: ['400', '500'] });

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <ClerkProvider>
      <html lang="en" className={`${spaceGrotesk.variable} ${ibmPlex.variable} dark`}>
        <body className="bg-canvas text-text-primary font-body flex h-screen overflow-hidden antialiased selection:bg-accent/30">
          
          <aside className="w-64 bg-surface-subtle border-r border-border-subtle flex flex-col justify-between hidden md:flex">
            <div className="p-6">
              <div className="flex items-center gap-3 mb-12 text-text-primary">
                <ShieldAlert className="w-6 h-6 text-accent" />
                <span className="font-heading font-semibold tracking-wide">ThreatTrailer</span>
              </div>
              <nav className="space-y-2">
                <NavItem href="/" icon={<Activity />} label="Live Detonation" active={pathname === '/'} />
                <NavItem href="/history" icon={<Database />} label="Historical Logs" active={pathname === '/history'} />
                <NavItem href="/settings" icon={<Settings />} label="Engine Config" active={pathname === '/settings'} />
              </nav>
            </div>
            
            <div className="p-6 border-t border-border-subtle flex flex-col gap-6">
              
              {/* --- CLERK AUTH SECTION (FIXED KEBAB-CASE) --- */}
              <div className="flex flex-col gap-3">
                <Show when="signed-out">
                  <SignInButton mode="modal">
                    <div className="w-full bg-accent/10 hover:bg-accent/20 border border-accent/30 transition-colors px-4 py-2 text-xs font-heading uppercase tracking-widest text-accent rounded-sm cursor-pointer flex items-center justify-center gap-2">
                      <LogIn className="w-4 h-4" />
                      Agent Login
                    </div>
                  </SignInButton>
                </Show>
                
                <Show when="signed-in">
                  <div className="flex items-center gap-3 w-full p-2 bg-surface-muted rounded-sm border border-border-subtle shadow-inner">
                    <UserButton appearance={{ elements: { avatarBox: "w-8 h-8 rounded-sm border border-border-subtle" } }} />
                    <div className="flex flex-col">
                      <span className="text-[10px] font-heading uppercase tracking-widest text-accent">Active Agent</span>
                    </div>
                  </div>
                </Show>
              </div>

              {/* --- SYSTEM STATUS --- */}
              <div>
                <div className="text-xs text-text-secondary">System Status</div>
                <div className="flex items-center gap-2 mt-2 text-sm">
                  <span className="w-2 h-2 rounded-full bg-green-500/80 animate-pulse" />
                  Secure Network
                </div>
              </div>

            </div>
          </aside>

          <main className="flex-1 overflow-y-auto bg-canvas relative">
            
            {/* Mobile Auth Header (FIXED KEBAB-CASE) */}
            <div className="md:hidden absolute top-6 right-6 z-50">
               <Show when="signed-out">
                  <SignInButton mode="modal">
                    <button className="bg-accent/10 border border-accent/30 px-3 py-1.5 text-[10px] font-heading uppercase tracking-widest text-accent rounded-sm">
                      Login
                    </button>
                  </SignInButton>
               </Show>
               <Show when="signed-in">
                  <UserButton appearance={{ elements: { avatarBox: "w-8 h-8 rounded-sm border border-accent/50" } }} />
               </Show>
            </div>

            {children}
          </main>
        </body>
      </html>
    </ClerkProvider>
  );
}

function NavItem({ href, icon, label, active }: { href: string; icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <Link href={href}>
      <div className={`flex items-center gap-3 px-3 py-2 text-sm rounded-sm transition-colors cursor-pointer ${
        active ? 'bg-accent/10 text-accent font-medium shadow-[inset_2px_0_0_0_var(--accent)]' : 'text-text-secondary hover:text-text-primary hover:bg-surface-muted'
      }`}>
        <div className="w-4 h-4">{icon}</div>
        {label}
      </div>
    </Link>
  );
}