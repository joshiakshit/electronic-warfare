import { useState } from 'react';
import { X, Search, Monitor, Settings as SettingsIcon, Sliders, Sun, Moon } from 'lucide-react';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  winSize: number;
  setWinSize: (s: number) => void;
  theme: 'dark' | 'light';
  setTheme: (t: 'dark' | 'light') => void;
}

export const SettingsModal = ({ isOpen, onClose, winSize, setWinSize, theme, setTheme }: SettingsModalProps) => {
  const [activeTab, setActiveTab] = useState('Display');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-4xl h-[70vh] bg-ew-surface border border-ew-border-subtle rounded-xl shadow-2xl flex overflow-hidden flex-row">

        {/* Left Sidebar */}
        <div className="w-64 bg-ew-bg border-r border-ew-border-subtle p-4 flex flex-col shrink-0">
          <div className="relative mb-6">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ew-text-dim" />
            <input type="text" placeholder="Search" className="w-full bg-ew-surface border border-ew-border-subtle rounded-md pl-9 pr-3 py-1.5 text-sm text-ew-text outline-none focus:border-ew-accent transition-colors" />
          </div>

          <div className="text-xs font-semibold text-ew-text-dim mb-2 px-3 uppercase tracking-wider">Settings</div>

          <div className="flex flex-col gap-1">
            <button onClick={() => setActiveTab('General')} className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${activeTab === 'General' ? 'bg-ew-surface text-ew-text shadow-sm border border-ew-border' : 'text-ew-text-muted hover:bg-ew-surface/50 border border-transparent'}`}>
              <Sliders size={16} /> General
            </button>
            <button onClick={() => setActiveTab('Display')} className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${activeTab === 'Display' ? 'bg-ew-surface text-ew-text shadow-sm border border-ew-border' : 'text-ew-text-muted hover:bg-ew-surface/50 border border-transparent'}`}>
              <Monitor size={16} /> Display
            </button>
            <button onClick={() => setActiveTab('Simulation')} className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${activeTab === 'Simulation' ? 'bg-ew-surface text-ew-text shadow-sm border border-ew-border' : 'text-ew-text-muted hover:bg-ew-surface/50 border border-transparent'}`}>
              <SettingsIcon size={16} /> Simulation
            </button>
          </div>
        </div>

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col relative bg-ew-surface text-ew-text-secondary">
          <button onClick={onClose} className="absolute top-4 right-4 text-ew-text-dim hover:text-ew-text transition-colors p-2 z-10">
            <X size={20} />
          </button>

          <div className="flex-1 overflow-y-auto p-10 relative">
            <h2 className="text-xl font-semibold mb-8 text-ew-text">{activeTab}</h2>

            {activeTab === 'Display' && (
              <div className="flex flex-col gap-10">
                <div className="flex flex-col gap-3">
                  <h3 className="text-sm font-semibold text-ew-text">Appearance</h3>
                  <p className="text-xs text-ew-text-muted max-w-md">Choose your preferred color scheme.</p>
                  <div className="flex gap-4 mt-2">
                    <button
                      onClick={() => setTheme('dark')}
                      className={`flex items-center gap-2 px-6 py-3 rounded-lg border transition-colors ${theme === 'dark' ? 'border-ew-accent text-ew-accent bg-ew-accent/10' : 'border-ew-border text-ew-text-muted hover:border-ew-text-muted'}`}
                    >
                      <Moon size={16} /> Dark
                    </button>
                    <button
                      onClick={() => setTheme('light')}
                      className={`flex items-center gap-2 px-6 py-3 rounded-lg border transition-colors ${theme === 'light' ? 'border-ew-accent text-ew-accent bg-ew-accent/10' : 'border-ew-border text-ew-text-muted hover:border-ew-text-muted'}`}
                    >
                      <Sun size={16} /> Light
                    </button>
                  </div>
                </div>
                <div className="h-px bg-ew-border-subtle w-full"></div>
                <div className="flex flex-col gap-3">
                  <h3 className="text-sm font-semibold text-ew-text">Chart Viewport Size</h3>
                  <p className="text-xs text-ew-text-muted max-w-md">Number of time slots to show simultaneously in the waterfall chart. A higher number provides more history but squishes the cells.</p>
                  <div className="flex items-center gap-4 mt-2">
                    <input type="range" min="20" max="100" value={winSize} onChange={(e) => setWinSize(Number(e.target.value))} className="w-64 accent-ew-accent" />
                    <span className="text-sm font-mono bg-ew-bg border border-ew-border px-3 py-1 rounded text-ew-text">{winSize} Slots</span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'Simulation' && (
              <div className="flex flex-col gap-8">
                <div className="flex flex-col gap-2 max-w-md">
                  <h3 className="text-sm font-semibold text-ew-text">Backend URL</h3>
                  <input type="text" defaultValue="http://localhost:8000" className="w-full bg-ew-bg border border-ew-border rounded-md px-3 py-2 text-sm text-ew-text outline-none focus:border-ew-accent" />
                </div>
                <div className="flex flex-col gap-2 max-w-[150px]">
                  <h3 className="text-sm font-semibold text-ew-text">ML Exploration Rate</h3>
                  <input type="text" defaultValue="0.1" className="w-full bg-ew-bg border border-ew-border rounded-md px-3 py-2 text-sm text-ew-text outline-none focus:border-ew-accent" />
                </div>
              </div>
            )}

            {activeTab === 'General' && (
              <div className="flex flex-col gap-8">
                <p className="text-sm text-ew-text-muted">General settings for the E-WAVE Dashboard.</p>
                <div className="flex flex-col gap-2 max-w-md">
                  <h3 className="text-sm font-semibold text-ew-text">User Profile</h3>
                  <input type="text" defaultValue="Admin User" className="w-full bg-ew-bg border border-ew-border rounded-md px-3 py-2 text-sm text-ew-text outline-none focus:border-ew-accent" />
                </div>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};
