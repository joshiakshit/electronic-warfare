import { useState } from 'react';
import { X, Search, Monitor, Settings as SettingsIcon, Sliders } from 'lucide-react';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  winSize: number;
  setWinSize: (s: number) => void;
}

export const SettingsModal = ({ isOpen, onClose, winSize, setWinSize }: SettingsModalProps) => {
  const [activeTab, setActiveTab] = useState('Display');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-4xl h-[70vh] bg-[#09090b] border border-gray-900 rounded-xl shadow-2xl flex overflow-hidden flex-row">
        
        {/* Left Sidebar */}
        <div className="w-64 bg-[#000000] border-r border-gray-900 p-4 flex flex-col shrink-0">
          <div className="relative mb-6">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input type="text" placeholder="Search" className="w-full bg-[#09090b] border border-gray-900 rounded-md pl-9 pr-3 py-1.5 text-sm text-white outline-none focus:border-[#1ed760] transition-colors" />
          </div>
          
          <div className="text-xs font-semibold text-gray-500 mb-2 px-3 uppercase tracking-wider">Settings</div>
          
          <div className="flex flex-col gap-1">
            <button onClick={() => setActiveTab('General')} className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${activeTab === 'General' ? 'bg-[#09090b] text-white shadow-sm border border-gray-800' : 'text-gray-400 hover:bg-[#09090b]/50 border border-transparent'}`}>
              <Sliders size={16} /> General
            </button>
            <button onClick={() => setActiveTab('Display')} className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${activeTab === 'Display' ? 'bg-[#09090b] text-white shadow-sm border border-gray-800' : 'text-gray-400 hover:bg-[#09090b]/50 border border-transparent'}`}>
              <Monitor size={16} /> Display
            </button>
            <button onClick={() => setActiveTab('Simulation')} className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${activeTab === 'Simulation' ? 'bg-[#09090b] text-white shadow-sm border border-gray-800' : 'text-gray-400 hover:bg-[#09090b]/50 border border-transparent'}`}>
              <SettingsIcon size={16} /> Simulation
            </button>
          </div>
        </div>

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col relative bg-[#09090b] text-gray-200">
          <button onClick={onClose} className="absolute top-4 right-4 text-gray-500 hover:text-white transition-colors p-2 z-10">
            <X size={20} />
          </button>
          
          <div className="flex-1 overflow-y-auto p-10 relative">
            <h2 className="text-xl font-semibold mb-8 text-white">{activeTab}</h2>
            
            {activeTab === 'Display' && (
              <div className="flex flex-col gap-10">
                <div className="flex flex-col gap-3">
                  <h3 className="text-sm font-semibold text-white">Appearance</h3>
                  <p className="text-xs text-gray-400 max-w-md">Light mode is currently disabled by administrator.</p>
                  <div className="flex gap-4 opacity-50 pointer-events-none mt-2">
                    <button className="flex items-center gap-2 px-6 py-3 rounded-lg border border-[#1ed760] text-[#1ed760] bg-[#1ed760]/10">
                       Dark
                    </button>
                  </div>
                </div>
                <div className="h-px bg-gray-900 w-full"></div>
                <div className="flex flex-col gap-3">
                  <h3 className="text-sm font-semibold text-white">Chart Viewport Size</h3>
                  <p className="text-xs text-gray-400 max-w-md">Number of time slots to show simultaneously in the waterfall chart. A higher number provides more history but squishes the cells.</p>
                  <div className="flex items-center gap-4 mt-2">
                    <input type="range" min="20" max="100" value={winSize} onChange={(e) => setWinSize(Number(e.target.value))} className="w-64 accent-[#1ed760]" />
                    <span className="text-sm font-mono bg-[#000000] border border-gray-800 px-3 py-1 rounded text-white">{winSize} Slots</span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'Simulation' && (
              <div className="flex flex-col gap-8">
                <div className="flex flex-col gap-2 max-w-md">
                  <h3 className="text-sm font-semibold text-white">Backend URL</h3>
                  <input type="text" defaultValue="http://localhost:8000" className="w-full bg-[#000000] border border-gray-800 rounded-md px-3 py-2 text-sm text-white outline-none focus:border-[#1ed760]" />
                </div>
                <div className="flex flex-col gap-2 max-w-[150px]">
                  <h3 className="text-sm font-semibold text-white">ML Exploration Rate</h3>
                  <input type="text" defaultValue="0.1" className="w-full bg-[#000000] border border-gray-800 rounded-md px-3 py-2 text-sm text-white outline-none focus:border-[#1ed760]" />
                </div>
              </div>
            )}
            
            {activeTab === 'General' && (
              <div className="flex flex-col gap-8">
                <p className="text-sm text-gray-400">General settings for the E-WAVE Dashboard.</p>
                <div className="flex flex-col gap-2 max-w-md">
                  <h3 className="text-sm font-semibold text-white">User Profile</h3>
                  <input type="text" defaultValue="Admin User" className="w-full bg-[#000000] border border-gray-800 rounded-md px-3 py-2 text-sm text-white outline-none focus:border-[#1ed760]" />
                </div>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};
