import { useState } from 'react'
import { Monitor, Moon, Radio, Sun, X } from 'lucide-react'

export type SettingsTab = 'Scanner' | 'Display'

interface SettingsModalProps {
  isOpen: boolean
  initialTab: SettingsTab
  onClose: () => void
  scenarios: string[]
  schedulers: string[]
  scenario: string
  setScenario: (value: string) => void
  scheduler: string
  setScheduler: (value: string) => void
  seed: number
  setSeed: (value: number) => void
  k: number
  setK: (value: number) => void
  maxBands: number
  winSize: number
  setWinSize: (value: number) => void
  theme: 'dark' | 'light'
  setTheme: (value: 'dark' | 'light') => void
}

export const SettingsModal = ({
  isOpen,
  initialTab,
  onClose,
  scenarios,
  schedulers,
  scenario,
  setScenario,
  scheduler,
  setScheduler,
  seed,
  setSeed,
  k,
  setK,
  maxBands,
  winSize,
  setWinSize,
  theme,
  setTheme,
}: SettingsModalProps) => {
  const [activeTab, setActiveTab] = useState<SettingsTab>(initialTab)

  if (!isOpen) return null

  const tabClass = (tab: SettingsTab) => `flex items-center gap-3 rounded-md border px-3 py-2 text-sm transition-colors ${activeTab === tab ? 'border-ew-border bg-ew-surface text-ew-text' : 'border-transparent text-ew-text-muted hover:bg-ew-surface/50'}`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="flex h-[70vh] w-full max-w-4xl overflow-hidden rounded-xl border border-ew-border-subtle bg-ew-surface shadow-2xl">
        <aside className="flex w-16 shrink-0 flex-col border-r border-ew-border-subtle bg-ew-bg p-2 sm:w-56 sm:p-4">
          <div className="mb-3 hidden px-3 text-xs font-semibold uppercase tracking-wider text-ew-text-dim sm:block">Settings</div>
          <div className="flex flex-col gap-1">
            <button onClick={() => setActiveTab('Scanner')} className={tabClass('Scanner')} title="Scanner settings">
              <Radio size={16} className="shrink-0" />
              <span className="hidden sm:inline">Scanner</span>
            </button>
            <button onClick={() => setActiveTab('Display')} className={tabClass('Display')} title="Display settings">
              <Monitor size={16} className="shrink-0" />
              <span className="hidden sm:inline">Display</span>
            </button>
          </div>
        </aside>

        <div className="relative flex min-w-0 flex-1 flex-col bg-ew-surface text-ew-text-secondary">
          <button onClick={onClose} aria-label="Close settings" className="absolute right-4 top-4 z-10 p-2 text-ew-text-dim transition-colors hover:text-ew-text">
            <X size={20} />
          </button>

          <div className="flex-1 overflow-y-auto p-6 sm:p-10">
            <h2 className="mb-8 text-xl font-semibold text-ew-text">{activeTab} settings</h2>

            {activeTab === 'Scanner' && (
              <div className="grid max-w-2xl gap-6 sm:grid-cols-2">
                <label className="flex flex-col gap-2 text-sm font-semibold text-ew-text">
                  RF scenario
                  <select aria-label="RF scenario" value={scenario} onChange={event => setScenario(event.target.value)} className="rounded-md border border-ew-border bg-ew-bg px-3 py-2 text-sm font-normal text-ew-text outline-none focus:border-ew-accent">
                    {scenarios.map(item => <option key={item} value={item}>{item.replace(/_/g, ' ')}</option>)}
                  </select>
                </label>

                <label className="flex flex-col gap-2 text-sm font-semibold text-ew-text">
                  Scheduling algorithm
                  <select aria-label="Scheduling algorithm" value={scheduler} onChange={event => setScheduler(event.target.value)} className="rounded-md border border-ew-border bg-ew-bg px-3 py-2 text-sm font-normal text-ew-text outline-none focus:border-ew-accent">
                    {schedulers.map(item => <option key={item} value={item}>{item.replace(/_/g, ' ')}</option>)}
                  </select>
                </label>

                <label className="flex flex-col gap-2 text-sm font-semibold text-ew-text">
                  Seed
                  <input aria-label="Seed" type="number" min={0} value={seed} onChange={event => setSeed(Math.max(0, Number(event.target.value)))} className="rounded-md border border-ew-border bg-ew-bg px-3 py-2 font-mono text-sm font-normal text-ew-text outline-none focus:border-ew-accent" />
                </label>

                <label className="flex flex-col gap-2 text-sm font-semibold text-ew-text">
                  Channel bands
                  <select aria-label="Channel bands" value={k} onChange={event => setK(Number(event.target.value))} className="rounded-md border border-ew-border bg-ew-bg px-3 py-2 text-sm font-normal text-ew-text outline-none focus:border-ew-accent">
                    {Array.from({ length: maxBands }, (_, index) => index + 1).map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
              </div>
            )}

            {activeTab === 'Display' && (
              <div className="flex flex-col gap-10">
                <div className="flex flex-col gap-3">
                  <h3 className="text-sm font-semibold text-ew-text">Appearance</h3>
                  <p className="max-w-md text-xs text-ew-text-muted">Choose your preferred color scheme.</p>
                  <div className="mt-2 flex gap-4">
                    <button onClick={() => setTheme('dark')} className={`flex items-center gap-2 rounded-lg border px-6 py-3 transition-colors ${theme === 'dark' ? 'border-ew-accent bg-ew-accent/10 text-ew-accent' : 'border-ew-border text-ew-text-muted hover:border-ew-text-muted'}`}>
                      <Moon size={16} /> Dark
                    </button>
                    <button onClick={() => setTheme('light')} className={`flex items-center gap-2 rounded-lg border px-6 py-3 transition-colors ${theme === 'light' ? 'border-ew-accent bg-ew-accent/10 text-ew-accent' : 'border-ew-border text-ew-text-muted hover:border-ew-text-muted'}`}>
                      <Sun size={16} /> Light
                    </button>
                  </div>
                </div>

                <div className="h-px w-full bg-ew-border-subtle" />

                <div className="flex flex-col gap-3">
                  <h3 className="text-sm font-semibold text-ew-text">Chart viewport size</h3>
                  <p className="max-w-md text-xs text-ew-text-muted">Number of time slots shown in the spectrum timeline.</p>
                  <div className="mt-2 flex flex-wrap items-center gap-4">
                    <input aria-label="Chart viewport size" type="range" min="20" max="100" value={winSize} onChange={event => setWinSize(Number(event.target.value))} className="w-64 max-w-full accent-ew-accent" />
                    <span className="rounded border border-ew-border bg-ew-bg px-3 py-1 font-mono text-sm text-ew-text">{winSize} slots</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
