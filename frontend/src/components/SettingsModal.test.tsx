import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { SettingsModal } from './SettingsModal'

describe('SettingsModal', () => {
  it('renders scanner controls when opened on scanner settings', () => {
    const markup = renderToStaticMarkup(
      <SettingsModal
        isOpen
        initialTab="Scanner"
        onClose={vi.fn()}
        scenarios={['periodic_radar']}
        schedulers={['ucb1']}
        scenario="periodic_radar"
        setScenario={vi.fn()}
        scheduler="ucb1"
        setScheduler={vi.fn()}
        seed={42}
        setSeed={vi.fn()}
        k={1}
        setK={vi.fn()}
        maxBands={16}
        winSize={40}
        setWinSize={vi.fn()}
        theme="dark"
        setTheme={vi.fn()}
      />,
    )

    expect(markup).toContain('RF scenario')
    expect(markup).toContain('Scheduling algorithm')
    expect(markup).toContain('Seed')
    expect(markup).toContain('Channel bands')
  })

  it('keeps display settings focused on appearance and chart density', () => {
    const markup = renderToStaticMarkup(
      <SettingsModal
        isOpen
        initialTab="Display"
        onClose={vi.fn()}
        scenarios={['periodic_radar']}
        schedulers={['ucb1']}
        scenario="periodic_radar"
        setScenario={vi.fn()}
        scheduler="ucb1"
        setScheduler={vi.fn()}
        seed={42}
        setSeed={vi.fn()}
        k={1}
        setK={vi.fn()}
        maxBands={16}
        winSize={40}
        setWinSize={vi.fn()}
        theme="dark"
        setTheme={vi.fn()}
      />,
    )

    expect(markup).toContain('Appearance')
    expect(markup).toContain('Chart viewport size')
    expect(markup).not.toContain('Sidebar behavior')
  })
})
