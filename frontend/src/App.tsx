import { useState, useEffect } from 'react';
import { TerminalDashboard } from './components/TerminalDashboard';

type Theme = 'dark' | 'light';

function App() {
  const [scenarios, setScenarios] = useState<string[]>([]);
  const [schedulers, setSchedulers] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [winSize, setWinSize] = useState(40);
  const [theme, setTheme] = useState<Theme>(() => {
    return (localStorage.getItem('ew-theme') as Theme) || 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ew-theme', theme);
  }, [theme]);

  useEffect(() => {
    const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    Promise.all([
      fetch(`${apiBase}/api/scenarios`).then(r => r.json()),
      fetch(`${apiBase}/api/schedulers`).then(r => r.json())
    ]).then(([scenData, schedData]) => {
      setScenarios(scenData.scenarios);
      setSchedulers(schedData.schedulers);
      setLoading(false);
    }).catch(err => {
      console.error(err);
      setError('Failed to connect to backend. Is the API server running?');
      setLoading(false);
    });
  }, []);

  if (loading) {
    return <div className="h-screen w-full flex items-center justify-center bg-ew-bg text-ew-accent font-mono text-xl tracking-wider">FETCHING E-WAVE TELEMETRY...</div>;
  }

  if (error) {
    return <div className="h-screen w-full flex items-center justify-center bg-ew-bg text-[#ef4444] font-mono text-xl tracking-wider">{error}</div>;
  }

  return (
    <TerminalDashboard
      scenarios={scenarios}
      schedulers={schedulers}
      winSize={winSize}
      setWinSize={setWinSize}
      theme={theme}
      setTheme={setTheme}
    />
  );
}

export default App;
