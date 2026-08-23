import { useState, useEffect } from 'react';
import { TerminalDashboard } from './components/TerminalDashboard';

function App() {
  const [scenarios, setScenarios] = useState<string[]>([]);
  const [schedulers, setSchedulers] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [winSize, setWinSize] = useState(40);

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
    return <div className="h-screen w-full flex items-center justify-center bg-[#000000] text-[#1ed760] font-mono text-xl tracking-wider">FETCHING E-WAVE TELEMETRY...</div>;
  }

  if (error) {
    return <div className="h-screen w-full flex items-center justify-center bg-[#000000] text-[#ef4444] font-mono text-xl tracking-wider">{error}</div>;
  }

  return (
    <TerminalDashboard 
      scenarios={scenarios} 
      schedulers={schedulers} 
      winSize={winSize}
      setWinSize={setWinSize}
    />
  );
}

export default App;
