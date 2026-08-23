import { useState, useEffect } from 'react';

const BOOT_LOGS = [
  "INITIALIZING SECURE TERMINAL...",
  "ESTABLISHING CONNECTION TO RF SENSORS... [OK]",
  "LOADING MACHINE LEARNING MODULES...",
  "> UCB1 AGENT INITIALIZED.",
  "> THOMPSON SAMPLING AGENT READY.",
  "ALIGNING POSTERIOR DISTRIBUTIONS... [OK]",
  "CALIBRATING WATERFALL SPECTRUM ANALYZER...",
  "SYSTEM ONLINE. AWAITING COMMAND."
];

export const BootSequence: React.FC<{ onComplete: () => void }> = ({ onComplete }) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    if (currentIndex < BOOT_LOGS.length) {
      const timer = setTimeout(() => {
        setLogs(prev => [...prev, BOOT_LOGS[currentIndex]]);
        setCurrentIndex(prev => prev + 1);
      }, Math.random() * 300 + 100);
      return () => clearTimeout(timer);
    } else {
      const timer = setTimeout(() => {
        onComplete();
      }, 800);
      return () => clearTimeout(timer);
    }
  }, [currentIndex, onComplete]);

  return (
    <div className="w-full h-screen bg-black flex flex-col p-8 font-mono text-ew-cyan crt text-sm md:text-base">
      {logs.map((log, i) => (
        <div key={i} className="mb-2 text-glow">{log}</div>
      ))}
      {currentIndex < BOOT_LOGS.length && (
        <div className="animate-pulse-fast text-glow">_</div>
      )}
    </div>
  );
};
