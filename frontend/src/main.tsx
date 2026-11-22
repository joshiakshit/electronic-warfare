import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './ui';
import { applyTheme, readTheme } from './theme';
import './style.css';

const initialTheme = readTheme();
applyTheme(initialTheme);

createRoot(document.getElementById('root')!).render(
  <React.StrictMode><App initialTheme={initialTheme} /></React.StrictMode>,
);
