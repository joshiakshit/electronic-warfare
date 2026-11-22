export const themes = [
  { id: 'slate-cyan', label: 'Slate + Cyan' },
  { id: 'graphite-amber', label: 'Graphite + Amber' },
  { id: 'ink-violet', label: 'Ink + Violet' },
] as const;

export type Theme = (typeof themes)[number]['id'];

const defaultTheme = themes[0].id;
const themeKey = 'ewave.theme';

export function readTheme(): Theme {
  try {
    const saved = localStorage.getItem(themeKey);
    return themes.find(theme => theme.id === saved)?.id ?? defaultTheme;
  } catch {
    return defaultTheme;
  }
}

export function rememberTheme(theme: Theme): void {
  try {
    localStorage.setItem(themeKey, theme);
  } catch {
    // The theme still applies for the current visit when storage is unavailable.
  }
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  root.dataset.theme = theme;
  const canvas = getComputedStyle(root).getPropertyValue('--canvas').trim();
  if (canvas) document.querySelector('meta[name="theme-color"]')?.setAttribute('content', canvas);
}
