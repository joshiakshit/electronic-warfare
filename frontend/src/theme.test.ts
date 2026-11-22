import { afterEach, describe, expect, it, vi } from 'vitest';
import { readTheme, rememberTheme, themes } from './theme';

afterEach(() => vi.unstubAllGlobals());

describe('theme preference', () => {
  it('defaults to Slate + Cyan for missing and unknown preferences', () => {
    const getItem = vi.fn().mockReturnValueOnce(null).mockReturnValueOnce('old-theme');
    vi.stubGlobal('localStorage', { getItem });

    expect(readTheme()).toBe('slate-cyan');
    expect(readTheme()).toBe('slate-cyan');
  });

  it('restores each theme after it is saved', () => {
    const preferences = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => preferences.get(key) ?? null,
      setItem: (key: string, value: string) => preferences.set(key, value),
    });

    for (const { id } of themes) {
      rememberTheme(id);
      expect(readTheme()).toBe(id);
    }
  });

  it('handles unavailable storage', () => {
    const unavailable = () => { throw new Error('Storage denied'); };
    vi.stubGlobal('localStorage', { getItem: unavailable, setItem: unavailable });

    expect(readTheme()).toBe('slate-cyan');
    expect(() => rememberTheme('ink-violet')).not.toThrow();
  });
});
