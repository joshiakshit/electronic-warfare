/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"Fira Code"', 'monospace'],
      },
      colors: {
        ew: {
          bg: 'rgb(var(--ew-bg) / <alpha-value>)',
          surface: 'rgb(var(--ew-surface) / <alpha-value>)',
          accent: 'rgb(var(--ew-accent) / <alpha-value>)',
          unscanned: 'rgb(var(--ew-unscanned) / <alpha-value>)',
          text: 'rgb(var(--ew-text) / <alpha-value>)',
          'text-secondary': 'rgb(var(--ew-text-secondary) / <alpha-value>)',
          'text-muted': 'rgb(var(--ew-text-muted) / <alpha-value>)',
          'text-dim': 'rgb(var(--ew-text-dim) / <alpha-value>)',
          'text-dimmer': 'rgb(var(--ew-text-dimmer) / <alpha-value>)',
          border: 'rgb(var(--ew-border) / <alpha-value>)',
          'border-subtle': 'rgb(var(--ew-border-subtle) / <alpha-value>)',
        }
      }
    },
  },
  plugins: [],
}
