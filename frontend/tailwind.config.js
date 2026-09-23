/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        soc: {
          bg:      '#02040a',
          surface: '#080e1a',
          card:    '#0d1526',
          border:  'rgba(255,255,255,0.07)',
          muted:   '#475569',
          text:    '#94a3b8',
          heading: '#e2e8f0',
        },
      },
      boxShadow: {
        'neon-red':   '0 0 30px rgba(239,68,68,0.15)',
        'neon-blue':  '0 0 30px rgba(59,130,246,0.15)',
        'neon-amber': '0 0 30px rgba(245,158,11,0.15)',
        'card':       '0 1px 3px rgba(0,0,0,0.5), 0 8px 24px rgba(0,0,0,0.3)',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      },
    },
  },
  plugins: [],
}
