import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        canvas: '#141618',
        surface: {
          subtle: '#191C1F',
          muted: '#202428',
        },
        border: {
          subtle: '#292E35',
        },
        accent: {
          DEFAULT: '#5E748B',
          hover: '#6E859E',
          muted: '#36424E',
        },
        text: {
          primary: '#E1E4EA',
          secondary: '#8B939E',
        },
      },
      fontFamily: {
        heading: ['var(--font-heading)', 'sans-serif'],
        body: ['var(--font-body)', 'sans-serif'],
      },
      spacing: {
        '2': '8px',
        '4': '16px',
        '6': '24px',
        '8': '32px',
        '12': '48px',
        '16': '64px',
      },
    },
  },
  plugins: [],
};

export default config;