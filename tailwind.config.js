/** @type {import('tailwindcss').Config} */
module.exports = {
  // Scan templates AND Go files: some utility class strings (nav links, meter
  // colours) are emitted from Go helpers in internal/web, so they must be
  // scanned too or Tailwind would purge them.
  content: [
    "./internal/web/templates/**/*.html",
    "./internal/web/**/*.go",
    "./internal/domains/**/*.go",
    // The file explorer + domains picker build DOM (and class strings) in JS.
    "./internal/web/static/files.js",
    "./internal/web/static/domains.js",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
