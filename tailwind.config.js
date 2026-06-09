/** Tailwind config — compiled to static/css/app.css via the standalone CLI.
 *  Build:  ./tailwindcss.exe -c tailwind.config.js -i static/css/tailwind-input.css -o static/css/app.css --minify
 */
module.exports = {
  content: ["./templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        border:      "var(--border)",
        input:       "var(--input)",
        ring:        "var(--ring)",
        background:  "var(--background)",
        foreground:  "var(--foreground)",
        primary:     { DEFAULT: "var(--primary)",     foreground: "var(--primary-foreground)" },
        secondary:   { DEFAULT: "var(--secondary)",   foreground: "var(--secondary-foreground)" },
        destructive: { DEFAULT: "var(--destructive)", foreground: "var(--destructive-foreground)" },
        muted:       { DEFAULT: "var(--muted)",       foreground: "var(--muted-foreground)" },
        accent:      { DEFAULT: "var(--accent)",      foreground: "var(--accent-foreground)" },
        card:        { DEFAULT: "var(--card)",        foreground: "var(--card-foreground)" },
      },
      borderRadius: {
        xl: "calc(var(--radius) + 4px)",
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      boxShadow: {
        xs: "0 1px 2px 0 rgb(0 0 0 / 0.05)",
        sm: "0 1px 3px 0 rgb(0 0 0 / 0.08), 0 1px 2px -1px rgb(0 0 0 / 0.08)",
      },
    },
  },
  safelist: [
    "bg-red-600","bg-orange-500","bg-amber-500","bg-blue-600","bg-sky-600","bg-emerald-600",
    "text-red-600","text-orange-600","text-amber-600","text-emerald-600","text-blue-600","text-sky-600",
  ],
};
