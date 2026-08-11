import { defineConfig } from "vite";

export default defineConfig({
  server: {
    allowedHosts: [".ngrok.dev"]
  },
  plugins: [{
    name: "risk-navigator-tool-aliases",
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (!req.url) {
          next();
          return;
        }
        const [pathname, query = ""] = req.url.split("?");
        const suffix = query ? `?${query}` : "";
        if (pathname === "/tools/risk-navigator.html") {
          req.url = `/tool/risk-navigator.html${suffix}`;
        } else if (pathname === "/tools/manifest.json") {
          req.url = `/tool/manifest.json${suffix}`;
        } else if (pathname.startsWith("/tools/assets/")) {
          req.url = `/tool/assets/${pathname.slice("/tools/assets/".length)}${suffix}`;
        }
        next();
      });
    }
  }
  ]
});
