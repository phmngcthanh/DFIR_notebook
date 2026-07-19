import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        index: "index.html",
      },
      output: {
        manualChunks(id) {
          if (id.includes('/node_modules/cytoscape/')) return 'cytoscape';
          if (id.includes('/node_modules/react-cytoscapejs/')) return 'react-cytoscape';
          if (
            id.includes('/node_modules/cytoscape-dagre/') ||
            id.includes('/node_modules/dagre/') ||
            id.includes('/node_modules/graphlib/')
          ) return 'topology-layout';
          if (id.includes('/node_modules/vis-timeline/')) return 'vis-timeline';
          if (id.includes('/node_modules/vis-data/')) return 'vis-data';
          if (id.includes('/node_modules/vis-util/')) return 'vis-util';
          if (id.includes('/node_modules/moment/')) return 'moment';
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    host: true,
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
