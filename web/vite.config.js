import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During development (npm run dev) the page runs on :5173 and API calls are
// forwarded to the FastAPI server on :8000. After "npm run build", FastAPI
// serves the built files itself, so only one server is needed.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8000" },
  },
  build: { outDir: "dist", emptyOutDir: true },
});
