// Builds the frontend, copies it into backend/static_frontend (mirroring
// what backend/Dockerfile does at image build time), then starts the real
// FastAPI backend which serves that build as one origin -- the same shape
// the app runs in production. Used as Playwright's webServer command so
// e2e tests exercise the real built UI talking to the real API, not a dev
// proxy standing in for it.
import { spawn } from "node:child_process";
import { cpSync, existsSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDir = path.resolve(__dirname, "..");
const backendDir = path.resolve(frontendDir, "..", "backend");
const staticDir = path.join(backendDir, "static_frontend");

function run(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: "inherit", shell: true });
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${args.join(" ")} exited with code ${code}`));
    });
  });
}

await run("npm", ["run", "build"], frontendDir);

if (existsSync(staticDir)) rmSync(staticDir, { recursive: true, force: true });
cpSync(path.join(frontendDir, "dist"), staticDir, { recursive: true });

const python = process.env.PYTHON ?? (process.platform === "win32" ? "python" : "python3");
const uvicorn = spawn(python, ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"], {
  cwd: backendDir,
  stdio: "inherit",
});

const shutdown = () => {
  uvicorn.kill();
  process.exit(0);
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
uvicorn.on("exit", (code) => process.exit(code ?? 0));
