import { build } from 'esbuild';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const dir = fileURLToPath(new URL('.', import.meta.url));
const output = await build({
  absWorkingDir: dir,
  entryPoints: { dashboard: 'src/main.jsx' },
  outdir: 'dist',
  jsx: 'automatic',
  bundle: true,
  minify: true,
  format: 'iife',
  target: 'es2022',
  legalComments: 'inline',
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  write: false,
});
const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const entry = '<script type="module" src="/src/main.jsx"></script>';
  await mkdir(new URL('./dist/', import.meta.url), { recursive: true });
  for (const file of output.outputFiles) await writeFile(file.path, file.contents);
  const page = html.replace('</head>', '<link rel="stylesheet" href="/dashboard.css" />\n</head>').replace(entry, '<script src="/dashboard.js"></script>');
  await writeFile(new URL('./dist/index.html', import.meta.url), page);

await copyFile(new URL('../scripts/Connect-Server.ps1', import.meta.url), new URL('./dist/Connect-Server.ps1', import.meta.url));
