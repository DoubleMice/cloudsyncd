#!/usr/bin/env node
// Add files/directories to shared/. Defaults to HARD LINKS (same inode, zero
// extra disk space) and falls back to a byte copy when hard-linking is not
// possible (e.g. source on a different filesystem). Use --copy to force copies.

const fs = require('fs');
const path = require('path');

const sharedDir = path.join(__dirname, 'shared');
const args = process.argv.slice(2);
const forceCopy = args.includes('--copy');

if (args.length === 0 || (args.length === 1 && forceCopy)) {
  console.log('用法:');
  console.log('  node share.js file1.pdf dir/ file2.txt  — 加入 shared/（默认硬链接，省空间）');
  console.log('  node share.js --copy file.pdf           — 强制复制一份（旧行为）');
  console.log('  node share.js --list                    — 列出共享文件');
  console.log('  node share.js --clear                   — 清空 shared/');
  process.exit(0);
}

// --list: show current shared files
if (args[0] === '--list') {
  if (!fs.existsSync(sharedDir)) {
    console.log('shared/ 目录为空');
    process.exit(0);
  }
  const walk = (dir, prefix = '') => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name.startsWith('.')) continue;
      const rel = prefix ? `${prefix}/${e.name}` : e.name;
      if (e.isDirectory()) {
        walk(path.join(dir, e.name), rel);
      } else {
        const sz = fs.statSync(path.join(dir, e.name)).size;
        console.log(`  ${rel}  (${formatSize(sz)})`);
      }
    }
  };
  walk(sharedDir);
  process.exit(0);
}

// --clear: remove all files in shared/
if (args[0] === '--clear') {
  if (fs.existsSync(sharedDir)) {
    fs.rmSync(sharedDir, { recursive: true });
  }
  fs.mkdirSync(sharedDir, { recursive: true });
  console.log('shared/ 已清空');
  process.exit(0);
}

// ============ Add to shared/ ============

fs.mkdirSync(sharedDir, { recursive: true });

// Place a single file at dest. Prefers a hard link (zero space, same inode);
// copies on failure (EXDEV = cross-filesystem). Returns 'link' | 'copy'.
function addFile(src, dest) {
  if (fs.existsSync(dest)) fs.rmSync(dest, { force: true });
  if (forceCopy) {
    fs.copyFileSync(src, dest);
    return 'copy';
  }
  try {
    fs.linkSync(src, dest);
    return 'link';
  } catch (e) {
    fs.copyFileSync(src, dest);
    return e.code === 'EXDEV' ? 'copy(exdev)' : 'copy';
  }
}

// Recursively mirror a directory: recreate subdirs, hard-link each file
// (per-file copy fallback). Returns { link, copy } counts.
function addDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  const counts = { link: 0, copy: 0 };
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    // statSync follows symlinks at the source so we mirror real content.
    const st = fs.statSync(s);
    if (st.isDirectory()) {
      const sub = addDir(s, d);
      counts.link += sub.link;
      counts.copy += sub.copy;
    } else if (st.isFile()) {
      counts[addFile(s, d) === 'link' ? 'link' : 'copy']++;
    }
  }
  return counts;
}

let fileCount = 0;
let linked = 0;
let copied = 0;

for (const src of args.filter((a) => a !== '--copy')) {
  const resolved = path.resolve(src);
  if (!fs.existsSync(resolved)) {
    console.error(`  跳过: ${src} (不存在)`);
    continue;
  }
  const dest = path.join(sharedDir, path.basename(resolved));
  const stat = fs.statSync(resolved);

  if (stat.isDirectory()) {
    const c = addDir(resolved, dest);
    fileCount += c.link + c.copy;
    linked += c.link;
    copied += c.copy;
    console.log(`  + ${path.basename(resolved)}/  (link ${c.link}, copy ${c.copy})`);
  } else {
    const mode = addFile(resolved, dest);
    fileCount++;
    if (mode === 'link') linked++; else copied++;
    console.log(`  + ${path.basename(resolved)}  [${mode}]`);
  }
}

console.log(`共加入 ${fileCount} 个文件到 shared/（硬链接 ${linked}，复制 ${copied}）`);

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
