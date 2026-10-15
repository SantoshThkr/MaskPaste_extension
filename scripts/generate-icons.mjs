// Renders the MaskPaste toolbar icons (a masked "•••" field on an indigo tile)
// to PNG with no dependencies. Run: npm run icons
//
// Shapes are drawn with signed-distance functions and 6×6 supersampling, then
// written as RGBA PNGs using node:zlib.

import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const OUT_DIR = fileURLToPath(new URL('../extension/icons/', import.meta.url));
const SIZES = [16, 32, 48, 128];
const SAMPLES = 6;

const TOP = [99, 102, 241]; // #6366F1
const BOTTOM = [67, 56, 202]; // #4338CA
const WHITE = [255, 255, 255];

function roundedRect(x, y, cx, cy, halfW, halfH, r) {
  const qx = Math.abs(x - cx) - halfW + r;
  const qy = Math.abs(y - cy) - halfH + r;
  return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r;
}

/** Colour at a point in unit coordinates, or null when transparent. */
function shade(x, y, size) {
  // Small icons get a slightly bigger field and dots so they stay legible.
  const small = size <= 16;
  if (roundedRect(x, y, 0.5, 0.5, 0.5, 0.5, 0.22) > 0) return null;
  const t = (x + y) / 2;
  const tile = TOP.map((c, i) => Math.round(c + (BOTTOM[i] - c) * t));

  const pillHalfW = small ? 0.4 : 0.36;
  const pillHalfH = small ? 0.19 : 0.165;
  if (roundedRect(x, y, 0.5, 0.5, pillHalfW, pillHalfH, pillHalfH) > 0) return tile;

  const dotR = small ? 0.075 : 0.06;
  const gap = small ? 0.2 : 0.155;
  for (const dx of [-gap, 0, gap]) {
    if (Math.hypot(x - (0.5 + dx), y - 0.5) <= dotR) return BOTTOM;
  }
  return WHITE;
}

function render(size) {
  const pixels = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      for (let sy = 0; sy < SAMPLES; sy += 1) {
        for (let sx = 0; sx < SAMPLES; sx += 1) {
          const color = shade((px + (sx + 0.5) / SAMPLES) / size, (py + (sy + 0.5) / SAMPLES) / size, size);
          if (!color) continue;
          r += color[0];
          g += color[1];
          b += color[2];
          a += 1;
        }
      }
      const i = (py * size + px) * 4;
      if (a > 0) {
        pixels[i] = Math.round(r / a);
        pixels[i + 1] = Math.round(g / a);
        pixels[i + 2] = Math.round(b / a);
        pixels[i + 3] = Math.round((a / (SAMPLES * SAMPLES)) * 255);
      }
    }
  }
  return pixels;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

function encodePng(size, rgba) {
  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y += 1) rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

mkdirSync(OUT_DIR, { recursive: true });
for (const size of SIZES) {
  const file = new URL(`icon-${size}.png`, `file://${OUT_DIR}`);
  writeFileSync(file, encodePng(size, render(size)));
  console.log(`wrote extension/icons/icon-${size}.png`);
}
