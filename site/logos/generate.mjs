/**
 * Purple Wolf Logo Asset Generator
 *
 * Converts the green-background source logo into transparent source assets,
 * favicons, app icons, social cards, and utility background variants.
 */
import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import sharp from 'sharp';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const BRAND_NAME = 'Purple Wolf';
const TAGLINE = 'A fast, verifiable WAF for Traefik';
const SOURCE_FILE = 'purple-wolf-logo-green-background.png';
const SRC = path.resolve(__dirname, SOURCE_FILE);
const OUT_DIR = path.resolve(__dirname, 'generated');

const BRAND = {
  background: '#12081f',
  background2: '#21103c',
  purple: '#8b45f6',
  purpleLight: '#d8a8ff',
  ink: '#10061c',
  white: '#ffffff',
};

const FAVICON_SIZES = [16, 32, 48, 96, 180, 192, 512];

function distance(a, b) {
  const dr = a.r - b.r;
  const dg = a.g - b.g;
  const db = a.b - b.b;
  return Math.sqrt(dr * dr + dg * dg + db * db);
}

function averageColor(samples) {
  const totals = samples.reduce(
    (acc, color) => ({
      r: acc.r + color.r,
      g: acc.g + color.g,
      b: acc.b + color.b,
    }),
    { r: 0, g: 0, b: 0 },
  );

  return {
    r: Math.round(totals.r / samples.length),
    g: Math.round(totals.g / samples.length),
    b: Math.round(totals.b / samples.length),
  };
}

async function sampleKeyColor(inputPath) {
  const sampleSize = 24;
  const image = sharp(inputPath).ensureAlpha();
  const { width, height } = await image.metadata();

  const regions = [
    { left: 0, top: 0 },
    { left: width - sampleSize, top: 0 },
    { left: 0, top: height - sampleSize },
    { left: width - sampleSize, top: height - sampleSize },
  ];

  const samples = [];
  for (const region of regions) {
    const { data } = await sharp(inputPath)
      .extract({ ...region, width: sampleSize, height: sampleSize })
      .raw()
      .toBuffer({ resolveWithObject: true });

    for (let i = 0; i < data.length; i += 3) {
      samples.push({ r: data[i], g: data[i + 1], b: data[i + 2] });
    }
  }

  return averageColor(samples);
}

async function chromaKey(inputPath) {
  const key = await sampleKeyColor(inputPath);
  const { data, info } = await sharp(inputPath)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const innerDist = 56;
  const outerDist = 145;
  let transparentPixels = 0;
  let edgePixels = 0;

  for (let i = 0; i < data.length; i += 4) {
    const color = { r: data[i], g: data[i + 1], b: data[i + 2] };
    const dist = distance(color, key);

    const greenDominant = color.g > color.r + 20 && color.g > color.b + 20;

    if (dist <= innerDist) {
      data[i + 3] = 0;
      transparentPixels++;
    } else if (greenDominant) {
      if (dist < outerDist) {
        const alpha = Math.round(((dist - innerDist) / (outerDist - innerDist)) * 255);
        data[i + 3] = Math.max(0, Math.min(255, alpha));
      }
      data[i + 1] = Math.min(color.g, Math.max(color.r, color.b) + 12);
      edgePixels++;
    }
  }

  return {
    key,
    transparentPixels,
    edgePixels,
    image: sharp(data, { raw: { width: info.width, height: info.height, channels: 4 } }),
  };
}

async function metadataFor(bufferOrPath) {
  const metadata = await sharp(bufferOrPath).metadata();
  return {
    width: metadata.width,
    height: metadata.height,
    format: metadata.format,
    hasAlpha: Boolean(metadata.hasAlpha),
  };
}

async function alphaStats(buffer) {
  const { data, info } = await sharp(buffer).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  let transparent = 0;
  let opaque = 0;
  let partial = 0;

  for (let i = 3; i < data.length; i += 4) {
    if (data[i] === 0) transparent++;
    else if (data[i] === 255) opaque++;
    else partial++;
  }

  const pixels = info.width * info.height;
  return {
    transparent,
    opaque,
    partial,
    transparentRatio: Number((transparent / pixels).toFixed(4)),
    partialRatio: Number((partial / pixels).toFixed(4)),
  };
}

async function suppressGreenSpill(input) {
  const { data, info } = await sharp(input).ensureAlpha().raw().toBuffer({ resolveWithObject: true });

  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    if (data[i + 3] > 0 && g > r + 20 && g > b + 20) {
      data[i + 1] = Math.min(g, Math.max(r, b) + 12);
    }
  }

  return sharp(data, { raw: { width: info.width, height: info.height, channels: 4 } }).png().toBuffer();
}

async function greenFringeStats(input) {
  const { data } = await sharp(input).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  let suspicious = 0;
  let visible = 0;

  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    const a = data[i + 3];
    if (a > 20) {
      visible++;
      if (g > r + 32 && g > b + 32) {
        suspicious++;
      }
    }
  }

  return { suspicious, visible };
}

function svgText({ width, height, text, y, size, weight = 700, fill = BRAND.white, opacity = 1 }) {
  const escaped = text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

  return Buffer.from(`<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
    <text x="${width / 2}" y="${y}" text-anchor="middle"
      font-family="Afacad Flux, Inter, system-ui, -apple-system, BlinkMacSystemFont, sans-serif"
      font-size="${size}" font-weight="${weight}"
      fill="${fill}" opacity="${opacity}">${escaped}</text>
  </svg>`);
}

function brandedSquareSvg(size) {
  const radius = Math.round(size * 0.19);

  return Buffer.from(`<svg width="${size}" height="${size}" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${BRAND.purple}"/>
        <stop offset="48%" stop-color="#6e31dd"/>
        <stop offset="100%" stop-color="${BRAND.ink}"/>
      </linearGradient>
    </defs>
    <rect width="${size}" height="${size}" rx="${radius}" fill="url(#bg)"/>
  </svg>`);
}

function ogBackgroundSvg(width, height) {
  return Buffer.from(`<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${BRAND.background}"/>
        <stop offset="54%" stop-color="${BRAND.background2}"/>
        <stop offset="100%" stop-color="#35125b"/>
      </linearGradient>
      <radialGradient id="glow" cx="50%" cy="35%" r="48%">
        <stop offset="0%" stop-color="${BRAND.purpleLight}" stop-opacity="0.22"/>
        <stop offset="100%" stop-color="${BRAND.purpleLight}" stop-opacity="0"/>
      </radialGradient>
    </defs>
    <rect width="${width}" height="${height}" fill="url(#bg)"/>
    <ellipse cx="${width / 2}" cy="${height * 0.34}" rx="420" ry="240" fill="url(#glow)"/>
  </svg>`);
}

async function writePng(name, input) {
  const outputPath = path.join(OUT_DIR, name);
  const sanitized = await suppressGreenSpill(input);
  await sharp(sanitized).png({ compressionLevel: 9, adaptiveFiltering: true }).toFile(outputPath);
  return { name, path: outputPath, ...(await metadataFor(outputPath)) };
}

async function createLogoOnBackground(name, transparentLogo, background) {
  const size = 1024;
  const logo = await sharp(transparentLogo)
    .resize(Math.round(size * 0.86), Math.round(size * 0.86), { fit: 'inside' })
    .png()
    .toBuffer();
  const logoMeta = await sharp(logo).metadata();

  return writePng(
    name,
    await sharp({
      create: {
        width: size,
        height: size,
        channels: 4,
        background,
      },
    })
      .composite([
        {
          input: logo,
          left: Math.round((size - logoMeta.width) / 2),
          top: Math.round((size - logoMeta.height) / 2),
        },
      ])
      .png()
      .toBuffer(),
  );
}

async function validateGeneratedAssets(assets, logoBuffer, sourceMeta, chromaStats) {
  const logoStats = await alphaStats(logoBuffer);
  const byName = new Map(assets.map((asset) => [asset.name, asset]));

  const requiredDimensions = {
    'favicon-16.png': [16, 16],
    'favicon-32.png': [32, 32],
    'favicon-48.png': [48, 48],
    'favicon-96.png': [96, 96],
    'apple-touch-icon.png': [180, 180],
    'icon-192.png': [192, 192],
    'icon-512.png': [512, 512],
    'favicon-branded-512.png': [512, 512],
    'og-image.png': [1200, 630],
    'logo-on-white.png': [1024, 1024],
    'logo-on-dark.png': [1024, 1024],
  };

  for (const [name, [width, height]] of Object.entries(requiredDimensions)) {
    const asset = byName.get(name);
    if (!asset) {
      throw new Error(`Missing generated asset: ${name}`);
    }
    if (asset.width !== width || asset.height !== height) {
      throw new Error(`${name} is ${asset.width}x${asset.height}, expected ${width}x${height}`);
    }
  }

  if (sourceMeta.width !== sourceMeta.height) {
    throw new Error(`Source logo must be square, got ${sourceMeta.width}x${sourceMeta.height}`);
  }
  if (chromaStats.transparentPixels < sourceMeta.width * sourceMeta.height * 0.15) {
    throw new Error('Chroma-key removed too few pixels; source green may not have been extracted.');
  }
  if (logoStats.transparentRatio < 0.2) {
    throw new Error(`Transparent logo has too little transparency: ${logoStats.transparentRatio}`);
  }

  for (const name of ['logo-transparent.png', 'logo-square-transparent.png', 'icon-512.png', 'og-image.png']) {
    const stats = await greenFringeStats(byName.get(name).path);
    if (stats.suspicious > 0) {
      throw new Error(`${name} has ${stats.suspicious} visible green-fringe pixels`);
    }
  }

  return { logoStats };
}

async function main() {
  console.log(`${BRAND_NAME} Logo Generator\n`);
  await rm(OUT_DIR, { recursive: true, force: true });
  await mkdir(OUT_DIR, { recursive: true });

  const sourceMeta = await metadataFor(SRC);
  console.log(`1. Reading ${SOURCE_FILE} (${sourceMeta.width}x${sourceMeta.height})`);

  console.log('2. Removing green-screen background...');
  const keyed = await chromaKey(SRC);
  const transparentSourceBuffer = await keyed.image.png().toBuffer();
  console.log(
    `   key rgb(${keyed.key.r}, ${keyed.key.g}, ${keyed.key.b}); removed ${keyed.transparentPixels.toLocaleString()} pixels`,
  );

  const logoBuffer = await sharp(transparentSourceBuffer).trim({ threshold: 8 }).png().toBuffer();
  const squareLogoBuffer = await sharp(logoBuffer)
    .resize(1024, 1024, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
    .png()
    .toBuffer();
  const iconBuffer = await sharp(squareLogoBuffer)
    .resize(1024, 1024, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
    .png()
    .toBuffer();

  console.log('3. Writing transparent source assets...');
  const assets = [];
  assets.push(await writePng('logo-transparent.png', logoBuffer));
  assets.push(await writePng('logo-square-transparent.png', squareLogoBuffer));
  assets.push(await writePng('icon-transparent.png', iconBuffer));

  console.log('4. Writing favicons and app icons...');
  for (const size of FAVICON_SIZES) {
    const fileName =
      size === 180 ? 'apple-touch-icon.png' : size >= 192 ? `icon-${size}.png` : `favicon-${size}.png`;
    const resized = await sharp(iconBuffer)
      .resize(size, size, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toBuffer();
    assets.push(await writePng(fileName, resized));
  }

  console.log('5. Writing branded favicons...');
  const brandedBaseSize = 512;
  const brandedIcon = await sharp(iconBuffer)
    .resize(432, 432, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
    .png()
    .toBuffer();
  const brandedIconMeta = await sharp(brandedIcon).metadata();
  const brandedBase = await sharp(brandedSquareSvg(brandedBaseSize))
    .composite([
      {
        input: brandedIcon,
        left: Math.round((brandedBaseSize - brandedIconMeta.width) / 2),
        top: Math.round((brandedBaseSize - brandedIconMeta.height) / 2),
      },
    ])
    .png()
    .toBuffer();

  for (const size of [16, 32, 48, 96, 180, 192, 512]) {
    const name = `favicon-branded-${size}.png`;
    const resized = await sharp(brandedBase).resize(size, size).png().toBuffer();
    assets.push(await writePng(name, resized));
  }

  console.log('6. Writing social and utility variants...');
  const ogWidth = 1200;
  const ogHeight = 630;
  const ogIcon = await sharp(iconBuffer).resize(360, 360, { fit: 'contain' }).png().toBuffer();
  const ogIconMeta = await sharp(ogIcon).metadata();
  const og = await sharp(ogBackgroundSvg(ogWidth, ogHeight))
    .composite([
      { input: ogIcon, left: Math.round((ogWidth - ogIconMeta.width) / 2), top: 44 },
      { input: svgText({ width: ogWidth, height: 68, text: BRAND_NAME, y: 50, size: 48 }), left: 0, top: 430 },
      {
        input: svgText({ width: ogWidth, height: 36, text: TAGLINE, y: 23, size: 20, weight: 500, opacity: 0.7 }),
        left: 0,
        top: 492,
      },
    ])
    .png()
    .toBuffer();
  assets.push(await writePng('og-image.png', og));
  assets.push(await createLogoOnBackground('logo-on-white.png', squareLogoBuffer, { r: 255, g: 255, b: 255, alpha: 255 }));
  assets.push(await createLogoOnBackground('logo-on-dark.png', squareLogoBuffer, { r: 18, g: 8, b: 31, alpha: 255 }));

  console.log('7. Validating generated assets...');
  const validation = await validateGeneratedAssets(assets, logoBuffer, sourceMeta, keyed);
  const manifest = {
    brandName: BRAND_NAME,
    tagline: TAGLINE,
    source: SOURCE_FILE,
    sourceMetadata: sourceMeta,
    generatedAt: new Date().toISOString(),
    chromaKey: {
      sampledKey: keyed.key,
      transparentPixels: keyed.transparentPixels,
      edgePixels: keyed.edgePixels,
    },
    validation,
    assets: assets.map(({ name, width, height, format, hasAlpha }) => ({ name, width, height, format, hasAlpha })),
  };
  await writeFile(path.join(OUT_DIR, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  assets.push({ name: 'manifest.json', path: path.join(OUT_DIR, 'manifest.json'), format: 'json' });

  for (const asset of assets) {
    if (asset.width && asset.height) {
      console.log(`   -> ${asset.name} (${asset.width}x${asset.height})`);
    } else {
      console.log(`   -> ${asset.name}`);
    }
  }

  console.log('\nGeneration complete.');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
