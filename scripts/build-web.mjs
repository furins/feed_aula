import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(scriptDir, '..');
const distDir = join(rootDir, 'dist');

const desktopSource = join(rootDir, 'desktop.html');
const scanSource = join(rootDir, 'scan.html');
const configSource = join(rootDir, 'config.html');
const identitiesSource = join(rootDir, 'identities.html');
const appIconSource = join(rootDir, 'app-icon.png');

const vendorSource = join(rootDir, 'node_modules', 'js-aruco2', 'src');
const vendorTarget = join(distDir, 'vendor', 'js-aruco2');

const replacements = new Map([
  [
    'https://cdn.jsdelivr.net/npm/js-aruco2@2.0.0/src/cv.js',
    'vendor/js-aruco2/cv.js'
  ],
  [
    'https://cdn.jsdelivr.net/npm/js-aruco2@2.0.0/src/aruco.js',
    'vendor/js-aruco2/aruco.js'
  ],
  [
    'https://cdn.jsdelivr.net/npm/js-aruco2@2.0.0/src/dictionaries/aruco_4x4_1000.js',
    'vendor/js-aruco2/dictionaries/aruco_4x4_1000.js'
  ]
]);

async function build() {
  await rm(distDir, { recursive: true, force: true });
  await mkdir(vendorTarget, { recursive: true });

  const [desktopHtml, scanHtml, configHtml, identitiesHtml] = await Promise.all([
    readFile(desktopSource, 'utf8'),
    readFile(scanSource, 'utf8'),
    readFile(configSource, 'utf8'),
    readFile(identitiesSource, 'utf8')
  ]);

  let offlineScan = scanHtml;
  for (const [remoteUrl, localUrl] of replacements) {
    if (!offlineScan.includes(remoteUrl)) {
      throw new Error(`Dipendenza attesa non trovata in scan.html: ${remoteUrl}`);
    }
    offlineScan = offlineScan.replaceAll(remoteUrl, localUrl);
  }

  await Promise.all([
    writeFile(join(distDir, 'index.html'), desktopHtml, 'utf8'),
    writeFile(join(distDir, 'scan.html'), offlineScan, 'utf8'),
    writeFile(join(distDir, 'config.html'), configHtml, 'utf8'),
    writeFile(join(distDir, 'identities.html'), identitiesHtml, 'utf8'),
    cp(appIconSource, join(distDir, 'app-icon.png')),
    cp(join(vendorSource, 'cv.js'), join(vendorTarget, 'cv.js')),
    cp(join(vendorSource, 'aruco.js'), join(vendorTarget, 'aruco.js')),
    cp(
      join(vendorSource, 'dictionaries', 'aruco_4x4_1000.js'),
      join(vendorTarget, 'dictionaries', 'aruco_4x4_1000.js')
    )
  ]);

  const markersSource = join(rootDir, 'markers');
  const markersTarget = join(distDir, 'markers');
  await cp(markersSource, markersTarget, { recursive: true });

  console.log('FEED desktop frontend pronto in dist/ (riconoscimento marker offline).');
}

build().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
