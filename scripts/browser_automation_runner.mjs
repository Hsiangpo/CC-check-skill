#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { chromium } from 'playwright';

const CHINA_FONTS = [
  'SimSun',
  'SimHei',
  'Microsoft YaHei',
  'PingFang SC',
  'Noto Sans CJK SC',
  'Source Han Sans SC',
];

async function collectJavascript(page) {
  await page.goto('about:blank', { waitUntil: 'domcontentloaded' });
  return page.evaluate(() => {
    const intl = Intl.DateTimeFormat().resolvedOptions();
    return {
      locale: intl.locale,
      timeZone: intl.timeZone,
      hourCycle: intl.hourCycle || '',
      calendar: intl.calendar || '',
      numberingSystem: intl.numberingSystem || '',
      userAgent: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages,
      platform: navigator.platform,
    };
  });
}

async function collectWebRtc(page) {
  await page.goto('about:blank', { waitUntil: 'domcontentloaded' });
  return page.evaluate(async () => {
    if (!window.RTCPeerConnection) {
      return { supported: false, localCandidates: [], publicCandidates: [] };
    }

    const candidates = [];
    const peer = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
    peer.createDataChannel('cc-check');

    peer.onicecandidate = (event) => {
      if (event.candidate?.candidate) {
        candidates.push(event.candidate.candidate);
      }
    };

    try {
      const offer = await peer.createOffer();
      await peer.setLocalDescription(offer);
      await new Promise((resolve) => setTimeout(resolve, 2500));
    } catch (error) {
      return {
        supported: true,
        error: error instanceof Error ? error.message : String(error),
        localCandidates: [],
        publicCandidates: [],
      };
    } finally {
      peer.close();
    }

    const ips = [];
    const regex = /([0-9]{1,3}(?:\.[0-9]{1,3}){3})/g;
    for (const candidate of candidates) {
      const matches = candidate.match(regex) || [];
      for (const ip of matches) {
        if (!ips.includes(ip)) {
          ips.push(ip);
        }
      }
    }

    const isPrivate = (ip) => (
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
      ip.startsWith('127.')
    );

    return {
      supported: true,
      localCandidates: ips.filter((ip) => isPrivate(ip)),
      publicCandidates: ips.filter((ip) => !isPrivate(ip)),
      candidateCount: candidates.length,
    };
  });
}

async function collectBrowserIp(page) {
  const endpoints = [
    ['ipify', 'https://api.ipify.org?format=json'],
    ['ifconfig', 'https://ifconfig.me/ip'],
    ['httpbin', 'https://httpbin.org/ip'],
  ];
  const results = {};

  for (const [name, url] of endpoints) {
    try {
      const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      const body = (await page.textContent('body'))?.trim() || '';
      if (!response?.ok() || !body) {
        continue;
      }
      if (name === 'ipify') {
        results[name] = JSON.parse(body).ip || '';
      } else if (name === 'httpbin') {
        results[name] = (JSON.parse(body).origin || '').split(',')[0].trim();
      } else {
        results[name] = body;
      }
    } catch {
      // 单个端点失败时继续其余端点。
    }
  }

  return { endpoints: results };
}

async function collectFonts(page) {
  await page.goto('about:blank', { waitUntil: 'domcontentloaded' });
  return page.evaluate((fontNames) => {
    const found = [];
    for (const font of fontNames) {
      try {
        if (document.fonts.check(`12px "${font}"`)) {
          found.push(font);
        }
      } catch {
        // 某些环境可能不支持特定字体检查，忽略即可。
      }
    }
    return { detectedFonts: found, checkedFonts: fontNames };
  }, CHINA_FONTS);
}

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

async function collectCanvas(page) {
  await page.goto('about:blank', { waitUntil: 'domcontentloaded' });
  const payload = await page.evaluate(() => {
    const render = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 280;
      canvas.height = 80;
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        return '';
      }
      ctx.textBaseline = 'top';
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = '#f60';
      ctx.fillRect(10, 10, 120, 24);
      ctx.fillStyle = '#069';
      ctx.fillText('cc-check-canvas', 14, 14);
      ctx.strokeStyle = 'rgba(120, 20, 160, 0.8)';
      ctx.beginPath();
      ctx.arc(210, 34, 18, 0, Math.PI * 2);
      ctx.stroke();
      return canvas.toDataURL();
    };
    const primary = render();
    const secondary = render();
    return {
      primary,
      secondary,
      dataUrlsMatch: primary === secondary,
    };
  });

  return {
    fingerprintHash: payload.primary ? sha256(payload.primary) : '',
    secondaryHash: payload.secondary ? sha256(payload.secondary) : '',
    dataUrlsMatch: payload.dataUrlsMatch,
  };
}

async function collectTlsPage(page) {
  await page.goto('https://browserleaks.com/tls', { waitUntil: 'domcontentloaded', timeout: 20000 });
  const text = await page.locator('body').innerText();
  return { text };
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const results = {};
  const executedTests = [];
  const errors = [];

  const tasks = [
    ['javascript', collectJavascript],
    ['webrtc', collectWebRtc],
    ['ip', collectBrowserIp],
    ['fonts', collectFonts],
    ['canvas', collectCanvas],
    ['tls', collectTlsPage],
  ];

  for (const [name, task] of tasks) {
    try {
      results[name] = await task(page);
      executedTests.push(name);
    } catch (error) {
      errors.push(`${name}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  await context.close();
  await browser.close();

  process.stdout.write(JSON.stringify({ ok: true, provider: 'playwright', executedTests, results, errors }));
}

main().catch((error) => {
  process.stderr.write(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
