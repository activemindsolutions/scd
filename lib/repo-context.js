'use strict';

/**
 * lib/repo-context.js
 *
 * Reads project manifest files to build a repo context snapshot.
 * Context is used locally for smarter rule targeting and sent to
 * scd-server for dependency tracking, compliance reports, and
 * future intel (CVE matching) features.
 *
 * Supported manifests:
 *   JavaScript/TypeScript: package.json
 *   Python:               requirements.txt, pyproject.toml
 *   PHP:                  composer.json
 *   .NET:                 *.csproj
 *
 * Storage: ~/.scd/repos/{repoId}/repo-context.json
 * Updated: at each scan, only if content changed.
 * Server:  sent as repo_context event via push-queue after scan.
 */

const fs   = require('fs');
const path = require('path');

function parsePackageJson(filePath) {
  try {
    const pkg  = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const deps = {};
    for (const [n, v] of Object.entries(pkg.dependencies    || {})) deps[n] = { version: v, dev: false };
    for (const [n, v] of Object.entries(pkg.devDependencies || {})) deps[n] = { version: v, dev: true  };

    const keys = Object.keys(pkg.dependencies || {});
    const frameworks = [];
    if (keys.includes('express'))    frameworks.push('express');
    if (keys.includes('fastify'))    frameworks.push('fastify');
    if (keys.includes('koa'))        frameworks.push('koa');
    if (keys.includes('next'))       frameworks.push('next');
    if (keys.includes('react'))      frameworks.push('react');
    if (keys.includes('vue'))        frameworks.push('vue');
    if (keys.some(k => k.startsWith('@nestjs'))) frameworks.push('nestjs');
    if (keys.includes('typeorm'))    frameworks.push('typeorm');
    if (keys.includes('sequelize'))  frameworks.push('sequelize');
    if (keys.includes('mongoose'))   frameworks.push('mongoose');
    if (keys.includes('jsonwebtoken')) frameworks.push('jsonwebtoken');

    return { language: 'javascript', manifest: 'package.json',
             name: pkg.name || null, version: pkg.version || null, frameworks, dependencies: deps };
  } catch { return null; }
}

function parseRequirementsTxt(filePath) {
  try {
    const deps = {};
    for (const line of fs.readFileSync(filePath, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t || t.startsWith('#') || t.startsWith('-')) continue;
      const m = t.match(/^([A-Za-z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+)?/);
      if (m) deps[m[1].toLowerCase()] = { version: m[2]?.trim() || '*', dev: false };
    }
    const keys = Object.keys(deps);
    const frameworks = [];
    if (keys.includes('flask'))      frameworks.push('flask');
    if (keys.includes('django'))     frameworks.push('django');
    if (keys.includes('fastapi'))    frameworks.push('fastapi');
    if (keys.includes('sqlalchemy')) frameworks.push('sqlalchemy');
    if (keys.includes('pyjwt'))      frameworks.push('pyjwt');
    return { language: 'python', manifest: 'requirements.txt', frameworks, dependencies: deps };
  } catch { return null; }
}

function parsePyprojectToml(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const deps    = {};
    const sec = content.match(/\[(?:project\.dependencies|tool\.poetry\.dependencies)\]([\s\S]*?)(?=\[|$)/);
    if (sec) {
      for (const line of sec[1].split('\n')) {
        const m = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*["']?([^"'\n]+)["']?/);
        if (m) deps[m[1].toLowerCase()] = { version: m[2].trim(), dev: false };
        const am = line.match(/["']([A-Za-z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+)?["']/);
        if (am && !m) deps[am[1].toLowerCase()] = { version: am[2]?.trim() || '*', dev: false };
      }
    }
    if (!Object.keys(deps).length) return null;
    const keys = Object.keys(deps);
    const frameworks = ['flask','django','fastapi','sqlalchemy','pyjwt'].filter(f => keys.includes(f));
    return { language: 'python', manifest: 'pyproject.toml', frameworks, dependencies: deps };
  } catch { return null; }
}

function parseComposerJson(filePath) {
  try {
    const pkg  = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const deps = {};
    for (const [n, v] of Object.entries(pkg.require      || {})) { if (n !== 'php') deps[n] = { version: v, dev: false }; }
    for (const [n, v] of Object.entries(pkg['require-dev'] || {})) deps[n] = { version: v, dev: true };
    const keys = Object.keys(deps);
    const frameworks = [];
    if (keys.some(k => k.startsWith('laravel/')))  frameworks.push('laravel');
    if (keys.some(k => k.startsWith('symfony/')))  frameworks.push('symfony');
    if (keys.includes('slim/slim'))                frameworks.push('slim');
    if (keys.includes('doctrine/orm'))             frameworks.push('doctrine');
    return { language: 'php', manifest: 'composer.json', name: pkg.name || null, frameworks, dependencies: deps };
  } catch { return null; }
}

function parseCsproj(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const deps    = {};
    for (const [, n, v] of content.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/gi))
      deps[n.toLowerCase()] = { version: v, dev: false };
    if (!Object.keys(deps).length) return null;
    const keys = Object.keys(deps);
    const frameworks = [];
    if (keys.some(k => k.includes('aspnetcore')))      frameworks.push('aspnetcore');
    if (keys.some(k => k.includes('entityframework'))) frameworks.push('entityframework');
    const tfm = content.match(/<TargetFramework[s]?>([^<]+)<\/TargetFramework[s]?>/i);
    return { language: 'csharp', manifest: path.basename(filePath),
             targetFramework: tfm ? tfm[1].trim() : null, frameworks, dependencies: deps };
  } catch { return null; }
}

function parseRepoContext(repoRoot) {
  const results = [];
  function add(r) { if (r) results.push(r); }

  add(parsePackageJson(path.join(repoRoot, 'package.json')));
  const hasReqTxt = fs.existsSync(path.join(repoRoot, 'requirements.txt'));
  if (hasReqTxt) add(parseRequirementsTxt(path.join(repoRoot, 'requirements.txt')));
  else           add(parsePyprojectToml(path.join(repoRoot, 'pyproject.toml')));
  add(parseComposerJson(path.join(repoRoot, 'composer.json')));

  try {
    const csproj = fs.readdirSync(repoRoot).find(e => e.endsWith('.csproj'));
    if (csproj) add(parseCsproj(path.join(repoRoot, csproj)));
  } catch { /* ignore */ }

  if (!results.length) return null;

  const languages  = [...new Set(results.map(r => r.language))];
  const frameworks = [...new Set(results.flatMap(r => r.frameworks || []))];
  const manifests  = results.map(r => r.manifest);

  const dependencies = {};
  for (const r of results)
    for (const [n, info] of Object.entries(r.dependencies || {}))
      dependencies[`${r.language}:${n}`] = { ...info, language: r.language };

  return {
    scannedAt: new Date().toISOString(),
    languages,
    frameworks,
    manifestFiles: manifests,
    manifests: results.map(r => ({
      language:        r.language,
      manifest:        r.manifest,
      name:            r.name            || null,
      version:         r.version         || null,
      frameworks:      r.frameworks      || [],
      targetFramework: r.targetFramework || null,
      dependencyCount: Object.keys(r.dependencies || {}).length,
    })),
    dependencies,
  };
}

function loadRepoContext(repoRoot) {
  try {
    const { storeDir } = require('./store');
    const p = path.join(storeDir(repoRoot), 'repo-context.json');
    return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null;
  } catch { return null; }
}

function saveRepoContext(repoRoot, context) {
  try {
    const { storeDir } = require('./store');
    const p = path.join(storeDir(repoRoot), 'repo-context.json');
    const existing = loadRepoContext(repoRoot);
    const sig = c => JSON.stringify({ languages: c.languages, frameworks: c.frameworks, dependencies: c.dependencies });
    fs.writeFileSync(p, JSON.stringify(context, null, 2), 'utf8');
    return !existing || sig(existing) !== sig(context);
  } catch { return false; }
}

module.exports = { parseRepoContext, loadRepoContext, saveRepoContext };
