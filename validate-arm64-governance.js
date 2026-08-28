#!/usr/bin/env node

'use strict'

const childProcess = require('child_process')
const fs = require('fs')
const path = require('path')

const COPILOT_COAUTHOR = 'Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>'
const COPILOT_SESSION = /^Copilot-Session: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

const APPROVED_ACTION_PINS = Object.freeze({
  'actions/checkout': '11d5960a326750d5838078e36cf38b85af677262',
  'msys2/setup-msys2': '66cd2cce69caa17b53920067426061ca1de3a884',
  'actions/upload-artifact': 'ea165f8d65b6e75b540449e92b4886f43607fa02',
  'actions/download-artifact': 'd3f86a106a0bac45b974a628896c90dbdf5c8093',
  'git-for-windows/setup-git-for-windows-sdk': '335917db02da4280d3d5e87915d7b86196677f9f',
  'actions/github-script': '3a2844b7e9c422d3c10d287c895573f7108da1b3'
})

const fail = message => {
  throw new Error(message)
}

const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value)

const expectRecord = (value, label) => {
  if (!isRecord(value)) fail(`${label} must be an object`)
}

const expectExactKeys = (value, keys, label) => {
  expectRecord(value, label)
  const actual = Object.keys(value)
  const missing = keys.filter(key => !actual.includes(key))
  const unexpected = actual.filter(key => !keys.includes(key))
  if (missing.length || unexpected.length) {
    fail(`${label} keys differ (missing: ${missing.join(', ') || 'none'}; unexpected: ${unexpected.join(', ') || 'none'})`)
  }
}

const expectSafeInteger = (value, label, minimum) => {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${label} must be a safe integer greater than or equal to ${minimum}`)
  }
}

const expectSha = (value, label) => {
  if (typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) {
    fail(`${label} must be a lowercase 40-hex object ID`)
  }
}

const rejectUrlCarriers = (value, label) => {
  if (typeof value === 'string' && /^https?:\/\//i.test(value)) {
    fail(`${label} must not use a URL as an input identity`)
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectUrlCarriers(item, `${label}[${index}]`))
  } else if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (/url/i.test(key)) fail(`${label}.${key} is an unapproved URL carrier`)
      rejectUrlCarriers(item, `${label}.${key}`)
    }
  }
}

const validateTagName = (value, label) => {
  if (
    typeof value !== 'string' ||
    !value ||
    value === '@' ||
    value.startsWith('.') ||
    value.startsWith('/') ||
    value.endsWith('.') ||
    value.endsWith('/') ||
    value.endsWith('.lock') ||
    value.includes('..') ||
    value.includes('//') ||
    value.includes('@{') ||
    /[\s~^:?*\[\\]/.test(value)
  ) {
    fail(`${label} is not a valid tag name`)
  }
}

const validateReleaseInput = (input, label = 'release input') => {
  rejectUrlCarriers(input, label)
  expectExactKeys(input, ['schemaVersion', 'architecture', 'repository', 'release', 'tag', 'assets'], label)

  if (input.schemaVersion !== 1) fail(`${label}.schemaVersion must be 1`)
  if (input.architecture !== 'aarch64') fail(`${label}.architecture must be "aarch64"`)
  if (typeof input.repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(input.repository)) {
    fail(`${label}.repository must be an owner/repository identity`)
  }

  expectExactKeys(input.release, ['id', 'tagName', 'immutable'], `${label}.release`)
  expectSafeInteger(input.release.id, `${label}.release.id`, 1)
  validateTagName(input.release.tagName, `${label}.release.tagName`)
  if (input.release.immutable !== true) fail(`${label}.release.immutable must be true`)

  expectExactKeys(
    input.tag,
    ['name', 'objectType', 'objectSha', 'peeledType', 'peeledCommitSha', 'peeledTreeSha'],
    `${label}.tag`
  )
  validateTagName(input.tag.name, `${label}.tag.name`)
  if (input.tag.name !== input.release.tagName) fail(`${label}.tag.name must match release.tagName`)
  if (input.tag.objectType !== 'tag') fail(`${label}.tag.objectType must be "tag" for an annotated tag`)
  if (input.tag.peeledType !== 'commit') fail(`${label}.tag.peeledType must be "commit"`)
  expectSha(input.tag.objectSha, `${label}.tag.objectSha`)
  expectSha(input.tag.peeledCommitSha, `${label}.tag.peeledCommitSha`)
  expectSha(input.tag.peeledTreeSha, `${label}.tag.peeledTreeSha`)
  if (new Set([input.tag.objectSha, input.tag.peeledCommitSha, input.tag.peeledTreeSha]).size !== 3) {
    fail(`${label}.tag object, peeled commit, and peeled tree must be distinct`)
  }

  if (!Array.isArray(input.assets) || input.assets.length === 0) {
    fail(`${label}.assets must be a non-empty array`)
  }
  const assetIds = new Set()
  const assetNames = new Set()
  input.assets.forEach((asset, index) => {
    const assetLabel = `${label}.assets[${index}]`
    expectExactKeys(asset, ['id', 'name', 'size', 'digest'], assetLabel)
    expectSafeInteger(asset.id, `${assetLabel}.id`, 1)
    expectSafeInteger(asset.size, `${assetLabel}.size`, 0)
    if (
      typeof asset.name !== 'string' ||
      !asset.name ||
      asset.name !== asset.name.trim() ||
      asset.name === '.' ||
      asset.name === '..' ||
      /[\/\\\0]/.test(asset.name)
    ) {
      fail(`${assetLabel}.name must be an exact asset basename`)
    }
    if (typeof asset.digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(asset.digest)) {
      fail(`${assetLabel}.digest must be a lowercase sha256 digest`)
    }
    if (assetIds.has(asset.id)) fail(`${label}.assets contains duplicate ID ${asset.id}`)
    if (assetNames.has(asset.name)) fail(`${label}.assets contains duplicate name ${asset.name}`)
    assetIds.add(asset.id)
    assetNames.add(asset.name)
  })

  return input
}

const parseUses = raw => {
  let value = raw.replace(/\s+#.*$/, '').trim()
  if (
    value.length >= 2 &&
    (value[0] === '"' || value[0] === "'") &&
    value[value.length - 1] === value[0]
  ) {
    value = value.slice(1, -1)
  }
  return value
}

const validateWorkflowText = (contents, label) => {
  const inventory = []
  const lines = contents.split(/\r?\n/)

  lines.forEach((line, index) => {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*(.+?)\s*$/)
    if (!match) return
    const spec = parseUses(match[1])
    if (spec.startsWith('./')) return

    const action = spec.match(/^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:\/[^@\s]+)?@([0-9a-f]{40})$/)
    if (!action) {
      fail(`${label}:${index + 1}: external Action '${spec}' must use a literal lowercase 40-hex commit`)
    }

    const identity = action[1].toLowerCase()
    const sha = action[2]
    const approved = APPROVED_ACTION_PINS[identity]
    if (!approved) {
      fail(`${label}:${index + 1}: unapproved external Action identity ${identity}`)
    }
    if (sha !== approved) {
      fail(`${label}:${index + 1}: ${identity} must use approved commit ${approved}, not ${sha}`)
    }
    inventory.push({ identity, sha })
  })

  const forbiddenDownloads = [
    [/\bgh\s+(?:run|release)\s+download\b/i, 'GitHub CLI artifact download'],
    [/\/(?:actions\/artifacts|releases\/(?:download|assets))\//i, 'URL-only artifact carrier'],
    [/\b(?:browser_download_url|archive_download_url|artifact-url)\b/i, 'URL-only artifact carrier']
  ]
  for (const [pattern, description] of forbiddenDownloads) {
    if (pattern.test(contents)) fail(`${label}: unapproved ${description}`)
  }

  return inventory
}

const validateWorkflowDirectory = directory => {
  const files = fs.readdirSync(directory, { withFileTypes: true })
    .filter(entry => entry.isFile() && /\.ya?ml$/i.test(entry.name))
    .map(entry => entry.name)
    .sort()
  if (files.length === 0) fail(`${directory} contains no workflow files`)

  const inventory = []
  for (const file of files) {
    const filePath = path.join(directory, file)
    inventory.push(...validateWorkflowText(fs.readFileSync(filePath, 'utf8'), filePath))
  }
  return inventory
}

const isCopilotOwned = lines => lines.some(line =>
  /^Copilot-Session:/i.test(line) || /^Co-authored-by:\s*Copilot App\b/i.test(line)
)

const validateOwnedCommitMessage = (message, label = 'commit') => {
  const rawLines = message.split('\n')
  if (!isCopilotOwned(rawLines)) return false
  if (message.includes('\r')) fail(`${label}: commit message must use LF line endings`)
  if (!message.endsWith('\n') || message.endsWith('\n\n')) {
    fail(`${label}: owned commit must end immediately after the Copilot-Session trailer`)
  }

  const lines = message.slice(0, -1).split('\n')
  if (lines.length < 2 || lines[lines.length - 2] !== COPILOT_COAUTHOR || !COPILOT_SESSION.test(lines[lines.length - 1])) {
    fail(`${label}: owned commit must end with the exact Co-authored-by and Copilot-Session pair`)
  }
  if (isCopilotOwned(lines.slice(0, -2))) {
    fail(`${label}: owned commit has duplicate or non-terminal Copilot trailers`)
  }
  return true
}

const runGit = (args, cwd, encoding = 'utf8') => {
  try {
    return childProcess.execFileSync('git', args, { cwd, encoding, stdio: ['ignore', 'pipe', 'pipe'] })
  } catch (error) {
    const stderr = error.stderr ? error.stderr.toString().trim() : error.message
    fail(`git ${args.join(' ')} failed${stderr ? `: ${stderr}` : ''}`)
  }
}

const validateCommitRange = (base, head, cwd = process.cwd()) => {
  if (!/^[0-9a-f]{40}$/.test(base) || !/^[0-9a-f]{40}$/.test(head)) {
    fail('commit range endpoints must be literal lowercase 40-hex object IDs')
  }
  const resolvedBase = runGit(['rev-parse', '--verify', `${base}^{commit}`], cwd).trim()
  const resolvedHead = runGit(['rev-parse', '--verify', `${head}^{commit}`], cwd).trim()
  if (resolvedBase !== base || resolvedHead !== head) fail('commit range endpoints did not resolve exactly')
  const mergeBase = runGit(['merge-base', base, head], cwd).trim()
  if (!/^[0-9a-f]{40}$/.test(mergeBase)) fail(`could not resolve one merge base for ${base} and ${head}`)

  const commits = runGit(['rev-list', '--reverse', `${mergeBase}..${head}`], cwd)
    .trim()
    .split('\n')
    .filter(Boolean)
  let owned = 0
  for (const commit of commits) {
    const object = runGit(['cat-file', 'commit', commit], cwd)
    const separator = object.indexOf('\n\n')
    if (separator < 0) fail(`${commit}: malformed commit object`)
    if (validateOwnedCommitMessage(object.slice(separator + 2), commit)) owned++
  }
  return { commits: commits.length, mergeBase, owned }
}

const usage = () => [
  'usage:',
  '  node validate-arm64-governance.js workflows [workflow-directory]',
  '  node validate-arm64-governance.js commits <base-commit> <head-commit>',
  '  node validate-arm64-governance.js release-input <metadata.json>...'
].join('\n')

const main = () => {
  const [command, ...args] = process.argv.slice(2)
  if (command === 'workflows') {
    if (args.length > 1) fail(usage())
    const inventory = validateWorkflowDirectory(args[0] || '.github/workflows')
    const pins = [...new Set(inventory.map(({ identity, sha }) => `${identity}@${sha}`))].sort()
    pins.forEach(pin => process.stdout.write(`${pin}\n`))
    return
  }
  if (command === 'commits') {
    if (args.length !== 2) fail(usage())
    const result = validateCommitRange(args[0], args[1])
    process.stdout.write(
      `validated ${result.owned} owned commit(s) in ${result.commits} commit(s) from merge base ${result.mergeBase}\n`
    )
    return
  }
  if (command === 'release-input') {
    if (args.length === 0) fail(usage())
    args.forEach(file => validateReleaseInput(JSON.parse(fs.readFileSync(file, 'utf8')), file))
    process.stdout.write(`validated ${args.length} immutable release input(s)\n`)
    return
  }
  fail(usage())
}

if (require.main === module) {
  try {
    main()
  } catch (error) {
    process.stderr.write(`${error.message}\n`)
    process.exit(1)
  }
}

module.exports = {
  APPROVED_ACTION_PINS,
  COPILOT_COAUTHOR,
  validateCommitRange,
  validateOwnedCommitMessage,
  validateReleaseInput,
  validateWorkflowDirectory,
  validateWorkflowText
}
