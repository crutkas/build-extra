#!/usr/bin/env node

'use strict'

const childProcess = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const https = require('https')
const os = require('os')
const path = require('path')
const yaml = require('js-yaml')
const yamlPackage = require('js-yaml/package.json')

const COPILOT_COAUTHOR = 'Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>'
const SESSION_TRAILER_PREFIX = 'Copilot-Session: '
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const SHA = /^[0-9a-f]{40}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const TRUSTED_ADMISSION_COMMAND =
  'node trusted/validate-arm64-governance.js admission trusted "$CANDIDATE_REPOSITORY" "$BASE_SHA" "$HEAD_SHA"'
const TRUSTED_DEPENDENCY_COMMAND =
  'npm ci --prefix trusted --ignore-scripts --no-audit --no-fund'
const TRUSTED_TEST_COMMAND = 'npm --prefix trusted run test:governance'
const TRUSTED_MUTATION_COMMAND = 'npm --prefix trusted run test:governance:mutations'

const REQUIRED_ACTION_PROVENANCE = Object.freeze({
  'actions/checkout': {
    commit: '11d5960a326750d5838078e36cf38b85af677262',
    tree: 'f8a7b72dc00648d050099727d25ca92a43ad1162',
    source: ['lightweight-tag', 'refs/tags/v4.4.0', null],
    verification: [true, 'valid', 'verified']
  },
  'msys2/setup-msys2': {
    commit: '66cd2cce69caa17b53920067426061ca1de3a884',
    tree: 'e44409e0abb209473d580a1de6f1640312a2ec11',
    source: ['lightweight-tag', 'refs/tags/v2.32.0', null],
    verification: [false, 'unsigned', 'policy-required-exception']
  },
  'actions/upload-artifact': {
    commit: 'ea165f8d65b6e75b540449e92b4886f43607fa02',
    tree: '90fba5b2fb462e7dd5b3b810757b73327d2d66bc',
    source: ['lightweight-tag', 'refs/tags/v4.6.2', null],
    verification: [true, 'valid', 'verified']
  },
  'actions/download-artifact': {
    commit: 'd3f86a106a0bac45b974a628896c90dbdf5c8093',
    tree: '064a6e5489b0f9f42ede63b1262704c4e73e4093',
    source: ['lightweight-tag', 'refs/tags/v4.3.0', null],
    verification: [true, 'valid', 'verified']
  },
  'actions/github-script': {
    commit: '3a2844b7e9c422d3c10d287c895573f7108da1b3',
    tree: '23894d36d73527d5502aa7b2b9d53041f9e56f4e',
    source: ['annotated-tag', 'refs/tags/v9', '373c709c69115d41ff229c7e5df9f8788daa9553'],
    verification: [true, 'valid', 'verified']
  }
})

const APPROVED_ACTION_PINS = Object.freeze(Object.fromEntries(
  Object.entries(REQUIRED_ACTION_PROVENANCE).map(([identity, provenance]) => [identity, provenance.commit])
))

const DENIED_ACTION_IDENTITIES = Object.freeze(new Set([
  'git-for-windows/setup-git-for-windows-sdk'
]))

const REQUIRED_GOVERNANCE_SOURCES = Object.freeze([
  '.github/arm64-denied-ancestry.json',
  '.github/arm64-governance.json',
  '.github/workflows/add-release-note.yml',
  '.github/workflows/main.yml',
  'add-release-note.js',
  'package-lock.json',
  'package.json',
  'tests/fixtures/arm64-ancestry-api.json',
  'tests/fixtures/arm64-release-api.json',
  'validate-arm64-governance.js',
  'validate-arm64-governance.mutation.js',
  'validate-arm64-governance.test.js'
])

const REQUIRED_DENIED_ENUMERATION = Object.freeze({
  branchPattern: '^crutkas-(?:.*arm64.*|finalize-preview-validator)$',
  pullRequestTitlePattern: '\\barm64\\b',
  excludedBranches: ['crutkas-arm64-governance-pins'],
  excludedPullRequests: [17],
  pageSize: 100
})

const compareDeniedSources = (left, right) => {
  const leftKind = left.startsWith('refs/heads/') ? 0 : 1
  const rightKind = right.startsWith('refs/heads/') ? 0 : 1
  if (leftKind !== rightKind) return leftKind - rightKind
  return left < right ? -1 : left > right ? 1 : 0
}

const yamlStreamHasNoNode = contents => contents
  .replace(/^\uFEFF/, '')
  .split(/\r?\n/)
  .every(line => {
    const trimmed = line.trim()
    return !trimmed ||
      trimmed.startsWith('#') ||
      /^---(?:\s+#.*)?$/.test(trimmed) ||
      /^%[A-Z]+(?:\s+.*)?$/.test(trimmed)
  })

const DEFAULT_YAML_PARSERS = Object.freeze([
  {
    name: 'js-yaml',
    version: yamlPackage.version,
    parse (contents) {
      const documents = []
      yaml.loadAll(contents, document => {
        documents.push(document)
      })
      const emptyDocuments = documents.map(document => document === undefined)
      if (documents.length === 1 && documents[0] === null && yamlStreamHasNoNode(contents)) {
        emptyDocuments[0] = true
      }
      return {
        parser: `js-yaml@${yamlPackage.version}`,
        stream: { documentCount: documents.length, emptyDocuments, documents }
      }
    }
  }
])

const FORBIDDEN_COMMANDS = Object.freeze([
  [/\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b/i, 'network downloader'],
  [/\bgh\s+(?:api|run\s+download|release\s+(?:download|upload|create|edit))\b/i,
    'GitHub CLI network or publication command'],
  [/\bgit\b[^\n;&|]{0,200}\b(?:clone|fetch|pull|push|ls-remote)\b/i, 'mutable Git network command'],
  [/\bgit\b[^\n;&|]{0,200}\b(?:checkout|switch|reset)\b[^\n;&|]*(?:refs\/heads\/|\bmain\b|\bmaster\b|\$\{\{)/i,
    'mutable Git ref command'],
  [/https?:\/\//i, 'URL carrier'],
  [/\b(?:browser_download_url|archive_download_url|artifact-url)\b/i, 'artifact URL carrier']
])

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
  if (typeof value !== 'string' || !SHA.test(value)) fail(`${label} must be a lowercase 40-hex object ID`)
}

const expectAuthorizedSessions = (value, label) => {
  const sessions = Array.isArray(value) ? value : [value]
  if (sessions.length === 0) fail(`${label}: at least one authorized Copilot session UUID is required`)
  for (const session of sessions) {
    if (typeof session !== 'string' || !UUID.test(session)) {
      fail(`${label}: every authorized Copilot session must be an explicit lowercase UUID`)
    }
  }
  if (new Set(sessions).size !== sessions.length) {
    fail(`${label}: authorized Copilot sessions must be unique`)
  }
  return sessions
}

const clone = value => JSON.parse(JSON.stringify(value))

const canonical = value => {
  if (Array.isArray(value)) return value.map(canonical)
  if (!isRecord(value)) return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]))
}

const sameJson = (left, right) => JSON.stringify(canonical(left)) === JSON.stringify(canonical(right))

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

const safeRelativePath = (value, label) => {
  if (
    typeof value !== 'string' ||
    !value ||
    path.isAbsolute(value) ||
    value.includes('\\') ||
    value.split('/').some(part => !part || part === '.' || part === '..')
  ) {
    fail(`${label} must be a normalized repository-relative path`)
  }
  return value
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

const validateAsset = (asset, label) => {
  expectExactKeys(asset, ['id', 'name', 'size', 'digest'], label)
  expectSafeInteger(asset.id, `${label}.id`, 1)
  expectSafeInteger(asset.size, `${label}.size`, 0)
  if (
    typeof asset.name !== 'string' ||
    !asset.name ||
    asset.name !== asset.name.trim() ||
    asset.name === '.' ||
    asset.name === '..' ||
    /[\/\\\0]/.test(asset.name)
  ) {
    fail(`${label}.name must be an exact asset basename`)
  }
  if (typeof asset.digest !== 'string' || !DIGEST.test(asset.digest)) {
    fail(`${label}.digest must be a lowercase sha256 digest`)
  }
}

const validateAssetSet = (assets, label) => {
  if (!Array.isArray(assets) || assets.length === 0) fail(`${label} must be a non-empty array`)
  const ids = new Set()
  const names = new Set()
  assets.forEach((asset, index) => {
    validateAsset(asset, `${label}[${index}]`)
    if (ids.has(asset.id)) fail(`${label} contains duplicate ID ${asset.id}`)
    if (names.has(asset.name)) fail(`${label} contains duplicate name ${asset.name}`)
    ids.add(asset.id)
    names.add(asset.name)
  })
}

const sortedAssets = assets => clone(assets).sort((left, right) => left.id - right.id)

const validateReleaseLock = (lock, label = 'release lock') => {
  rejectUrlCarriers(lock, label)
  expectExactKeys(lock, ['schemaVersion', 'architecture', 'repository', 'release', 'tag', 'assets'], label)
  if (lock.schemaVersion !== 1) fail(`${label}.schemaVersion must be 1`)
  if (lock.architecture !== 'aarch64') fail(`${label}.architecture must be "aarch64"`)
  if (typeof lock.repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(lock.repository)) {
    fail(`${label}.repository must be an owner/repository identity`)
  }

  expectExactKeys(lock.release, ['id', 'tagName', 'immutable', 'assetCount'], `${label}.release`)
  expectSafeInteger(lock.release.id, `${label}.release.id`, 1)
  expectSafeInteger(lock.release.assetCount, `${label}.release.assetCount`, 1)
  validateTagName(lock.release.tagName, `${label}.release.tagName`)
  if (lock.release.immutable !== true) fail(`${label}.release.immutable must be true`)

  expectExactKeys(lock.tag, ['objectSha', 'peeledCommitSha', 'peeledTreeSha'], `${label}.tag`)
  expectSha(lock.tag.objectSha, `${label}.tag.objectSha`)
  expectSha(lock.tag.peeledCommitSha, `${label}.tag.peeledCommitSha`)
  expectSha(lock.tag.peeledTreeSha, `${label}.tag.peeledTreeSha`)
  if (new Set(Object.values(lock.tag)).size !== 3) {
    fail(`${label}.tag object, peeled commit, and peeled tree must be distinct`)
  }

  validateAssetSet(lock.assets, `${label}.assets`)
  if (lock.assets.length !== lock.release.assetCount) {
    fail(`${label}.release.assetCount must equal the complete expected asset set`)
  }
  return lock
}

const validateDigestEvidence = (evidence, lock, label = 'digest evidence') => {
  rejectUrlCarriers(evidence, label)
  expectExactKeys(
    evidence,
    ['schemaVersion', 'method', 'repository', 'releaseId', 'tagObjectSha', 'peeledCommitSha', 'assets'],
    label
  )
  if (evidence.schemaVersion !== 1) fail(`${label}.schemaVersion must be 1`)
  if (evidence.method !== 'independent-redownload') fail(`${label}.method must be "independent-redownload"`)
  if (evidence.repository !== lock.repository) fail(`${label}.repository does not match the release lock`)
  if (evidence.releaseId !== lock.release.id) fail(`${label}.releaseId does not match the release lock`)
  if (evidence.tagObjectSha !== lock.tag.objectSha) fail(`${label}.tagObjectSha does not match the release lock`)
  if (evidence.peeledCommitSha !== lock.tag.peeledCommitSha) {
    fail(`${label}.peeledCommitSha does not match the release lock`)
  }
  validateAssetSet(evidence.assets, `${label}.assets`)
  if (!sameJson(sortedAssets(evidence.assets), sortedAssets(lock.assets))) {
    fail(`${label}.assets do not bind every locked asset ID, name, size, and digest`)
  }
  return evidence
}

const verifyReleaseInput = async (lock, evidence, request) => {
  validateReleaseLock(lock)
  validateDigestEvidence(evidence, lock)
  if (typeof request !== 'function') fail('authoritative API request function is required')

  const repository = await request(`/repos/${lock.repository}`)
  if (!isRecord(repository) || repository.full_name !== lock.repository) {
    fail(`authoritative repository identity does not match ${lock.repository}`)
  }

  const release = await request(`/repos/${lock.repository}/releases/${lock.release.id}`)
  if (!isRecord(release) || release.id !== lock.release.id) fail('authoritative release ID does not match')
  if (release.immutable !== true) fail('authoritative release is not immutable')
  if (release.tag_name !== lock.release.tagName) fail('authoritative release tag does not match')
  if (!Array.isArray(release.assets) || release.assets.length !== lock.release.assetCount) {
    fail('authoritative release asset count does not match the complete expected set')
  }
  const authoritativeAssets = release.assets.map(asset => ({
    id: asset.id,
    name: asset.name,
    size: asset.size,
    digest: asset.digest
  }))
  validateAssetSet(authoritativeAssets, 'authoritative release assets')
  if (!sameJson(sortedAssets(authoritativeAssets), sortedAssets(lock.assets))) {
    fail('authoritative release asset membership or identity does not match the lock')
  }

  const tagName = encodeURIComponent(lock.release.tagName)
  const reference = await request(`/repos/${lock.repository}/git/ref/tags/${tagName}`)
  if (
    !isRecord(reference) ||
    reference.ref !== `refs/tags/${lock.release.tagName}` ||
    !isRecord(reference.object) ||
    reference.object.type !== 'tag' ||
    reference.object.sha !== lock.tag.objectSha
  ) {
    fail('authoritative tag ref is lightweight, moved, or does not match the annotated tag object')
  }

  const tag = await request(`/repos/${lock.repository}/git/tags/${lock.tag.objectSha}`)
  if (
    !isRecord(tag) ||
    tag.sha !== lock.tag.objectSha ||
    !isRecord(tag.object) ||
    tag.object.type !== 'commit' ||
    tag.object.sha !== lock.tag.peeledCommitSha
  ) {
    fail('authoritative annotated tag does not peel to the locked commit')
  }

  const commit = await request(`/repos/${lock.repository}/git/commits/${lock.tag.peeledCommitSha}`)
  if (
    !isRecord(commit) ||
    commit.sha !== lock.tag.peeledCommitSha ||
    !isRecord(commit.tree) ||
    commit.tree.sha !== lock.tag.peeledTreeSha
  ) {
    fail('authoritative peeled commit or tree does not match the lock')
  }

  return true
}

const createFixtureApi = responses => async apiPath => {
  if (!Object.prototype.hasOwnProperty.call(responses, apiPath)) {
    fail(`offline API fixture has no authoritative response for ${apiPath}`)
  }
  return clone(responses[apiPath])
}

const createGitHubApi = token => apiPath => new Promise((resolve, reject) => {
  const headers = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'build-extra-arm64-governance',
    'X-GitHub-Api-Version': '2022-11-28'
  }
  if (token) headers.Authorization = `Bearer ${token}`
  const request = https.request({
    hostname: 'api.github.com',
    method: 'GET',
    path: apiPath,
    headers
  }, response => {
    const chunks = []
    let length = 0
    response.on('data', chunk => {
      length += chunk.length
      if (length > 2 * 1024 * 1024) {
        request.destroy(new Error(`GitHub API response for ${apiPath} exceeded 2 MiB`))
        return
      }
      chunks.push(chunk)
    })
    response.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      if (response.statusCode < 200 || response.statusCode >= 300) {
        reject(new Error(`GitHub API ${apiPath} returned ${response.statusCode}`))
        return
      }
      try {
        resolve(JSON.parse(body))
      } catch (error) {
        reject(new Error(`GitHub API ${apiPath} returned invalid JSON: ${error.message}`))
      }
    })
  })
  request.setTimeout(15000, () => request.destroy(new Error(`GitHub API ${apiPath} timed out`)))
  request.on('error', reject)
  request.end()
})

const enumerateDeniedCampaignSources = async (policy, request) => {
  if (typeof request !== 'function') fail('authoritative campaign enumeration API request function is required')
  const rules = policy.deniedCampaignEnumeration
  if (!sameJson(rules, REQUIRED_DENIED_ENUMERATION)) {
    fail('authoritative campaign enumeration rules are not the fixed reviewed rules')
  }
  const getAllPages = async endpoint => {
    const values = []
    for (let page = 1; ; page++) {
      const apiPath = `${endpoint}${endpoint.includes('?') ? '&' : '?'}per_page=${rules.pageSize}&page=${page}`
      const response = await request(apiPath)
      if (!Array.isArray(response)) fail(`authoritative enumeration response for ${apiPath} must be an array`)
      values.push(...response)
      if (response.length < rules.pageSize) return values
      if (page >= 100) fail(`authoritative enumeration for ${endpoint} exceeded 100 pages`)
    }
  }

  const branchPattern = new RegExp(rules.branchPattern, 'i')
  const titlePattern = new RegExp(rules.pullRequestTitlePattern, 'i')
  const excludedBranches = new Set(rules.excludedBranches)
  const excludedPullRequests = new Set(rules.excludedPullRequests)
  const selected = []
  const tips = new Set()
  const branchNames = new Set()
  const branches = await getAllPages(`/repos/${policy.repository}/branches`)
  for (const [index, branch] of branches.entries()) {
    if (
      !isRecord(branch) ||
      typeof branch.name !== 'string' ||
      !isRecord(branch.commit)
    ) {
      fail(`authoritative branch enumeration entry ${index} is invalid`)
    }
    expectSha(branch.commit.sha, `authoritative branch enumeration entry ${index}.commit.sha`)
    if (branchNames.has(branch.name)) fail(`authoritative branch enumeration repeats ${branch.name}`)
    branchNames.add(branch.name)
    if (!branchPattern.test(branch.name) || excludedBranches.has(branch.name)) continue
    if (tips.has(branch.commit.sha)) fail(`authoritative campaign branches share denied tip ${branch.commit.sha}`)
    selected.push({ source: `refs/heads/${branch.name}`, tip: branch.commit.sha })
    tips.add(branch.commit.sha)
  }

  const pullNumbers = new Set()
  const pulls = await getAllPages(`/repos/${policy.repository}/pulls?state=all`)
  for (const [index, pull] of pulls.entries()) {
    if (
      !isRecord(pull) ||
      !Number.isSafeInteger(pull.number) ||
      pull.number < 1 ||
      typeof pull.title !== 'string' ||
      !isRecord(pull.head)
    ) {
      fail(`authoritative pull-request enumeration entry ${index} is invalid`)
    }
    expectSha(pull.head.sha, `authoritative pull-request enumeration entry ${index}.head.sha`)
    if (pullNumbers.has(pull.number)) fail(`authoritative pull-request enumeration repeats PR ${pull.number}`)
    pullNumbers.add(pull.number)
    if (!titlePattern.test(pull.title) || excludedPullRequests.has(pull.number) || tips.has(pull.head.sha)) continue
    selected.push({ source: `pull/${pull.number}/head`, tip: pull.head.sha })
    tips.add(pull.head.sha)
  }

  selected.sort((left, right) => compareDeniedSources(left.source, right.source))
  return selected
}

const verifyDeniedAncestry = async (policy, candidateCommits, request) => {
  validateGovernancePolicy(policy)
  if (!Array.isArray(candidateCommits) || candidateCommits.length === 0) {
    fail('candidate commit list must be non-empty')
  }
  const candidate = new Set()
  candidateCommits.forEach((commit, index) => {
    expectSha(commit, `candidate commits[${index}]`)
    if (candidate.has(commit)) fail(`candidate commit list contains duplicate ${commit}`)
    candidate.add(commit)
  })
  if (typeof request !== 'function') fail('authoritative ancestry API request function is required')
  const enumerated = await enumerateDeniedCampaignSources(policy, request)
  const declared = policy.deniedCampaignCommits.map(({ source, tip }) => ({ source, tip }))
  if (!sameJson(declared, enumerated)) {
    fail('denied campaign policy is incomplete or stale relative to authoritative branch/PR enumeration')
  }

  const collected = []
  for (const entry of policy.deniedCampaignCommits) {
    if (entry.commitCount > 250) fail(`${entry.source}: compare proof exceeds GitHub's complete 250-commit limit`)
    const refName = entry.source.startsWith('refs/') ? entry.source.slice(5) : entry.source
    const reference = await request(`/repos/${policy.repository}/git/ref/${refName}`)
    if (
      !isRecord(reference) ||
      reference.ref !== (entry.source.startsWith('refs/') ? entry.source : `refs/${entry.source}`) ||
      !isRecord(reference.object) ||
      reference.object.type !== 'commit' ||
      reference.object.sha !== entry.tip
    ) {
      fail(`${entry.source}: authoritative ref does not resolve to the denied campaign tip`)
    }

    const commits = []
    let page = 1
    while (commits.length < entry.commitCount) {
      const apiPath =
        `/repos/${policy.repository}/compare/${entry.mergeBase}...${entry.tip}?per_page=100&page=${page}`
      const comparison = await request(apiPath)
      if (
        !isRecord(comparison) ||
        comparison.status !== 'ahead' ||
        !isRecord(comparison.base_commit) ||
        comparison.base_commit.sha !== entry.mergeBase ||
        !isRecord(comparison.merge_base_commit) ||
        comparison.merge_base_commit.sha !== entry.mergeBase ||
        comparison.total_commits !== entry.commitCount ||
        !Array.isArray(comparison.commits) ||
        comparison.commits.length === 0
      ) {
        fail(`${entry.source}: authoritative compare proof is missing, partial, or does not match policy anchors`)
      }
      comparison.commits.forEach((commit, index) => {
        if (!isRecord(commit)) fail(`${entry.source}: compare page ${page} commit ${index} is invalid`)
        expectSha(commit.sha, `${entry.source}: compare page ${page} commit ${index}`)
        commits.push(commit.sha)
      })
      if (commits.length > entry.commitCount) fail(`${entry.source}: compare proof exceeds the declared commit count`)
      page++
    }

    if (
      commits.length !== entry.commitCount ||
      commits[0] !== entry.root ||
      commits[commits.length - 1] !== entry.tip ||
      new Set(commits).size !== commits.length
    ) {
      fail(`${entry.source}: authoritative compare proof does not provide the complete rooted ancestry`)
    }
    const tip = await request(`/repos/${policy.repository}/commits/${entry.tip}`)
    if (!isRecord(tip) || tip.sha !== entry.tip || !Array.isArray(tip.parents)) {
      fail(`${entry.source}: authoritative tip commit proof is invalid`)
    }
    if (
      commits.length > 1 &&
      !tip.parents.some(parent => isRecord(parent) && parent.sha === commits[commits.length - 2])
    ) {
      fail(`${entry.source}: authoritative tip parent is not bound to the compare proof`)
    }
    const reused = commits.find(commit => candidate.has(commit))
    if (reused) fail(`candidate ancestry reuses denied campaign commit ${reused} from ${entry.source}`)
    collected.push({ ...entry, commits })
  }

  const digest = crypto.createHash('sha256')
    .update(JSON.stringify(collected))
    .digest('hex')
  return { collected, digest: `sha256:${digest}` }
}

const serializeAncestryManifest = (policy, collected) => `${JSON.stringify({
  schemaVersion: 1,
  repository: policy.repository,
  sources: collected
}, null, 2)}\n`

const validateAncestryManifest = (policy, contents, candidateCommits, label = 'ancestry manifest') => {
  if (typeof contents !== 'string') fail(`${label} must be serialized JSON`)
  const digest = `sha256:${crypto.createHash('sha256').update(contents).digest('hex')}`
  if (digest !== policy.ancestryManifest.digest) {
    fail(`${label} byte digest ${digest} does not match trusted policy ${policy.ancestryManifest.digest}`)
  }
  let manifest
  try {
    manifest = JSON.parse(contents)
  } catch (error) {
    fail(`${label}: invalid JSON: ${error.message}`)
  }
  expectExactKeys(manifest, ['schemaVersion', 'repository', 'sources'], label)
  if (manifest.schemaVersion !== 1 || manifest.repository !== policy.repository) {
    fail(`${label} schema or repository identity does not match policy`)
  }
  if (!Array.isArray(manifest.sources) || manifest.sources.length !== policy.deniedCampaignCommits.length) {
    fail(`${label} must contain complete evidence for every denied source`)
  }
  if (!Array.isArray(candidateCommits) || candidateCommits.length === 0) {
    fail('candidate commit list must be non-empty')
  }
  const candidate = new Set()
  candidateCommits.forEach((commit, index) => {
    expectSha(commit, `candidate commits[${index}]`)
    if (candidate.has(commit)) fail(`candidate commit list contains duplicate ${commit}`)
    candidate.add(commit)
  })

  const sources = new Map()
  manifest.sources.forEach((entry, index) => {
    const entryLabel = `${label}.sources[${index}]`
    expectExactKeys(entry, ['source', 'mergeBase', 'root', 'tip', 'commitCount', 'commits'], entryLabel)
    if (sources.has(entry.source)) fail(`${label} contains duplicate source ${entry.source}`)
    sources.set(entry.source, entry)
  })
  for (const denied of policy.deniedCampaignCommits) {
    const entry = sources.get(denied.source)
    if (!entry) fail(`${label} is missing ${denied.source}`)
    for (const key of ['mergeBase', 'root', 'tip', 'commitCount']) {
      if (entry[key] !== denied[key]) fail(`${label} ${denied.source}.${key} does not match policy`)
    }
    if (
      !Array.isArray(entry.commits) ||
      entry.commits.length !== denied.commitCount ||
      entry.commits[0] !== denied.root ||
      entry.commits[entry.commits.length - 1] !== denied.tip
    ) {
      fail(`${label} ${denied.source} does not contain the complete rooted commit list`)
    }
    const unique = new Set()
    entry.commits.forEach((commit, index) => {
      expectSha(commit, `${label} ${denied.source}.commits[${index}]`)
      if (unique.has(commit)) fail(`${label} ${denied.source} contains duplicate commit ${commit}`)
      unique.add(commit)
      if (candidate.has(commit)) fail(`candidate ancestry reuses denied campaign commit ${commit} from ${denied.source}`)
    })
  }
  return { digest, sources: manifest.sources }
}

const validateGovernancePolicy = (policy, label = 'governance policy') => {
  expectExactKeys(
    policy,
    [
      'schemaVersion',
      'repository',
      'authorizedSessions',
      'bootstrap',
      'payloadPolicy',
      'ancestryManifest',
      'governanceSources',
      'deniedCampaignEnumeration',
      'deniedActions',
      'releaseLock',
      'actions',
      'deniedCampaignCommits'
    ],
    label
  )
  if (policy.schemaVersion !== 1) fail(`${label}.schemaVersion must be 1`)
  if (policy.repository !== 'crutkas/build-extra') fail(`${label}.repository must be "crutkas/build-extra"`)
  if (!Array.isArray(policy.authorizedSessions)) {
    fail(`${label}.authorizedSessions must be an explicit list of lowercase session UUIDs`)
  }
  expectAuthorizedSessions(policy.authorizedSessions, `${label}.authorizedSessions`)
  if (policy.authorizedSessions.some((session, index) => index > 0 && session <= policy.authorizedSessions[index - 1])) {
    fail(`${label}.authorizedSessions must be sorted ascending so the trusted set is order-independent`)
  }
  expectExactKeys(
    policy.bootstrap,
    ['pullRequest', 'selfAdmission', 'requiredReview', 'commit', 'session'],
    `${label}.bootstrap`
  )
  if (
    policy.bootstrap.pullRequest !== 17 ||
    policy.bootstrap.selfAdmission !== false ||
    policy.bootstrap.requiredReview !== 'independent-read-only-audit' ||
    policy.bootstrap.commit !== '737ea2e89258b19defcf347af37eeac64cf16e2c' ||
    policy.bootstrap.session !== 'b3c52e9a-e880-4744-82aa-225db6ff93ef'
  ) {
    fail(`${label}.bootstrap must state that PR 17 requires independent read-only review and cannot self-admit`)
  }
  if (policy.authorizedSessions.includes(policy.bootstrap.session)) {
    fail(`${label}.authorizedSessions must not authorize the bootstrap session for new commits`)
  }
  expectExactKeys(
    policy.payloadPolicy,
    ['pullRequestExecution', 'publication', 'admittedExecution'],
    `${label}.payloadPolicy`
  )
  if (
    policy.payloadPolicy.pullRequestExecution !== 'disabled' ||
    policy.payloadPolicy.publication !== 'disabled' ||
    policy.payloadPolicy.admittedExecution !== 'protected-exact-commit-only'
  ) {
    fail(`${label}.payloadPolicy must prohibit PR payloads/publication and require protected exact-commit execution`)
  }
  expectExactKeys(policy.ancestryManifest, ['path', 'digest'], `${label}.ancestryManifest`)
  safeRelativePath(policy.ancestryManifest.path, `${label}.ancestryManifest.path`)
  if (typeof policy.ancestryManifest.digest !== 'string' || !DIGEST.test(policy.ancestryManifest.digest)) {
    fail(`${label}.ancestryManifest.digest must be a lowercase sha256 digest`)
  }
  if (policy.releaseLock !== null) {
    expectExactKeys(policy.releaseLock, ['lockFile', 'evidenceFile'], `${label}.releaseLock`)
    safeRelativePath(policy.releaseLock.lockFile, `${label}.releaseLock.lockFile`)
    safeRelativePath(policy.releaseLock.evidenceFile, `${label}.releaseLock.evidenceFile`)
  }
  const requiredSources = [...REQUIRED_GOVERNANCE_SOURCES]
  if (policy.releaseLock) requiredSources.push(policy.releaseLock.lockFile, policy.releaseLock.evidenceFile)
  requiredSources.sort()
  if (new Set(requiredSources).size !== requiredSources.length) {
    fail(`${label}.releaseLock paths must be unique protected governance sources`)
  }
  if (
    !Array.isArray(policy.governanceSources) ||
    new Set(policy.governanceSources).size !== policy.governanceSources.length ||
    !sameJson(policy.governanceSources, requiredSources)
  ) {
    fail(`${label}.governanceSources must be the exact sorted protected-base path manifest`)
  }
  policy.governanceSources.forEach((sourcePath, index) => {
    safeRelativePath(sourcePath, `${label}.governanceSources[${index}]`)
    if (sourcePath !== sourcePath.normalize('NFC') || !/^[\x20-\x7e]+$/.test(sourcePath)) {
      fail(`${label}.governanceSources[${index}] must be normalized ASCII`)
    }
  })
  if (!sameJson(policy.deniedCampaignEnumeration, REQUIRED_DENIED_ENUMERATION)) {
    fail(`${label}.deniedCampaignEnumeration must match the fixed authoritative enumeration rules`)
  }
  if (!sameJson(policy.deniedActions, [...DENIED_ACTION_IDENTITIES])) {
    fail(`${label}.deniedActions must list every structurally forbidden Action identity`)
  }

  if (!Array.isArray(policy.actions) || policy.actions.length !== Object.keys(REQUIRED_ACTION_PROVENANCE).length) {
    fail(`${label}.actions must contain exactly all approved Action identities`)
  }
  const seenActions = new Set()
  for (const [index, action] of policy.actions.entries()) {
    const actionLabel = `${label}.actions[${index}]`
    expectExactKeys(action, ['identity', 'commit', 'tree', 'source', 'verification'], actionLabel)
    if (typeof action.identity !== 'string' || seenActions.has(action.identity)) {
      fail(`${actionLabel}.identity must be unique`)
    }
    seenActions.add(action.identity)
    const required = REQUIRED_ACTION_PROVENANCE[action.identity]
    if (!required) fail(`${actionLabel}.identity is not approved`)
    expectSha(action.commit, `${actionLabel}.commit`)
    expectSha(action.tree, `${actionLabel}.tree`)
    if (action.commit !== required.commit || action.tree !== required.tree) {
      fail(`${actionLabel} commit/tree provenance does not match the approved review`)
    }

    expectExactKeys(action.source, ['type', 'ref', 'tagObject'], `${actionLabel}.source`)
    if (
      action.source.type !== required.source[0] ||
      action.source.ref !== required.source[1] ||
      action.source.tagObject !== required.source[2]
    ) {
      fail(`${actionLabel}.source does not match the reviewed ref/tag provenance`)
    }

    expectExactKeys(action.verification, ['verified', 'reason', 'disposition'], `${actionLabel}.verification`)
    if (
      action.verification.verified !== required.verification[0] ||
      action.verification.reason !== required.verification[1] ||
      action.verification.disposition !== required.verification[2]
    ) {
      fail(`${actionLabel}.verification does not match the reviewed status and disposition`)
    }
  }

  if (!Array.isArray(policy.deniedCampaignCommits) || policy.deniedCampaignCommits.length === 0) {
    fail(`${label}.deniedCampaignCommits must be non-empty`)
  }
  const denied = new Set()
  const deniedSources = new Set()
  let previousSource
  policy.deniedCampaignCommits.forEach((entry, index) => {
    const entryLabel = `${label}.deniedCampaignCommits[${index}]`
    expectExactKeys(entry, ['source', 'mergeBase', 'root', 'tip', 'commitCount'], entryLabel)
    expectSha(entry.mergeBase, `${entryLabel}.mergeBase`)
    expectSha(entry.root, `${entryLabel}.root`)
    expectSha(entry.tip, `${entryLabel}.tip`)
    expectSafeInteger(entry.commitCount, `${entryLabel}.commitCount`, 1)
    if (
      typeof entry.source !== 'string' ||
      !/^(?:refs\/heads\/[A-Za-z0-9._/-]+|pull\/[1-9][0-9]*\/head)$/.test(entry.source)
    ) {
      fail(`${entryLabel}.source must identify an exact branch or pull-request ref`)
    }
    if (deniedSources.has(entry.source)) fail(`${label}.deniedCampaignCommits contains duplicate source ${entry.source}`)
    if (previousSource && compareDeniedSources(previousSource, entry.source) >= 0) {
      fail(`${label}.deniedCampaignCommits must be ordered by source`)
    }
    deniedSources.add(entry.source)
    previousSource = entry.source
    if (denied.has(entry.tip)) fail(`${label}.deniedCampaignCommits contains duplicate tip ${entry.tip}`)
    denied.add(entry.tip)
  })

  return policy
}

let selectedYamlParser

const invokeYamlParser = (parser, contents) => {
  if (typeof parser.parse === 'function') {
    try {
      return parser.parse(contents)
    } catch (error) {
      return { error: error.message }
    }
  }
  const result = childProcess.spawnSync(parser.command, parser.args, {
    input: contents,
    encoding: 'utf8',
    timeout: 10000,
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true
  })
  if (result.error || result.status !== 0 || !result.stdout.trim()) {
    const detail = result.error
      ? result.error.message
      : (result.stderr || `exit ${result.status}`).trim()
    return { error: detail }
  }
  try {
    const parsed = JSON.parse(result.stdout)
    if (!isRecord(parsed) || typeof parsed.parser !== 'string' || !isRecord(parsed.stream)) {
      return { error: 'parser did not report its identity and complete semantic stream' }
    }
    return parsed
  } catch (error) {
    return { error: `invalid parser JSON: ${error.message}` }
  }
}

const parseYaml = (contents, label = 'YAML', parsers) => {
  if (typeof contents !== 'string' || Buffer.byteLength(contents) > 1024 * 1024) {
    fail(`${label} must be UTF-8 YAML no larger than 1 MiB`)
  }
  if (/(?:^|[\r\n]\s*|:\s+|-\s+|[\[,{]\s*)!{1,2}[A-Za-z<]/m.test(contents)) {
    fail(`${label}: executable or custom YAML tags are not allowed`)
  }
  if (/(?:^|\r?\n)\s*\.\.\.\s*(?:#.*)?(?:\r?\n|$)/m.test(contents)) {
    fail(`${label}: explicit YAML document terminators are not allowed`)
  }
  const candidates = parsers || (selectedYamlParser ? [selectedYamlParser] : DEFAULT_YAML_PARSERS)
  if (!Array.isArray(candidates) || candidates.length === 0) {
    fail(`${label}: no approved semantic YAML parser is available`)
  }
  const failures = []
  for (const parser of candidates) {
    const result = invokeYamlParser(parser, contents)
    if (!result.error) {
      const { documentCount, emptyDocuments, documents } = result.stream
      if (
        documentCount !== 1 ||
        !Array.isArray(emptyDocuments) ||
        emptyDocuments.length !== 1 ||
        emptyDocuments[0] !== false ||
        !Array.isArray(documents) ||
        documents.length !== 1
      ) {
        fail(`${label}: YAML must contain exactly one non-empty document`)
      }
      if (!parsers) selectedYamlParser = parser
      return { document: documents[0], parser: result.parser }
    }
    failures.push(`${parser.name}: ${result.error}`)
  }
  fail(`${label}: semantic YAML parsing failed closed (${failures.join('; ')})`)
}

const normalizeRelative = value => value.replace(/^\.\//, '').replace(/\\/g, '/')

const createFileSource = root => {
  const absoluteRoot = path.resolve(root)
  const resolveFile = relative => {
    const normalized = safeRelativePath(normalizeRelative(relative), `candidate path '${relative}'`)
    const absolute = path.resolve(absoluteRoot, ...normalized.split('/'))
    if (absolute !== absoluteRoot && !absolute.startsWith(`${absoluteRoot}${path.sep}`)) {
      fail(`candidate path '${relative}' escapes the checkout`)
    }
    return { absolute, normalized }
  }
  return {
    label: absoluteRoot,
    exists (relative) {
      const { absolute } = resolveFile(relative)
      if (!fs.existsSync(absolute)) return false
      const stat = fs.lstatSync(absolute)
      if (stat.isSymbolicLink()) fail(`${relative} must not be a symbolic link`)
      return stat.isFile()
    },
    read (relative) {
      const { absolute, normalized } = resolveFile(relative)
      if (!fs.existsSync(absolute)) fail(`${normalized} is missing`)
      const stat = fs.lstatSync(absolute)
      if (stat.isSymbolicLink() || !stat.isFile()) fail(`${normalized} must be a regular file`)
      if (stat.size > 2 * 1024 * 1024) fail(`${normalized} exceeds the 2 MiB inspection limit`)
      return fs.readFileSync(absolute, 'utf8')
    },
    list (relative) {
      const { absolute, normalized } = resolveFile(relative)
      if (!fs.existsSync(absolute)) fail(`${normalized} is missing`)
      return fs.readdirSync(absolute, { withFileTypes: true }).map(entry => {
        if (entry.isSymbolicLink()) fail(`${normalized}/${entry.name} must not be a symbolic link`)
        return `${normalized}/${entry.name}`
      })
    }
  }
}

const createGitSource = (repository, revision) => {
  expectSha(revision, 'candidate revision')
  const entry = relative => {
    const normalized = safeRelativePath(normalizeRelative(relative), `candidate path '${relative}'`)
    const output = runGit(['ls-tree', revision, '--', normalized], repository).trim()
    if (!output) return undefined
    const line = output.split('\n').find(value => value.endsWith(`\t${normalized}`))
    if (!line) return undefined
    const match = line.match(/^([0-9]{6}) ([a-z]+) ([0-9a-f]{40})\t/)
    if (!match) fail(`${normalized}: malformed Git tree entry`)
    return { mode: match[1], type: match[2], oid: match[3], path: normalized }
  }
  return {
    label: `${repository}@${revision}`,
    entry,
    exists (relative) {
      const item = entry(relative)
      if (!item) return false
      if (item.mode === '120000') fail(`${item.path} must not be a symbolic link`)
      return item.type === 'blob'
    },
    read (relative) {
      const item = entry(relative)
      if (!item) fail(`${normalizeRelative(relative)} is missing`)
      if (item.mode === '120000' || item.type !== 'blob') {
        fail(`${item.path} must be a regular Git blob`)
      }
      const size = Number(runGit(['cat-file', '-s', `${revision}:${item.path}`], repository).trim())
      if (!Number.isSafeInteger(size) || size > 2 * 1024 * 1024) {
        fail(`${item.path} exceeds the 2 MiB inspection limit`)
      }
      return runGit(['cat-file', 'blob', `${revision}:${item.path}`], repository)
    },
    list (relative) {
      const normalized = safeRelativePath(normalizeRelative(relative), `candidate path '${relative}'`)
      const output = runGit(['ls-tree', '-r', '--name-only', revision, '--', `${normalized}/`], repository).trim()
      return output ? output.split('\n') : []
    },
    listAll () {
      const output = runGit(['ls-tree', '-r', '-z', '--full-tree', revision], repository)
      return output.split('\0').filter(Boolean).map((line, index) => {
        const tab = line.indexOf('\t')
        const match = tab > 0 && line.slice(0, tab).match(/^([0-9]{6}) ([a-z]+) ([0-9a-f]{40})$/)
        if (!match) fail(`Git tree entry ${index} is malformed`)
        return {
          mode: match[1],
          type: match[2],
          oid: match[3],
          path: line.slice(tab + 1)
        }
      })
    }
  }
}

const governanceNamespacePath = value => {
  const normalized = value.normalize('NFC').toLowerCase()
  return (
    normalized === 'add-release-note.js' ||
    normalized === 'validate-arm64-governance.js' ||
    normalized === 'validate-arm64-governance.test.js' ||
    normalized.startsWith('.github/arm64-') ||
    normalized.startsWith('.github/workflows/') ||
    normalized.startsWith('tests/fixtures/arm64-')
  )
}

const validateTrustedSources = (trustedSource, candidateSource, policy) => {
  validateGovernancePolicy(policy)
  for (const source of [trustedSource, candidateSource]) {
    if (typeof source.entry !== 'function' || typeof source.listAll !== 'function') {
      fail(`${source.label || 'source'} must expose exact Git tree entries`)
    }
  }

  const expectedPaths = [...policy.governanceSources].sort()
  const expected = new Set(expectedPaths)
  const trustedEntries = trustedSource.listAll()
  const candidateEntries = candidateSource.listAll()
  const trustedByPath = new Map(trustedEntries.map(entry => [entry.path, entry]))
  const candidateByPath = new Map(candidateEntries.map(entry => [entry.path, entry]))
  const trustedOids = new Map()

  for (const sourcePath of expectedPaths) {
    const trusted = trustedByPath.get(sourcePath)
    if (!trusted || trusted.type !== 'blob' || trusted.mode === '120000') {
      fail(`protected base governance source ${sourcePath} must be a regular Git blob`)
    }
    const candidate = candidateByPath.get(sourcePath)
    if (!candidate) fail(`candidate deleted or renamed protected governance source ${sourcePath}`)
    if (
      candidate.type !== trusted.type ||
      candidate.mode !== trusted.mode ||
      candidate.oid !== trusted.oid
    ) {
      fail(
        `candidate governance source ${sourcePath} differs from protected base ` +
        `(mode ${candidate.mode}/${trusted.mode}, object ${candidate.oid}/${trusted.oid})`
      )
    }
    if (!trustedOids.has(trusted.oid)) trustedOids.set(trusted.oid, [])
    trustedOids.get(trusted.oid).push(sourcePath)
  }

  const canonicalExpected = new Map(expectedPaths.map(sourcePath => [
    sourcePath.normalize('NFC').toLowerCase(),
    sourcePath
  ]))
  for (const entry of candidateEntries) {
    const canonical = entry.path.normalize('NFC').toLowerCase()
    const canonicalSource = canonicalExpected.get(canonical)
    if (canonicalSource && entry.path !== canonicalSource) {
      fail(`candidate governance path ${entry.path} aliases protected path ${canonicalSource}`)
    }
    if (governanceNamespacePath(entry.path) && !expected.has(entry.path)) {
      fail(`candidate added unreviewed governance path ${entry.path}`)
    }
    const copiedFrom = trustedOids.get(entry.oid)
    if (copiedFrom && !expected.has(entry.path)) {
      fail(`candidate copied protected governance source ${copiedFrom.join(', ')} to ${entry.path}`)
    }
  }

  return expectedPaths.map(sourcePath => clone(trustedByPath.get(sourcePath)))
}

const fetchCandidateRepository = (repository, revision) => {
  if (typeof repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    fail('candidate repository must be an exact owner/repository identity')
  }
  expectSha(revision, 'candidate revision')
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'arm64-candidate-'))
  try {
    runGit(['init', '--quiet'], directory)
    runGit(
      ['fetch', '--quiet', '--no-tags', '--force', `https://github.com/${repository}.git`, revision],
      directory
    )
    runGit(['update-ref', 'refs/heads/candidate', revision], directory)
    if (runGit(['rev-parse', 'refs/heads/candidate'], directory).trim() !== revision) {
      fail('credential-free candidate fetch did not resolve the exact requested commit')
    }
    return directory
  } catch (error) {
    fs.rmSync(directory, { recursive: true, force: true })
    throw error
  }
}

const createMemorySource = files => {
  const normalized = new Map(Object.entries(files).map(([file, contents]) => [normalizeRelative(file), contents]))
  return {
    label: 'memory',
    exists: relative => normalized.has(normalizeRelative(relative)),
    read (relative) {
      const file = normalizeRelative(relative)
      if (!normalized.has(file)) fail(`${file} is missing`)
      return normalized.get(file)
    },
    list (relative) {
      const prefix = `${normalizeRelative(relative)}/`
      return [...normalized.keys()].filter(file => file.startsWith(prefix) && !file.slice(prefix.length).includes('/'))
    }
  }
}

const validateActionSpec = (spec, label) => {
  if (typeof spec !== 'string' || !spec) fail(`${label} must be a string`)
  if (spec.startsWith('./')) return { local: normalizeRelative(spec) }
  const match = spec.match(/^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:\/[^@\s]+)?@([0-9a-f]{40})$/)
  if (!match) fail(`${label}: external Action '${spec}' must use a literal lowercase 40-hex commit`)
  const identity = match[1].toLowerCase()
  if (DENIED_ACTION_IDENTITIES.has(identity)) {
    fail(`${label}: ${identity} is forbidden because it resolves mutable SDK inputs dynamically`)
  }
  const approved = APPROVED_ACTION_PINS[identity]
  if (!approved) fail(`${label}: unapproved external Action identity ${identity}`)
  if (match[2] !== approved) fail(`${label}: ${identity} must use approved commit ${approved}, not ${match[2]}`)
  return { identity, sha: match[2] }
}

const walk = (value, callback, label = 'document', depth = 0, state = { count: 0 }) => {
  if (++state.count > 10000 || depth > 100) fail(`${label} exceeds semantic traversal limits`)
  if (Array.isArray(value)) {
    value.forEach((item, index) => walk(item, callback, `${label}[${index}]`, depth + 1, state))
    return
  }
  if (!isRecord(value)) return
  for (const [key, item] of Object.entries(value)) {
    callback(key, item, `${label}.${key}`)
    walk(item, callback, `${label}.${key}`, depth + 1, state)
  }
}

const findForbiddenCommands = contents => FORBIDDEN_COMMANDS
  .filter(([pattern]) => pattern.test(contents))
  .map(([, description]) => description)

const extractDelegatedScripts = command => {
  const scripts = new Set()
  const interpreter = /(?:^|[\s;&|])(?:node|bash|sh|pwsh|powershell|python3?)\s+(?:-[^\s]+\s+)*["']?((?:\.\/)?[A-Za-z0-9_.\/-]+\.(?:js|sh|ps1|py))["']?/g
  const direct = /(?:^|[\s;&|])(\.\/[A-Za-z0-9_.\/-]+\.(?:js|sh|ps1|py))\b/g
  const sourced = /(?:^|[\s;&|])(?:source|\.)\s+["']?((?:\.\/)?[A-Za-z0-9_.\/-]+\.(?:js|sh|ps1|py))["']?/g
  for (const pattern of [interpreter, direct, sourced]) {
    let match
    while ((match = pattern.exec(command)) !== null) scripts.add(normalizeRelative(match[1]))
  }
  return [...scripts]
}

const resolveDelegatedScript = (relative, directory, blocked, findings) => {
  const resolved = path.posix.normalize(path.posix.join(directory, normalizeRelative(relative)))
  if (resolved.startsWith('../') || resolved === '..' || path.posix.isAbsolute(resolved)) {
    if (!blocked) fail(`active delegated script ${relative} escapes the candidate checkout`)
    findings.push(`blocked delegated script escapes the candidate checkout: ${relative}`)
    return undefined
  }
  return resolved
}

const inspectScript = (relative, source, blocked, findings, visited) => {
  if (relative.startsWith('trusted/')) return
  if (visited.has(relative)) return
  visited.add(relative)
  if (!source.exists(relative)) {
    if (!blocked) fail(`active delegated script ${relative} is not a tracked regular file`)
    findings.push(`blocked delegated script is unresolved: ${relative}`)
    return
  }
  const contents = source.read(relative)
  const forbidden = findForbiddenCommands(contents)
  if (forbidden.length) {
    if (!blocked) fail(`${relative}: active delegated script contains ${forbidden.join(', ')}`)
    findings.push(`${relative}: ${forbidden.join(', ')}`)
  }
  const directory = path.posix.dirname(relative)
  extractDelegatedScripts(contents).forEach(script => {
    const resolved = resolveDelegatedScript(script, directory, blocked, findings)
    if (resolved) inspectScript(resolved, source, blocked, findings, visited)
  })
}

const inspectRun = (command, label, source, blocked, findings, visited = new Set()) => {
  if (typeof command !== 'string') fail(`${label} must be a string`)
  const forbidden = findForbiddenCommands(command)
  if (forbidden.length) {
    if (!blocked) fail(`${label}: active command contains ${forbidden.join(', ')}`)
    findings.push(`${label}: ${forbidden.join(', ')}`)
  }
  const scripts = extractDelegatedScripts(command)
  scripts.forEach(script => {
    const resolved = resolveDelegatedScript(script, '', blocked, findings)
    if (resolved) inspectScript(resolved, source, blocked, findings, visited)
  })
  if (
    !blocked &&
    command.trim() !== TRUSTED_ADMISSION_COMMAND &&
    /\b(?:node|bash|sh|pwsh|powershell|python3?)\b/.test(command) &&
    scripts.length === 0
  ) {
    fail(`${label}: dynamic or inline delegated execution is not approved`)
  }
}

const validateLocalAction = (relative, source, blocked, findings, visited) => {
  const directory = normalizeRelative(relative)
  if (visited.has(`action:${directory}`)) return
  visited.add(`action:${directory}`)
  const candidates = [`${directory}/action.yml`, `${directory}/action.yaml`]
  const manifestPath = candidates.find(candidate => source.exists(candidate))
  if (!manifestPath) fail(`${directory} has no tracked action.yml or action.yaml`)
  const parsed = parseYaml(source.read(manifestPath), manifestPath)
  expectRecord(parsed.document, manifestPath)
  walk(parsed.document, (key, value, label) => {
    if (key === 'uses') {
      const action = validateActionSpec(value, label)
      if (action.local) validateLocalAction(action.local, source, blocked, findings, visited)
    }
  }, manifestPath)
  const runs = parsed.document.runs
  expectRecord(runs, `${manifestPath}.runs`)
  if (runs.using === 'composite') {
    if (!Array.isArray(runs.steps)) fail(`${manifestPath}.runs.steps must be an array`)
    runs.steps.forEach((step, index) => {
      expectRecord(step, `${manifestPath}.runs.steps[${index}]`)
      if (step.run !== undefined) {
        inspectRun(step.run, `${manifestPath}.runs.steps[${index}].run`, source, blocked, findings)
      }
    })
  } else {
    for (const key of ['main', 'pre', 'post']) {
      if (runs[key] !== undefined) inspectScript(normalizeRelative(`${directory}/${runs[key]}`), source, blocked, findings, visited)
    }
  }
}

const validateJobSteps = (job, jobLabel, source, blocked, findings) => {
  if (!Array.isArray(job.steps)) return
  const visited = new Set()
  job.steps.forEach((step, index) => {
    const label = `${jobLabel}.steps[${index}]`
    expectRecord(step, label)
    if (step.uses !== undefined) {
      const action = validateActionSpec(step.uses, `${label}.uses`)
      if (action.local) validateLocalAction(action.local, source, blocked, findings, visited)
      if (!blocked && action.identity === 'actions/checkout') {
        const ref = isRecord(step.with) ? step.with.ref : undefined
        const approvedRefs = [
          '${{ github.event.pull_request.base.sha }}',
          '${{ github.event.pull_request.head.sha }}',
          '${{ github.sha }}'
        ]
        if (!approvedRefs.includes(ref)) fail(`${label}: active checkout must use an exact event commit SHA`)
      }
    }
    if (step.run !== undefined) inspectRun(step.run, `${label}.run`, source, blocked, findings, visited)
  })
}

const validateAdmissionJob = (job, label) => {
  expectExactKeys(job, ['if', 'needs', 'runs-on', 'outputs', 'steps'], label)
  if (job.if !== "github.event_name == 'pull_request_target'") {
    fail(`${label}.if must limit admission to pull_request_target`)
  }
  if (job.needs !== 'arm64-governance-tests') {
    fail(`${label}.needs must require the complete trusted governance test job`)
  }
  if (job['runs-on'] !== 'ubuntu-latest') fail(`${label}.runs-on must be ubuntu-latest`)
  expectExactKeys(job.outputs, ['inputs-locked'], `${label}.outputs`)
  if (job.outputs['inputs-locked'] !== '${{ steps.governance.outputs.inputs-locked }}') {
    fail(`${label}.outputs.inputs-locked must come only from the trusted governance step`)
  }
  if (!Array.isArray(job.steps) || job.steps.length !== 3) {
    fail(`${label}.steps must contain exactly one trusted checkout, dependency install, and evaluation`)
  }

  const base = job.steps[0]
  expectExactKeys(base, ['uses', 'with'], `${label}.steps[0]`)
  validateActionSpec(base.uses, `${label}.steps[0].uses`)
  if (base.uses !== `actions/checkout@${APPROVED_ACTION_PINS['actions/checkout']}`) {
    fail(`${label}.steps[0] must use the approved actions/checkout commit`)
  }
  expectExactKeys(base.with, ['ref', 'path', 'persist-credentials'], `${label}.steps[0].with`)
  if (
    base.with.ref !== '${{ github.event.pull_request.base.sha }}' ||
    base.with.path !== 'trusted' ||
    base.with['persist-credentials'] !== false
  ) {
    fail(`${label}.steps[0] must check out the exact base SHA without credentials`)
  }

  const dependency = job.steps[1]
  expectExactKeys(dependency, ['name', 'run'], `${label}.steps[1]`)
  if (
    dependency.name !== 'install trusted governance dependencies' ||
    dependency.run !== TRUSTED_DEPENDENCY_COMMAND
  ) {
    fail(`${label}.steps[1] must install only the lockfile-pinned trusted dependencies`)
  }

  const evaluation = job.steps[2]
  expectExactKeys(evaluation, ['name', 'id', 'env', 'run'], `${label}.steps[2]`)
  if (evaluation.id !== 'governance' || evaluation.run !== TRUSTED_ADMISSION_COMMAND) {
    fail(`${label}.steps[2] must execute only the trusted base validator`)
  }
  expectExactKeys(evaluation.env, ['BASE_SHA', 'HEAD_SHA', 'CANDIDATE_REPOSITORY'], `${label}.steps[2].env`)
  if (
    evaluation.env.BASE_SHA !== '${{ github.event.pull_request.base.sha }}' ||
    evaluation.env.HEAD_SHA !== '${{ github.event.pull_request.head.sha }}' ||
    evaluation.env.CANDIDATE_REPOSITORY !== '${{ github.event.pull_request.head.repo.full_name }}'
  ) {
    fail(`${label}.steps[2].env must use only exact event repository and commit identities`)
  }
}

const validateGovernanceTestJob = (job, label) => {
  expectExactKeys(job, ['runs-on', 'steps'], label)
  if (job['runs-on'] !== 'ubuntu-latest') fail(`${label}.runs-on must be ubuntu-latest`)
  if (!Array.isArray(job.steps) || job.steps.length !== 5) {
    fail(`${label}.steps must contain exact trusted checkouts, install, tests, and mutation proof`)
  }

  const checkouts = [
    {
      name: 'check out trusted pull-request base',
      condition: "github.event_name == 'pull_request_target'",
      ref: '${{ github.event.pull_request.base.sha }}'
    },
    {
      name: 'check out trusted event commit',
      condition: "github.event_name != 'pull_request_target'",
      ref: '${{ github.sha }}'
    }
  ]
  checkouts.forEach((expected, index) => {
    const checkout = job.steps[index]
    const stepLabel = `${label}.steps[${index}]`
    expectExactKeys(checkout, ['name', 'if', 'uses', 'with'], stepLabel)
    if (
      checkout.name !== expected.name ||
      checkout.if !== expected.condition ||
      checkout.uses !== `actions/checkout@${APPROVED_ACTION_PINS['actions/checkout']}`
    ) {
      fail(`${stepLabel} must select only its exact trusted event commit`)
    }
    expectExactKeys(
      checkout.with,
      ['ref', 'path', 'persist-credentials', 'fetch-depth'],
      `${stepLabel}.with`
    )
    if (
      checkout.with.ref !== expected.ref ||
      checkout.with.path !== 'trusted' ||
      checkout.with['persist-credentials'] !== false ||
      checkout.with['fetch-depth'] !== 0
    ) {
      fail(`${stepLabel} must check out complete trusted ancestry without credentials`)
    }
  })

  const commands = [
    ['install trusted governance dependencies', TRUSTED_DEPENDENCY_COMMAND],
    ['run full trusted governance tests', TRUSTED_TEST_COMMAND],
    ['prove trusted governance mutation completeness', TRUSTED_MUTATION_COMMAND]
  ]
  commands.forEach(([name, command], offset) => {
    const index = offset + 2
    const step = job.steps[index]
    const stepLabel = `${label}.steps[${index}]`
    expectExactKeys(step, ['name', 'run'], stepLabel)
    if (step.name !== name || step.run !== command) {
      fail(`${stepLabel} must run only the exact trusted ${name}`)
    }
  })
}

const workflowTrigger = workflow => (
  workflow.on !== undefined ? workflow.on : workflow.true
)

const validateMainWorkflow = (workflow, label, source) => {
  const normalized = { ...workflow }
  if (normalized.on === undefined && normalized.true !== undefined) {
    normalized.on = normalized.true
    delete normalized.true
  }
  expectExactKeys(normalized, ['name', 'on', 'permissions', 'jobs'], label)
  if (normalized.name !== 'ARM64 PR governance') fail(`${label}.name must identify the trusted governance workflow`)
  const trigger = workflowTrigger(normalized)
  if (
    !isRecord(trigger) ||
    !sameJson(Object.keys(trigger), ['pull_request_target', 'push', 'workflow_dispatch']) ||
    Object.values(trigger).some(value => value !== null)
  ) {
    fail(`${label} must run exact trusted tests on pushes and admission on pull_request_target`)
  }
  expectExactKeys(normalized.permissions, ['contents'], `${label}.permissions`)
  if (normalized.permissions.contents !== 'read') fail(`${label}.permissions.contents must be read`)
  expectRecord(normalized.jobs, `${label}.jobs`)
  if (!sameJson(Object.keys(normalized.jobs), ['arm64-governance-tests', 'arm64-governance'])) {
    fail(`${label} must contain only the trusted governance test and admission jobs`)
  }
  validateGovernanceTestJob(
    normalized.jobs['arm64-governance-tests'],
    `${label}.jobs.arm64-governance-tests`
  )
  validateAdmissionJob(normalized.jobs['arm64-governance'], `${label}.jobs.arm64-governance`)

  const findings = []
  validateJobSteps(
    normalized.jobs['arm64-governance-tests'],
    `${label}.jobs.arm64-governance-tests`,
    source,
    false,
    findings
  )
  validateJobSteps(
    normalized.jobs['arm64-governance'],
    `${label}.jobs.arm64-governance`,
    source,
    false,
    findings
  )
  return findings
}

const validateWorkflowSet = (source, policy) => {
  validateGovernancePolicy(policy)
  const files = source.list('.github/workflows')
    .filter(file => /\.ya?ml$/i.test(file))
    .sort()
  if (files.length === 0) fail(`${source.label} contains no workflow files`)

  const inventory = []
  const blockedFindings = []
  let parser
  let mainFound = false
  for (const file of files) {
    const parsed = parseYaml(source.read(file), file)
    parser = parsed.parser
    expectRecord(parsed.document, file)
    walk(parsed.document, (key, value, label) => {
      if (key !== 'uses') return
      const action = validateActionSpec(value, label)
      if (action.identity) inventory.push(action)
    }, file)
    if (file === '.github/workflows/main.yml') {
      mainFound = true
      blockedFindings.push(...validateMainWorkflow(parsed.document, file, source))
    }
  }
  const expectedWorkflows = [
    ...policy.governanceSources.filter(file => file.startsWith('.github/workflows/'))
  ]
  if (!sameJson(files, expectedWorkflows)) {
    fail(`workflow set must be exactly ${expectedWorkflows.join(', ')}`)
  }
  if (!mainFound) fail('.github/workflows/main.yml is required')
  return { blockedFindings, inventory, parser }
}

const emptyGitConfigDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'arm64-governance-git-'))
const emptyGitConfig = path.join(emptyGitConfigDirectory, 'empty.gitconfig')
fs.writeFileSync(emptyGitConfig, '')
process.once('exit', () => fs.rmSync(emptyGitConfigDirectory, { recursive: true, force: true }))

const gitEnvironment = () => ({
  ...process.env,
  GIT_CONFIG_GLOBAL: emptyGitConfig,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_TERMINAL_PROMPT: '0'
})

const runGit = (args, cwd, options = {}) => {
  const result = childProcess.spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: gitEnvironment(),
    input: options.input,
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true
  })
  if (result.error || result.status !== 0) {
    const detail = result.error ? result.error.message : result.stderr.trim()
    fail(`git ${args.join(' ')} failed${detail ? `: ${detail}` : ''}`)
  }
  return result.stdout
}

const commitMessage = (commit, cwd) => {
  const object = runGit(['cat-file', 'commit', commit], cwd)
  const separator = object.indexOf('\n\n')
  if (separator < 0) fail(`${commit}: malformed commit object`)
  return object.slice(separator + 2)
}

const interpretTrailers = (message, cwd) => runGit(
  ['-c', 'trailer.separators=:', 'interpret-trailers', '--parse'],
  cwd,
  { input: message }
).trimEnd().split('\n').filter(Boolean)

const validateOwnedCommitMessage = (message, authorizedSessions, cwd = process.cwd(), label = 'commit') => {
  const authorized = expectAuthorizedSessions(authorizedSessions, label)
  if (message.includes('\r')) fail(`${label}: commit message must use LF line endings`)
  if (!message.endsWith('\n') || message.endsWith('\n\n')) {
    fail(`${label}: owned commit must end immediately after the Copilot-Session trailer`)
  }
  const lines = message.slice(0, -1).split('\n')
  if (lines.length < 3) {
    fail(`${label}: owned commit must end with the exact expected Co-authored-by and Copilot-Session pair`)
  }
  const terminal = lines[lines.length - 1]
  const recorded = terminal.startsWith(SESSION_TRAILER_PREFIX)
    ? terminal.slice(SESSION_TRAILER_PREFIX.length)
    : ''
  if (!UUID.test(recorded) || !authorized.includes(recorded)) {
    fail(`${label}: terminal Copilot-Session trailer must name a session authorized by the trusted policy`)
  }
  const expectedSessionTrailer = `${SESSION_TRAILER_PREFIX}${recorded}`
  if (lines[lines.length - 2] !== COPILOT_COAUTHOR) {
    fail(`${label}: owned commit must end with the exact expected Co-authored-by and Copilot-Session pair`)
  }

  const rawSessions = lines.filter(line => /^Copilot-Session\s*:/i.test(line))
  const rawCopilotAuthors = lines.filter(line => /^Co-authored-by\s*:\s*Copilot App\b/i.test(line))
  if (rawSessions.length !== 1 || rawSessions[0] !== expectedSessionTrailer) {
    fail(`${label}: Copilot-Session trailer is missing, duplicated, malformed, or belongs to another session`)
  }
  if (rawCopilotAuthors.length !== 1 || rawCopilotAuthors[0] !== COPILOT_COAUTHOR) {
    fail(`${label}: Copilot App co-author trailer is missing, duplicated, or malformed`)
  }

  const trailers = interpretTrailers(message, cwd)
  if (
    trailers.length < 2 ||
    trailers[trailers.length - 2] !== COPILOT_COAUTHOR ||
    trailers[trailers.length - 1] !== expectedSessionTrailer
  ) {
    fail(`${label}: Git did not parse the exact terminal Copilot trailer pair`)
  }
  const parsedSessions = trailers.filter(line => /^Copilot-Session:/i.test(line))
  const parsedCopilotAuthors = trailers.filter(line => /^Co-authored-by:\s*Copilot App\b/i.test(line))
  if (parsedSessions.length !== 1 || parsedCopilotAuthors.length !== 1) {
    fail(`${label}: Git parsed duplicate or spacing-variant Copilot trailers`)
  }
  if (!trailers.some(line => /^Signed-off-by: \S.* <[^<>]+>$/.test(line))) {
    fail(`${label}: DCO Signed-off-by trailer is required before the terminal Copilot pair`)
  }
  return true
}

const validateCommitRange = (
  base,
  head,
  authorizedSessions,
  deniedCampaignCommits,
  cwd = process.cwd(),
  options = {}
) => {
  expectSha(base, 'base commit')
  expectSha(head, 'head commit')
  const authorized = expectAuthorizedSessions(authorizedSessions, 'owned commit range')
  if (!Array.isArray(deniedCampaignCommits)) fail('denied campaign commit list is required')

  const resolvedBase = runGit(['rev-parse', '--verify', `${base}^{commit}`], cwd).trim()
  const resolvedHead = runGit(['rev-parse', '--verify', `${head}^{commit}`], cwd).trim()
  if (resolvedBase !== base || resolvedHead !== head) fail('commit range endpoints did not resolve exactly')
  const mergeBases = runGit(['merge-base', '--all', base, head], cwd).trim().split('\n').filter(Boolean)
  if (mergeBases.length !== 1 || mergeBases[0] !== base) {
    fail(`candidate merge-base must equal the supplied base ${base}`)
  }
  if (runGit(['rev-parse', '--is-shallow-repository'], cwd).trim() !== 'false') {
    fail('candidate repository must contain complete, non-shallow ancestry')
  }

  const commits = runGit(['rev-list', '--reverse', `${base}..${head}`], cwd).trim().split('\n').filter(Boolean)
  if (commits.length === 0) fail('owned commit range must be non-empty')
  const denied = new Set(deniedCampaignCommits.flatMap(entry => (
    typeof entry === 'string' ? [entry] : [entry.root, entry.tip]
  )))
  const sessionExceptions = options.sessionExceptions || {}
  for (const commit of commits) {
    if (denied.has(commit)) fail(`${commit}: denied campaign commit is present in the owned range`)
    const parents = runGit(['rev-list', '--parents', '-n', '1', commit], cwd).trim().split(/\s+/)
    if (parents.length !== 2) fail(`${commit}: merge commits are not allowed in the owned range`)
    const commitSession = sessionExceptions[commit] || authorized
    validateOwnedCommitMessage(commitMessage(commit, cwd), commitSession, cwd, commit)
  }

  return { base, commits, head, mergeBase: base }
}

const loadJson = (source, relative, label = relative) => {
  try {
    return JSON.parse(source.read(relative))
  } catch (error) {
    fail(`${label}: invalid JSON: ${error.message}`)
  }
}

const appendLockedOutput = locked => {
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `inputs-locked=${locked ? 'true' : 'false'}\n`)
  }
}

const requireReleaseLock = policy => {
  if (policy.releaseLock === null) {
    fail('admission denied: releaseLock must bind a complete live-authoritative release and independent digest evidence')
  }
  return policy.releaseLock
}

const validateAdmission = async (trustedRoot, candidateRepository, base, head, options = {}) => {
  appendLockedOutput(false)
  const trustedHead = runGit(['rev-parse', 'HEAD'], trustedRoot).trim()
  if (trustedHead !== base) fail(`trusted checkout HEAD ${trustedHead} does not equal supplied base ${base}`)
  const trustedSource = createGitSource(trustedRoot, base)
  const candidateRoot = fetchCandidateRepository(candidateRepository, head)
  try {
    const candidateSource = createGitSource(candidateRoot, head)
    const trustedPolicy = validateGovernancePolicy(loadJson(trustedSource, '.github/arm64-governance.json'))
    const sourceManifest = validateTrustedSources(trustedSource, candidateSource, trustedPolicy)
    const candidatePolicy = validateGovernancePolicy(loadJson(candidateSource, '.github/arm64-governance.json'))
    if (!sameJson(candidatePolicy, trustedPolicy)) fail('candidate governance policy differs from the trusted base policy')

    const workflows = validateWorkflowSet(candidateSource, trustedPolicy)
    if (workflows.parser !== 'js-yaml@4.3.2') {
      fail(`admission requires lockfile-pinned js-yaml@4.3.2, not ${workflows.parser}`)
    }
    const topology = validateCommitRange(
      base,
      head,
      trustedPolicy.authorizedSessions,
      trustedPolicy.deniedCampaignCommits,
      candidateRoot,
      {
        sessionExceptions: {
          [trustedPolicy.bootstrap.commit]: trustedPolicy.bootstrap.session
        }
      }
    )
    const ancestryContents = trustedSource.read(trustedPolicy.ancestryManifest.path)
    if (candidateSource.read(candidatePolicy.ancestryManifest.path) !== ancestryContents) {
      fail('candidate ancestry manifest differs from the trusted base manifest')
    }
    const ancestry = validateAncestryManifest(trustedPolicy, ancestryContents, topology.commits)

    const releaseLock = requireReleaseLock(trustedPolicy)
    const lock = loadJson(trustedSource, releaseLock.lockFile)
    const evidence = loadJson(trustedSource, releaseLock.evidenceFile)
    await verifyReleaseInput(lock, evidence, options.api || createGitHubApi())
    appendLockedOutput(true)
    return { ancestry, locked: true, sourceManifest, topology, workflows }
  } finally {
    fs.rmSync(candidateRoot, { recursive: true, force: true })
  }
}

const uniquePins = inventory => [...new Set(inventory.map(({ identity, sha }) => `${identity}@${sha}`))].sort()

const usage = () => [
  'usage:',
  '  node validate-arm64-governance.js admission <trusted> <candidate-repository> <base> <head>',
  '  node validate-arm64-governance.js workflows [repository-root]',
  '  node validate-arm64-governance.js commits <base> <head> [policy.json]',
  '  node validate-arm64-governance.js provenance [policy.json]',
  '  node validate-arm64-governance.js ancestry offline <fixture.json>',
  '  node validate-arm64-governance.js ancestry live <candidate-commit>...',
  '  node validate-arm64-governance.js ancestry collect <candidate-commit> <output.json>',
  '  node validate-arm64-governance.js ancestry manifest <candidate-commit>...',
  '  node validate-arm64-governance.js release-input offline <fixture.json>',
  '  node validate-arm64-governance.js release-input live <lock.json> <evidence.json>'
].join('\n')

const main = async () => {
  const [command, ...args] = process.argv.slice(2)
  if (command === 'admission') {
    if (args.length !== 4) fail(usage())
    const result = await validateAdmission(args[0], args[1], args[2], args[3])
    process.stdout.write(
      `trusted admission evaluated ${result.topology.commits.length} commit(s); ` +
      `parser=${result.workflows.parser}; ancestry=${result.ancestry.digest}; inputs-locked=${result.locked}\n`
    )
    return
  }
  if (command === 'workflows') {
    if (args.length > 1) fail(usage())
    const root = args[0] || '.'
    const source = createFileSource(root)
    const policy = validateGovernancePolicy(loadJson(source, '.github/arm64-governance.json'))
    const result = validateWorkflowSet(source, policy)
    process.stdout.write(`semantic-parser=${result.parser}\n`)
    uniquePins(result.inventory).forEach(pin => process.stdout.write(`${pin}\n`))
    result.blockedFindings.forEach(finding => process.stdout.write(`blocked: ${finding}\n`))
    return
  }
  if (command === 'commits') {
    if (args.length < 2 || args.length > 3) fail(usage())
    const policyPath = args[2] || '.github/arm64-governance.json'
    const source = createFileSource('.')
    const policy = validateGovernancePolicy(JSON.parse(fs.readFileSync(policyPath, 'utf8')))
    const result = validateCommitRange(
      args[0],
      args[1],
      policy.authorizedSessions,
      policy.deniedCampaignCommits,
      process.cwd(),
      {
        sessionExceptions: {
          [policy.bootstrap.commit]: policy.bootstrap.session
        }
      }
    )
    process.stdout.write(`validated ${result.commits.length} owned non-merge commit(s) from exact base ${result.base}\n`)
    return
  }
  if (command === 'provenance') {
    if (args.length > 1) fail(usage())
    const policy = validateGovernancePolicy(JSON.parse(fs.readFileSync(args[0] || '.github/arm64-governance.json', 'utf8')))
    policy.actions.forEach(action => {
      process.stdout.write(
        `${action.identity}@${action.commit} tree=${action.tree} source=${action.source.ref} ` +
        `verified=${action.verification.verified} disposition=${action.verification.disposition}\n`
      )
    })
    return
  }
  if (command === 'ancestry') {
    const policy = validateGovernancePolicy(JSON.parse(fs.readFileSync('.github/arm64-governance.json', 'utf8')))
    let result
    if (args[0] === 'offline' && args.length === 2) {
      const fixture = JSON.parse(fs.readFileSync(args[1], 'utf8'))
      expectExactKeys(fixture, ['deniedCampaignCommits', 'candidate', 'api'], 'offline ancestry fixture')
      policy.deniedCampaignCommits = fixture.deniedCampaignCommits
      validateGovernancePolicy(policy)
      result = await verifyDeniedAncestry(
        policy,
        fixture.candidate.cleanCommits,
        createFixtureApi(fixture.api)
      )
    } else if (args[0] === 'live' && args.length > 1) {
      result = await verifyDeniedAncestry(policy, args.slice(1), createGitHubApi())
    } else if (args[0] === 'collect' && args.length === 3) {
      result = await verifyDeniedAncestry(policy, [args[1]], createGitHubApi(process.env.GITHUB_TOKEN))
      const contents = serializeAncestryManifest(policy, result.collected)
      fs.writeFileSync(args[2], contents)
      const digest = `sha256:${crypto.createHash('sha256').update(contents).digest('hex')}`
      process.stdout.write(`wrote trusted ancestry manifest ${digest}\n`)
      return
    } else if (args[0] === 'manifest' && args.length > 1) {
      const contents = fs.readFileSync(policy.ancestryManifest.path, 'utf8')
      result = validateAncestryManifest(policy, contents, args.slice(1))
    } else {
      fail(usage())
    }
    process.stdout.write(`validated complete denied ancestry proof ${result.digest}\n`)
    return
  }
  if (command === 'release-input') {
    if (args[0] === 'offline' && args.length === 2) {
      const fixture = JSON.parse(fs.readFileSync(args[1], 'utf8'))
      expectExactKeys(fixture, ['lock', 'evidence', 'api'], 'offline release fixture')
      await verifyReleaseInput(fixture.lock, fixture.evidence, createFixtureApi(fixture.api))
      process.stdout.write('validated immutable release input against deterministic offline API fixtures\n')
      return
    }
    if (args[0] === 'live' && args.length === 3) {
      const lock = JSON.parse(fs.readFileSync(args[1], 'utf8'))
      const evidence = JSON.parse(fs.readFileSync(args[2], 'utf8'))
      await verifyReleaseInput(lock, evidence, createGitHubApi(process.env.GITHUB_TOKEN))
      process.stdout.write('validated immutable release input against live authoritative API metadata\n')
      return
    }
    fail(usage())
  }
  fail(usage())
}

if (require.main === module) {
  main().catch(error => {
    process.stderr.write(`${error.message}\n`)
    process.exit(1)
  })
}

module.exports = {
  APPROVED_ACTION_PINS,
  COPILOT_COAUTHOR,
  DEFAULT_YAML_PARSERS,
  REQUIRED_ACTION_PROVENANCE,
  REQUIRED_GOVERNANCE_SOURCES,
  TRUSTED_ADMISSION_COMMAND,
  TRUSTED_DEPENDENCY_COMMAND,
  TRUSTED_MUTATION_COMMAND,
  TRUSTED_TEST_COMMAND,
  createFileSource,
  createFixtureApi,
  createGitSource,
  createMemorySource,
  enumerateDeniedCampaignSources,
  gitEnvironment,
  inspectRun,
  parseYaml,
  requireReleaseLock,
  validateActionSpec,
  validateAdmission,
  validateAncestryManifest,
  validateCommitRange,
  validateDigestEvidence,
  validateGovernancePolicy,
  validateLocalAction,
  validateOwnedCommitMessage,
  validateReleaseLock,
  validateTrustedSources,
  validateWorkflowSet,
  verifyDeniedAncestry,
  verifyReleaseInput
}
