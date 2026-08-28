#!/usr/bin/env node

'use strict'

const assert = require('assert')
const childProcess = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const os = require('os')
const path = require('path')

const {
  APPROVED_ACTION_PINS,
  COPILOT_COAUTHOR,
  DEFAULT_YAML_PARSERS,
  createFileSource,
  createFixtureApi,
  createGitSource,
  createMemorySource,
  inspectRun,
  parseYaml,
  validateActionSpec,
  validateAncestryManifest,
  validateCommitRange,
  validateGovernancePolicy,
  validateLocalAction,
  validateOwnedCommitMessage,
  validateWorkflowSet,
  verifyDeniedAncestry,
  verifyReleaseInput
} = require('./validate-arm64-governance')

const tests = []

const test = (name, callback) => tests.push({ name, callback })

const rejects = (name, callback) => test(name, async () => {
  await assert.rejects(Promise.resolve().then(callback))
})

const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'))
const clone = value => JSON.parse(JSON.stringify(value))
const policy = readJson('.github/arm64-governance.json')
const ancestryFixture = readJson('tests/fixtures/arm64-ancestry-api.json')
const releaseFixture = readJson('tests/fixtures/arm64-release-api.json')
const mainWorkflow = fs.readFileSync('.github/workflows/main.yml', 'utf8')
const ancestryManifest = fs.readFileSync('.github/arm64-denied-ancestry.json', 'utf8')

const workflowSource = (extraWorkflow, files = {}) => createMemorySource({
  '.github/workflows/main.yml': mainWorkflow,
  '.github/workflows/extra.yml': extraWorkflow,
  '.github/arm64-governance.json': JSON.stringify(policy),
  ...files
})

test('uses an approved semantic YAML parser', () => {
  assert.strictEqual(DEFAULT_YAML_PARSERS[0].name, 'powershell-yaml')
  const parsed = parseYaml('value: true\n', 'parser probe')
  assert.strictEqual(parsed.document.value, true)
  assert.ok(DEFAULT_YAML_PARSERS.some(parser => parsed.parser.startsWith(`${parser.name}@`)))
})

rejects('fails closed without a semantic YAML parser', () => {
  parseYaml('value: true\n', 'parser probe', [])
})

rejects('rejects custom executable YAML tags before parsing', () => {
  parseYaml('value: !example/object payload\n', 'tagged YAML')
})

rejects('rejects custom executable YAML tags in flow collections', () => {
  parseYaml('value: [!example/object payload]\n', 'flow-tagged YAML')
})

for (const [identity, sha] of Object.entries(APPROVED_ACTION_PINS)) {
  test(`accepts ${identity} approved commit`, () => {
    assert.deepStrictEqual(validateActionSpec(`${identity}@${sha}`, identity), { identity, sha })
  })
  rejects(`rejects ${identity} mutable ref`, () => {
    validateActionSpec(`${identity}@v1`, identity)
  })
  rejects(`rejects ${identity} unapproved commit`, () => {
    const replacement = `${sha[0] === '0' ? '1' : '0'}${sha.slice(1)}`
    validateActionSpec(`${identity}@${replacement}`, identity)
  })
}

rejects('rejects an unapproved Action identity at a literal commit', () => {
  validateActionSpec(`evil/action@${'a'.repeat(40)}`, 'evil action')
})

rejects('semantically rejects a quoted uses key', () => {
  validateWorkflowSet(workflowSource('jobs:\n  test:\n    steps:\n      - "uses": evil/action@v1\n'), policy)
})

rejects('semantically rejects a flow-mapping uses key', () => {
  validateWorkflowSet(workflowSource('jobs: { test: { steps: [ { uses: evil/action@v1 } ] } }\n'), policy)
})

rejects('semantically rejects an aliased quoted uses key', () => {
  validateWorkflowSet(workflowSource([
    'shared: &shared',
    '  "uses": evil/action@v1',
    'jobs:',
    '  test:',
    '    steps:',
    '      - *shared',
    ''
  ].join('\n')), policy)
})

rejects('semantically resolves and rejects a merged uses key', () => {
  validateWorkflowSet(workflowSource([
    'shared: &shared',
    '  "uses": evil/action@v1',
    'jobs:',
    '  test:',
    '    steps:',
    '      - <<: *shared',
    ''
  ].join('\n')), policy)
})

rejects('candidate cannot replace the trusted validator with a no-op', () => {
  const source = workflowSource(
    'jobs:\n  test:\n    steps:\n      - "uses": evil/action@v1\n',
    { 'validate-arm64-governance.js': 'process.exit(0)\n' }
  )
  validateWorkflowSet(source, policy)
})

rejects('rejects a constructed release URL downloader', () => {
  inspectRun(
    'ROOT=https://example.invalid/project/releases; curl "$ROOT/download/v1/input.zip"',
    'constructed download',
    createMemorySource({}),
    false,
    []
  )
})

rejects('rejects an active mutable Git clone', () => {
  inspectRun(
    'git clone --branch=main https://github.com/example/project input',
    'mutable clone',
    createMemorySource({}),
    false,
    []
  )
})

test('detects but permits mutable Git only behind the structural lock', () => {
  const findings = []
  inspectRun(
    'git clone --branch=main https://github.com/example/project input',
    'blocked clone',
    createMemorySource({}),
    true,
    findings
  )
  assert.ok(findings.some(finding => finding.includes('mutable Git network command')))
})

rejects('recursively rejects a delegated downloader script', () => {
  inspectRun(
    'sh scripts/fetch.sh',
    'delegated script',
    createMemorySource({ 'scripts/fetch.sh': 'curl "$ROOT/download/input.zip"\n' }),
    false,
    []
  )
})

rejects('recursively rejects a local Action downloader', () => {
  const source = createMemorySource({
    '.github/actions/fetch/action.yml': [
      'name: fetch',
      'runs:',
      '  using: composite',
      '  steps:',
      '    - shell: bash',
      '      run: curl "$ROOT/download/input.zip"',
      ''
    ].join('\n')
  })
  validateLocalAction('.github/actions/fetch', source, false, [], new Set())
})

test('validates the data-only workflow architecture semantically', () => {
  const result = validateWorkflowSet(createFileSource('.'), validateGovernancePolicy(policy))
  assert.ok(/^(?:powershell-yaml|ruby-psych)@/.test(result.parser))
  assert.deepStrictEqual(result.blockedFindings, [])
  assert.strictEqual(result.inventory.filter(action => action.identity === 'actions/checkout').length, 1)
  assert.ok(!mainWorkflow.includes('upload-artifact'))
  assert.ok(!mainWorkflow.includes('setup-git-for-windows-sdk'))
  assert.ok(!mainWorkflow.includes('secrets.'))
  assert.deepStrictEqual(
    [...new Set(result.inventory.map(action => action.identity))].sort(),
    [
      'actions/checkout',
      'actions/github-script'
    ]
  )
})

test('records bootstrap and protected payload policy explicitly', () => {
  assert.deepStrictEqual(policy.bootstrap, {
    pullRequest: 17,
    selfAdmission: false,
    requiredReview: 'independent-read-only-audit',
    commit: '737ea2e89258b19defcf347af37eeac64cf16e2c',
    session: 'b3c52e9a-e880-4744-82aa-225db6ff93ef'
  })
  assert.deepStrictEqual(policy.payloadPolicy, {
    pullRequestExecution: 'disabled',
    publication: 'disabled',
    admittedExecution: 'protected-exact-commit-only'
  })
})

rejects('rejects any payload job in pull_request_target', () => {
  const modified = `${mainWorkflow}\n  payload:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo payload\n`
  validateWorkflowSet(createMemorySource({
    '.github/workflows/main.yml': modified,
    '.github/arm64-governance.json': JSON.stringify(policy)
  }), policy)
})

rejects('rejects elevated pull_request_target permissions', () => {
  const modified = mainWorkflow.replace('contents: read', 'contents: write')
  validateWorkflowSet(createMemorySource({
    '.github/workflows/main.yml': modified,
    '.github/arm64-governance.json': JSON.stringify(policy)
  }), policy)
})

rejects('rejects changes to an allowlisted delegated manual-workflow script', () => {
  validateWorkflowSet(createMemorySource({
    '.github/workflows/main.yml': mainWorkflow,
    '.github/workflows/add-release-note.yml': fs.readFileSync('.github/workflows/add-release-note.yml', 'utf8'),
    '.github/arm64-governance.json': JSON.stringify(policy),
    'add-release-note.js': 'process.exit(0)\n'
  }), policy)
})

rejects('rejects publication commands in active execution', () => {
  inspectRun('gh release upload v1 payload.zip', 'publication', createMemorySource({}), false, [])
})

rejects('rejects candidate execution in place of the trusted admission command', () => {
  const replaced = mainWorkflow.replace(
    'node trusted/validate-arm64-governance.js admission trusted "$CANDIDATE_REPOSITORY" "$BASE_SHA" "$HEAD_SHA"',
    'node candidate/validate-arm64-governance.js admission trusted "$CANDIDATE_REPOSITORY" "$BASE_SHA" "$HEAD_SHA"'
  )
  const source = createMemorySource({
    '.github/workflows/main.yml': replaced,
    '.github/arm64-governance.json': JSON.stringify(policy),
    'candidate/validate-arm64-governance.js': 'process.exit(0)\n'
  })
  validateWorkflowSet(source, policy)
})

test('validates all six Action provenance records', () => {
  validateGovernancePolicy(policy)
  assert.strictEqual(policy.actions.length, 6)
})

test('records setup-msys2 as an explicit required unsigned exception', () => {
  const setup = policy.actions.find(action => action.identity === 'msys2/setup-msys2')
  assert.strictEqual(setup.verification.verified, false)
  assert.strictEqual(setup.verification.reason, 'unsigned')
  assert.strictEqual(setup.verification.disposition, 'policy-required-exception')
})

test('records the SDK Action unsigned source-ref review', () => {
  const setup = policy.actions.find(action => action.identity === 'git-for-windows/setup-git-for-windows-sdk')
  assert.strictEqual(setup.verification.verified, false)
  assert.strictEqual(setup.verification.disposition, 'unsigned-source-ref-review')
})

test('records github-script v9 as an annotated tag peeled to the pinned commit', () => {
  const action = policy.actions.find(entry => entry.identity === 'actions/github-script')
  assert.strictEqual(action.source.type, 'annotated-tag')
  assert.strictEqual(action.source.ref, 'refs/tags/v9')
  assert.strictEqual(action.source.tagObject, '373c709c69115d41ff229c7e5df9f8788daa9553')
  assert.strictEqual(action.commit, '3a2844b7e9c422d3c10d287c895573f7108da1b3')
})

rejects('rejects altered Action tree provenance', () => {
  const altered = clone(policy)
  altered.actions[0].tree = '0'.repeat(40)
  validateGovernancePolicy(altered)
})

rejects('rejects a hidden unsigned setup-msys2 disposition', () => {
  const altered = clone(policy)
  const setup = altered.actions.find(action => action.identity === 'msys2/setup-msys2')
  setup.verification.verified = true
  setup.verification.reason = 'valid'
  setup.verification.disposition = 'verified'
  validateGovernancePolicy(altered)
})

rejects('rejects an incomplete Action provenance set', () => {
  const altered = clone(policy)
  altered.actions.pop()
  validateGovernancePolicy(altered)
})

test('verifies immutable release identity against offline API fixtures', async () => {
  await verifyReleaseInput(
    clone(releaseFixture.lock),
    clone(releaseFixture.evidence),
    createFixtureApi(clone(releaseFixture.api))
  )
})

rejects('rejects a nonexistent authoritative repository', async () => {
  const api = clone(releaseFixture.api)
  delete api['/repos/example/project']
  await verifyReleaseInput(clone(releaseFixture.lock), clone(releaseFixture.evidence), createFixtureApi(api))
})

rejects('rejects a fabricated release ID', async () => {
  const lock = clone(releaseFixture.lock)
  lock.release.id = 9999
  const evidence = clone(releaseFixture.evidence)
  evidence.releaseId = 9999
  await verifyReleaseInput(lock, evidence, createFixtureApi(clone(releaseFixture.api)))
})

rejects('rejects authoritative mutable release metadata', async () => {
  const api = clone(releaseFixture.api)
  api['/repos/example/project/releases/1234'].immutable = false
  await verifyReleaseInput(clone(releaseFixture.lock), clone(releaseFixture.evidence), createFixtureApi(api))
})

rejects('rejects a lightweight authoritative tag', async () => {
  const api = clone(releaseFixture.api)
  api['/repos/example/project/git/ref/tags/v1.2.3'].object.type = 'commit'
  await verifyReleaseInput(clone(releaseFixture.lock), clone(releaseFixture.evidence), createFixtureApi(api))
})

rejects('rejects a moved authoritative tag', async () => {
  const api = clone(releaseFixture.api)
  api['/repos/example/project/git/ref/tags/v1.2.3'].object.sha = '9'.repeat(40)
  await verifyReleaseInput(clone(releaseFixture.lock), clone(releaseFixture.evidence), createFixtureApi(api))
})

rejects('rejects a fabricated peeled commit', async () => {
  const lock = clone(releaseFixture.lock)
  lock.tag.peeledCommitSha = '8'.repeat(40)
  const evidence = clone(releaseFixture.evidence)
  evidence.peeledCommitSha = '8'.repeat(40)
  await verifyReleaseInput(lock, evidence, createFixtureApi(clone(releaseFixture.api)))
})

rejects('rejects a fabricated peeled tree', async () => {
  const lock = clone(releaseFixture.lock)
  lock.tag.peeledTreeSha = '7'.repeat(40)
  await verifyReleaseInput(lock, clone(releaseFixture.evidence), createFixtureApi(clone(releaseFixture.api)))
})

rejects('rejects a partial expected asset list', async () => {
  const lock = clone(releaseFixture.lock)
  lock.assets.pop()
  lock.release.assetCount = 1
  const evidence = clone(releaseFixture.evidence)
  evidence.assets.pop()
  await verifyReleaseInput(lock, evidence, createFixtureApi(clone(releaseFixture.api)))
})

rejects('rejects an authoritative decoy asset', async () => {
  const api = clone(releaseFixture.api)
  api['/repos/example/project/releases/1234'].assets.push({
    id: 5680,
    name: 'decoy.zip',
    size: 1,
    digest: `sha256:${'6'.repeat(64)}`
  })
  await verifyReleaseInput(clone(releaseFixture.lock), clone(releaseFixture.evidence), createFixtureApi(api))
})

rejects('rejects an authoritative asset digest mismatch', async () => {
  const api = clone(releaseFixture.api)
  api['/repos/example/project/releases/1234'].assets[0].digest = `sha256:${'6'.repeat(64)}`
  await verifyReleaseInput(clone(releaseFixture.lock), clone(releaseFixture.evidence), createFixtureApi(api))
})

rejects('rejects unbound independent redownload evidence', async () => {
  const evidence = clone(releaseFixture.evidence)
  evidence.assets[0].digest = `sha256:${'6'.repeat(64)}`
  await verifyReleaseInput(clone(releaseFixture.lock), evidence, createFixtureApi(clone(releaseFixture.api)))
})

rejects('rejects URL-only release lock carriers', async () => {
  const lock = clone(releaseFixture.lock)
  lock.assets = [{ url: 'https://example.invalid/input-arm64.zip' }]
  await verifyReleaseInput(lock, clone(releaseFixture.evidence), createFixtureApi(clone(releaseFixture.api)))
})

const git = (cwd, args, input) => {
  const result = childProcess.spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    input,
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1'
    }
  })
  if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(' ')} failed`)
  return result.stdout.trim()
}

const ownedMessage = (session, subject = 'Owned change', extraTrailers = []) => [
  subject,
  '',
  'Signed-off-by: Test User <test@example.com>',
  ...extraTrailers,
  COPILOT_COAUTHOR,
  `Copilot-Session: ${session}`,
  ''
].join('\n')

const createRepository = () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'arm64-governance-'))
  git(directory, ['init', '--quiet', '--initial-branch=main'])
  git(directory, ['config', 'user.name', 'Test User'])
  git(directory, ['config', 'user.email', 'test@example.com'])
  git(directory, ['commit', '--quiet', '--allow-empty', '--cleanup=verbatim', '-F', '-'], 'Base\n')
  return {
    directory,
    base: git(directory, ['rev-parse', 'HEAD']),
    commit (message) {
      git(directory, ['commit', '--quiet', '--allow-empty', '--cleanup=verbatim', '-F', '-'], message)
      return git(directory, ['rev-parse', 'HEAD'])
    }
  }
}

const session = policy.expectedCopilotSession

test('reads candidate Git blobs without importing or executing them', () => {
  const repository = createRepository()
  try {
    const marker = path.join(repository.directory, 'executed')
    const candidate = path.join(repository.directory, 'candidate.js')
    fs.writeFileSync(candidate, `require('fs').writeFileSync(${JSON.stringify(marker)}, 'executed')\n`)
    git(repository.directory, ['add', '--', 'candidate.js'])
    const head = repository.commit(ownedMessage(session, 'Candidate data'))
    const source = createGitSource(repository.directory, head)
    assert.ok(source.read('candidate.js').includes('writeFileSync'))
    assert.strictEqual(fs.existsSync(marker), false)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

test('accepts the independently audited bootstrap commit only under its recorded session', () => {
  const result = validateCommitRange(
    '79f3c5fa9111e438b923222dd27392843a995995',
    policy.bootstrap.commit,
    session,
    policy.deniedCampaignCommits,
    process.cwd(),
    { sessionExceptions: { [policy.bootstrap.commit]: policy.bootstrap.session } }
  )
  assert.deepStrictEqual(result.commits, [policy.bootstrap.commit])
})

test('accepts multiple owned commits from one explicit session', () => {
  const repository = createRepository()
  try {
    repository.commit(ownedMessage(session, 'First'))
    const head = repository.commit(ownedMessage(session, 'Second'))
    const result = validateCommitRange(repository.base, head, session, [], repository.directory)
    assert.strictEqual(result.commits.length, 2)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

rejects('rejects an empty owned commit range', () => {
  const repository = createRepository()
  try {
    validateCommitRange(repository.base, repository.base, session, [], repository.directory)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

rejects('rejects shallow candidate ancestry', () => {
  const repository = createRepository()
  try {
    const head = repository.commit(ownedMessage(session))
    const shallow = git(repository.directory, ['rev-parse', '--git-path', 'shallow'])
    fs.writeFileSync(path.resolve(repository.directory, shallow), `${repository.base}\n`)
    validateCommitRange(repository.base, head, session, [], repository.directory)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

rejects('rejects a commit from another Copilot session', () => {
  const repository = createRepository()
  try {
    const head = repository.commit(ownedMessage('ffffffff-ffff-ffff-ffff-ffffffffffff'))
    validateCommitRange(repository.base, head, session, [], repository.directory)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

rejects('rejects a non-owned commit in the range', () => {
  const repository = createRepository()
  try {
    const head = repository.commit('Human change\n\nSigned-off-by: Test User <test@example.com>\n')
    validateCommitRange(repository.base, head, session, [], repository.directory)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

rejects('rejects a merge-base different from the supplied base', () => {
  const repository = createRepository()
  try {
    git(repository.directory, ['branch', 'candidate'])
    repository.commit(ownedMessage(session, 'Main only'))
    const suppliedBase = git(repository.directory, ['rev-parse', 'HEAD'])
    git(repository.directory, ['switch', '--quiet', 'candidate'])
    const head = repository.commit(ownedMessage(session, 'Candidate only'))
    validateCommitRange(suppliedBase, head, session, [], repository.directory)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

rejects('rejects a merge commit in the owned range', () => {
  const repository = createRepository()
  try {
    git(repository.directory, ['switch', '--quiet', '-c', 'side'])
    repository.commit(ownedMessage(session, 'Side'))
    git(repository.directory, ['switch', '--quiet', 'main'])
    repository.commit(ownedMessage(session, 'Main'))
    git(repository.directory, ['merge', '--quiet', '--no-ff', '--no-commit', 'side'])
    git(repository.directory, ['commit', '--quiet', '--cleanup=verbatim', '-F', '-'], ownedMessage(session, 'Merge'))
    const head = git(repository.directory, ['rev-parse', 'HEAD'])
    validateCommitRange(repository.base, head, session, [], repository.directory)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

rejects('rejects a denied campaign commit in the range', () => {
  const repository = createRepository()
  try {
    const denied = repository.commit(ownedMessage(session, 'Denied'))
    const head = repository.commit(ownedMessage(session, 'After denied'))
    validateCommitRange(repository.base, head, session, [denied], repository.directory)
  } finally {
    fs.rmSync(repository.directory, { recursive: true, force: true })
  }
})

const syntheticAncestryPolicy = () => {
  const value = clone(policy)
  value.deniedCampaignCommits = clone(ancestryFixture.deniedCampaignCommits)
  return value
}

test('validates the byte-digest-bound trusted ancestry manifest', () => {
  const head = git(process.cwd(), ['rev-parse', 'HEAD'])
  const result = validateAncestryManifest(policy, ancestryManifest, [head])
  assert.strictEqual(result.digest, policy.ancestryManifest.digest)
})

rejects('rejects a candidate-altered ancestry manifest', () => {
  const altered = ancestryManifest.replace(
    'ce597a2bb3b0e496220aac2d160a46c93ccc8267',
    'ffffffffffffffffffffffffffffffffffffffff'
  )
  validateAncestryManifest(policy, altered, [git(process.cwd(), ['rev-parse', 'HEAD'])])
})

test('accepts absent candidate deny objects with complete trusted collector proof', async () => {
  const result = await verifyDeniedAncestry(
    syntheticAncestryPolicy(),
    ancestryFixture.candidate.cleanCommits,
    createFixtureApi(clone(ancestryFixture.api))
  )
  assert.match(result.digest, /^sha256:[0-9a-f]{64}$/)
})

rejects('rejects absent trusted collector proof', async () => {
  const api = clone(ancestryFixture.api)
  delete api[
    '/repos/crutkas/build-extra/compare/' +
    '0000000000000000000000000000000000000000...' +
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?per_page=100&page=1'
  ]
  await verifyDeniedAncestry(
    syntheticAncestryPolicy(),
    ancestryFixture.candidate.cleanCommits,
    createFixtureApi(api)
  )
})

rejects('rejects fabricated trusted collector proof', async () => {
  const api = clone(ancestryFixture.api)
  const comparison = api[
    '/repos/crutkas/build-extra/compare/' +
    '0000000000000000000000000000000000000000...' +
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?per_page=100&page=1'
  ]
  comparison.commits[0].sha = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
  await verifyDeniedAncestry(
    syntheticAncestryPolicy(),
    ancestryFixture.candidate.cleanCommits,
    createFixtureApi(api)
  )
})

rejects('rejects a real descendant even when self-declared ancestry omits a527', async () => {
  assert.ok(!ancestryFixture.candidate.selfDeclaredAncestry.some(commit => commit.startsWith('a527')))
  const syntheticPolicy = syntheticAncestryPolicy()
  const collected = await verifyDeniedAncestry(
    syntheticPolicy,
    ancestryFixture.candidate.cleanCommits,
    createFixtureApi(clone(ancestryFixture.api))
  )
  const contents = `${JSON.stringify({
    schemaVersion: 1,
    repository: syntheticPolicy.repository,
    sources: collected.collected
  }, null, 2)}\n`
  syntheticPolicy.ancestryManifest.digest =
    `sha256:${crypto.createHash('sha256').update(contents).digest('hex')}`
  validateAncestryManifest(
    syntheticPolicy,
    contents,
    ancestryFixture.candidate.descendantCommits
  )
})

rejects('rejects spacing-variant duplicate Copilot trailers using Git semantics', () => {
  validateOwnedCommitMessage(
    ownedMessage(session, 'Spacing variant', ['Copilot-Session : hidden-session']),
    session
  )
})

rejects('rejects a trailer after the terminal Copilot pair', () => {
  validateOwnedCommitMessage(
    `${ownedMessage(session).slice(0, -1)}\nSigned-off-by: Later <later@example.com>\n`,
    session
  )
})

const main = async () => {
  for (const { name, callback } of tests) {
    try {
      await callback()
    } catch (error) {
      error.message = `${name}: ${error.message}`
      throw error
    }
  }
  process.stdout.write(`ok ${tests.length} ARM64 governance tests\n`)
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`)
  process.exit(1)
})
