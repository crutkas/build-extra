#!/usr/bin/env node

'use strict'

const assert = require('assert')

const {
  APPROVED_ACTION_PINS,
  COPILOT_COAUTHOR,
  validateOwnedCommitMessage,
  validateReleaseInput,
  validateWorkflowText
} = require('./validate-arm64-governance')

let tests = 0

const test = (name, callback) => {
  try {
    callback()
    tests++
  } catch (error) {
    error.message = `${name}: ${error.message}`
    throw error
  }
}

const rejects = (name, callback) => test(name, () => assert.throws(callback))

const workflow = uses => [
  'jobs:',
  '  validate:',
  '    steps:',
  `      - uses: ${uses}`,
  ''
].join('\n')

for (const [identity, sha] of Object.entries(APPROVED_ACTION_PINS)) {
  test(`accepts ${identity} approved pin`, () => {
    const inventory = validateWorkflowText(workflow(`${identity}@${sha}`), 'workflow.yml')
    assert.deepStrictEqual(inventory, [{ identity, sha }])
  })
  rejects(`rejects ${identity} mutable ref`, () => {
    validateWorkflowText(workflow(`${identity}@v1`), 'workflow.yml')
  })
  rejects(`rejects ${identity} unapproved commit`, () => {
    const replacement = `${sha[0] === '0' ? '1' : '0'}${sha.slice(1)}`
    validateWorkflowText(workflow(`${identity}@${replacement}`), 'workflow.yml')
  })
}

rejects('rejects an unapproved external Action identity', () => {
  validateWorkflowText(workflow(`example/action@${'a'.repeat(40)}`), 'workflow.yml')
})

test('accepts a local Action', () => {
  validateWorkflowText(workflow('./.github/actions/example'), 'workflow.yml')
})

rejects('rejects gh run download', () => {
  validateWorkflowText('steps:\n  - run: gh run download 123\n', 'workflow.yml')
})

rejects('rejects gh release download', () => {
  validateWorkflowText('steps:\n  - run: gh release download v1.0.0\n', 'workflow.yml')
})

rejects('rejects a direct release asset URL', () => {
  validateWorkflowText(
    'steps:\n  - run: curl https://github.com/example/project/releases/download/v1.0.0/input.zip\n',
    'workflow.yml'
  )
})

const validReleaseInput = () => ({
  schemaVersion: 1,
  architecture: 'aarch64',
  repository: 'example/project',
  release: {
    id: 1234,
    tagName: 'v1.2.3',
    immutable: true
  },
  tag: {
    name: 'v1.2.3',
    objectType: 'tag',
    objectSha: '1'.repeat(40),
    peeledType: 'commit',
    peeledCommitSha: '2'.repeat(40),
    peeledTreeSha: '3'.repeat(40)
  },
  assets: [{
    id: 5678,
    name: 'input-arm64.zip',
    size: 123456,
    digest: `sha256:${'4'.repeat(64)}`
  }]
})

const clone = value => JSON.parse(JSON.stringify(value))

test('accepts complete immutable release metadata', () => {
  validateReleaseInput(validReleaseInput())
})

rejects('rejects mutable release metadata', () => {
  const input = validReleaseInput()
  input.release.immutable = false
  validateReleaseInput(input)
})

rejects('rejects non-ARM64 release metadata', () => {
  const input = validReleaseInput()
  input.architecture = 'x86_64'
  validateReleaseInput(input)
})

rejects('rejects a lightweight tag', () => {
  const input = validReleaseInput()
  input.tag.objectType = 'commit'
  validateReleaseInput(input)
})

rejects('rejects a non-commit peeled tag', () => {
  const input = validReleaseInput()
  input.tag.peeledType = 'tag'
  validateReleaseInput(input)
})

for (const field of ['objectSha', 'peeledCommitSha', 'peeledTreeSha']) {
  rejects(`rejects missing tag ${field}`, () => {
    const input = validReleaseInput()
    delete input.tag[field]
    validateReleaseInput(input)
  })
}

rejects('rejects aliased tag identities', () => {
  const input = validReleaseInput()
  input.tag.peeledCommitSha = input.tag.objectSha
  validateReleaseInput(input)
})

for (const field of ['id', 'name', 'size', 'digest']) {
  rejects(`rejects missing asset ${field}`, () => {
    const input = validReleaseInput()
    delete input.assets[0][field]
    validateReleaseInput(input)
  })
}

rejects('rejects malformed asset digest', () => {
  const input = validReleaseInput()
  input.assets[0].digest = '4'.repeat(64)
  validateReleaseInput(input)
})

rejects('rejects asset paths in place of exact names', () => {
  const input = validReleaseInput()
  input.assets[0].name = 'downloads/input-arm64.zip'
  validateReleaseInput(input)
})

rejects('rejects duplicate asset IDs', () => {
  const input = validReleaseInput()
  const duplicate = clone(input.assets[0])
  duplicate.name = 'other-arm64.zip'
  input.assets.push(duplicate)
  validateReleaseInput(input)
})

rejects('rejects duplicate asset names', () => {
  const input = validReleaseInput()
  const duplicate = clone(input.assets[0])
  duplicate.id++
  input.assets.push(duplicate)
  validateReleaseInput(input)
})

rejects('rejects URL-only asset metadata', () => {
  const input = validReleaseInput()
  input.assets = [{ url: 'https://example.invalid/input-arm64.zip' }]
  validateReleaseInput(input)
})

const sessionTrailer = 'Copilot-Session: 01234567-89ab-cdef-0123-456789abcdef'
const validCommitMessage = [
  'Validate ARM64 inputs',
  '',
  'Signed-off-by: Example User <example@example.com>',
  COPILOT_COAUTHOR,
  sessionTrailer,
  ''
].join('\n')

test('accepts the exact terminal owned-commit trailers', () => {
  assert.strictEqual(validateOwnedCommitMessage(validCommitMessage), true)
})

test('ignores commits without Copilot ownership trailers', () => {
  assert.strictEqual(validateOwnedCommitMessage('Human-authored commit\n'), false)
})

rejects('rejects a missing Copilot co-author trailer', () => {
  validateOwnedCommitMessage(`Subject\n\n${sessionTrailer}\n`)
})

rejects('rejects reversed Copilot trailers', () => {
  validateOwnedCommitMessage(`Subject\n\n${sessionTrailer}\n${COPILOT_COAUTHOR}\n`)
})

rejects('rejects a trailer after Copilot-Session', () => {
  validateOwnedCommitMessage(`${validCommitMessage.slice(0, -1)}\nSigned-off-by: Later <later@example.com>\n`)
})

rejects('rejects a blank line after Copilot-Session', () => {
  validateOwnedCommitMessage(`${validCommitMessage}\n`)
})

rejects('rejects a duplicate Copilot trailer', () => {
  validateOwnedCommitMessage(`Subject\n\n${COPILOT_COAUTHOR}\n${COPILOT_COAUTHOR}\n${sessionTrailer}\n`)
})

process.stdout.write(`ok ${tests} ARM64 governance tests\n`)
