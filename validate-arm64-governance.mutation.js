#!/usr/bin/env node

'use strict'

const assert = require('assert')
const childProcess = require('child_process')
const fs = require('fs')
const path = require('path')

const VALIDATOR = 'validate-arm64-governance.js'
const TEST = 'validate-arm64-governance.test.js'
const OPERATORS = Object.freeze(['deletion', 'inversion', 'message'])
const GUARDS = Object.freeze([
  {
    id: 'lf-line-endings',
    anchor: "  if (message.includes('\\r')) fail(`${label}: commit message must use LF line endings`)",
    condition: "message.includes('\\r')",
    expectedTest: 'rejects CR in an otherwise valid owned commit message'
  },
  {
    id: 'terminal-session',
    anchor: [
      "  if (!message.endsWith('\\n') || message.endsWith('\\n\\n')) {",
      '    fail(`${label}: owned commit must end immediately after the Copilot-Session trailer`)',
      '  }'
    ].join('\n'),
    condition: "!message.endsWith('\\n') || message.endsWith('\\n\\n')",
    expectedTest: 'rejects a trailing blank line after an otherwise valid terminal pair'
  },
  {
    id: 'terminal-coauthor',
    anchor: [
      '  if (lines[lines.length - 2] !== COPILOT_COAUTHOR) {',
      '    fail(`${label}: owned commit must end with the exact expected Co-authored-by and Copilot-Session pair`)',
      '  }'
    ].join('\n'),
    condition: 'lines[lines.length - 2] !== COPILOT_COAUTHOR',
    expectedTest: 'rejects a non-Copilot co-author before an otherwise valid session trailer'
  },
  {
    id: 'dco',
    anchor: [
      '  if (!trailers.some(line => /^Signed-off-by: \\S.* <[^<>]+>$/.test(line))) {',
      '    fail(`${label}: DCO Signed-off-by trailer is required before the terminal Copilot pair`)',
      '  }'
    ].join('\n'),
    condition: '!trailers.some(line => /^Signed-off-by: \\S.* <[^<>]+>$/.test(line))',
    expectedTest: 'rejects an otherwise valid owned commit without DCO sign-off'
  }
])

const count = (contents, needle) => contents.split(needle).length - 1

const mutate = (source, guard, operator, id) => {
  let replacement
  if (operator === 'deletion') {
    replacement = `  // MUTATION_LANDED: ${id}`
  } else if (operator === 'inversion') {
    replacement = guard.anchor.replace(`if (${guard.condition})`, `if (!(${guard.condition}))`)
  } else {
    replacement = guard.anchor.replace('`)', ' [mutated]`)')
  }
  assert.notStrictEqual(replacement, guard.anchor, `${id}: operator did not change the guard`)
  const changed = source.replace(guard.anchor, replacement)
  assert.notStrictEqual(changed, source, `${id}: mutation did not change the validator`)
  return changed.replace(
    'module.exports = {',
    `module.exports = {\n  MUTATION_LANDED: '${id}',`
  )
}

const run = (args, env = {}) => childProcess.spawnSync(process.execPath, args, {
  cwd: process.cwd(),
  encoding: 'utf8',
  env: { ...process.env, ...env },
  maxBuffer: 4 * 1024 * 1024,
  windowsHide: true
})

const requireSuccess = (result, label) => {
  if (result.error || result.status !== 0) {
    throw new Error(`${label} failed:\n${result.error ? result.error.message : result.stderr}`)
  }
}

const main = () => {
  const source = fs.readFileSync(VALIDATOR, 'utf8')
  const test = fs.readFileSync(TEST, 'utf8')
  const baseline = run([TEST])
  requireSuccess(baseline, 'mutation baseline')
  const baselineMatch = baseline.stdout.match(/^ok (\d+) ARM64 governance tests$/m)
  assert.ok(baselineMatch, 'mutation baseline did not report its test denominator')

  for (const guard of GUARDS) {
    assert.strictEqual(count(source, guard.anchor), 1, `${guard.id}: guard anchor must occur exactly once`)
  }

  const mutantDirectory = fs.mkdtempSync(path.resolve('.arm64-governance-mutation-'))
  const mutantValidator = path.join(mutantDirectory, 'validate-arm64-governance.js')
  const mutantTest = path.join(mutantDirectory, 'validate-arm64-governance.test.js')
  const testSource = test
  assert.strictEqual(
    count(testSource, "require('./validate-arm64-governance')"),
    1,
    'mutant test must bind exactly once to its colocated mutant validator'
  )

  let landed = 0
  let killed = 0
  try {
    fs.writeFileSync(mutantTest, testSource)
    for (const guard of GUARDS) {
      for (const operator of OPERATORS) {
        const id = `${guard.id}:${operator}`
        fs.writeFileSync(mutantValidator, mutate(source, guard, operator, id))

        const control = run([
          '-e',
          `require('assert').strictEqual(require(${JSON.stringify(mutantValidator)}).MUTATION_LANDED, ${JSON.stringify(id)})`
        ])
        requireSuccess(control, `${id} positive landing control`)
        landed++

        const result = run([mutantTest])
        if (result.error || result.status === 0) {
          throw new Error(`${id} survived its independently landed mutation`)
        }
        const expectedTest = operator === 'inversion'
          ? 'accepts a fully valid owned commit message'
          : guard.expectedTest
        assert.ok(
          result.stderr.includes(`${expectedTest}:`),
          `${id} was killed outside its expected oracle:\n${result.stderr}`
        )
        killed++
        process.stdout.write(`killed ${id}\n`)
      }
    }
  } finally {
    fs.rmSync(mutantDirectory, { recursive: true, force: true })
  }

  const denominator = GUARDS.length * OPERATORS.length
  assert.strictEqual(landed, denominator)
  assert.strictEqual(killed, denominator)
  process.stdout.write(
    `ok ${killed}/${denominator} mutations killed; ${landed}/${denominator} positive landing controls passed; ` +
    `${baselineMatch[1]} baseline tests\n`
  )
}

try {
  main()
} catch (error) {
  process.stderr.write(`${error.stack || error.message}\n`)
  process.exit(1)
}
