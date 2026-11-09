import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  type ActionInputs,
  buildDispatchRequest,
  buildMeta,
  collectOutputs,
  getApiErrorMessage,
  parseParams,
  parsePositiveInteger,
  resolveIdempotencyKey,
  resolveRef,
  waitForJob,
} from './main.ts';
import { stableJson } from './approval.ts';

test('parseParams accepts an object and treats empty input as absent', () => {
  assert.equal(parseParams(''), undefined);
  assert.deepEqual(parseParams('{"env":"prod","count":2}'), {
    env: 'prod',
    count: 2,
  });
});

test('parseParams rejects invalid JSON and non-object values', () => {
  assert.throws(() => parseParams('{bad'), /params 입력은 .*JSON 객체여야 합니다/);
  assert.throws(() => parseParams('[]'), /params 입력은 JSON 객체여야 합니다/);
  assert.throws(() => parseParams('null'), /params 입력은 JSON 객체여야 합니다/);
});

test('buildMeta includes only fields backed by GitHub environment values', () => {
  assert.deepEqual(
    buildMeta({
      GITHUB_REPOSITORY: 'Deplite/device',
      GITHUB_SERVER_URL: 'https://github.com/',
      GITHUB_RUN_ID: '42',
      GITHUB_RUN_ATTEMPT: '3',
      GITHUB_SHA: 'abc123',
    }),
    {
      repo: 'Deplite/device',
      run_url: 'https://github.com/Deplite/device/actions/runs/42/attempts/3',
      sha: 'abc123',
    },
  );
  assert.deepEqual(buildMeta({ GITHUB_REPOSITORY: 'Deplite/device' }), {
    repo: 'Deplite/device',
  });
  assert.equal(buildMeta({}), undefined);
});

test('resolveRef uses the GitHub branch by default and permits an explicit empty ref', () => {
  assert.equal(resolveRef('', { GITHUB_REF_NAME: 'main' }), 'main');
  assert.equal(resolveRef('', { INPUT_REF: '', GITHUB_REF_NAME: 'main' }), undefined);
  assert.equal(resolveRef('release/1.2', { INPUT_REF: 'release/1.2' }), 'release/1.2');
});

test('resolveIdempotencyKey hashes stable ref, debug, and params content', () => {
  const env = {
    GITHUB_RUN_ID: '42',
    GITHUB_RUN_ATTEMPT: '3',
    GITHUB_JOB: 'deploy',
    GITHUB_ACTION: 'run-action',
  };
  const params = { z: 1, a: { y: 2, x: 1 } };
  const fingerprint = stableJson({ ref: 'main', debug: false, params });
  const hash16 = createHash('sha256').update(fingerprint).digest('hex').slice(0, 16);
  assert.equal(
    resolveIdempotencyKey('', env, { ref: 'main', debug: false, params }),
    'gha-42-3-deploy-run-action-' + hash16,
  );
  assert.equal(
    resolveIdempotencyKey('custom-key', env, { ref: 'main', debug: false, params }),
    'custom-key',
  );
  assert.notEqual(
    resolveIdempotencyKey('', env, { ref: 'main', debug: false, params }),
    resolveIdempotencyKey('', env, { ref: 'main', debug: false, params: { ...params, a: 2 } }),
  );
});

test('buildDispatchRequest uses the name-based route and assembles its body', () => {
  const request = buildDispatchRequest(
    {
      apiToken: 'tkn_test',
      agent: 'edge / one',
      workflow: 'release',
      params: { version: '1.2.3' },
      ref: 'release/1.2.3',
      debug: false,
      baseUrl: 'https://api.example.test/v1///',
      idempotencyKey: 'key-1',
    },
    {
      GITHUB_REPOSITORY: 'Deplite/device',
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_RUN_ID: '42',
      GITHUB_RUN_ATTEMPT: '1',
      GITHUB_SHA: 'abc123',
    },
    { method: 'hmac' },
  );
  assert.equal(
    request.url,
    'https://api.example.test/v1/run/edge%20%2F%20one/release',
  );
  assert.deepEqual(request.headers, {
    Authorization: 'Bearer tkn_test',
    'Content-Type': 'application/json',
    'Idempotency-Key': 'key-1',
  });
  assert.deepEqual(request.body, {
    debug: false,
    params: { version: '1.2.3' },
    ref: 'release/1.2.3',
    meta: {
      repo: 'Deplite/device',
      run_url: 'https://github.com/Deplite/device/actions/runs/42/attempts/1',
      sha: 'abc123',
    },
    approval: { method: 'hmac' },
  });
});

test('buildDispatchRequest omits an empty ref and unavailable metadata', () => {
  const request = buildDispatchRequest(
    {
      apiToken: 'tkn_test',
      agent: 'edge',
      workflow: 'deploy',
      debug: false,
      baseUrl: 'https://api.example.test/v1',
      idempotencyKey: 'key-1',
    },
    {},
  );
  assert.deepEqual(request.body, { debug: false });
});

test('collectOutputs exposes all supported outputs and JSON encodes output', () => {
  assert.deepEqual(
    collectOutputs({
      jobId: 'job-1',
      status: 'success',
      exitCode: 0,
      output: { ok: true },
      consoleUrl: 'https://console.example.test/jobs/job-1',
    }),
    {
      'job-id': 'job-1',
      status: 'success',
      'exit-code': '0',
      output: '{"ok":true}',
      'console-url': 'https://console.example.test/jobs/job-1',
    },
  );
  assert.deepEqual(collectOutputs({ jobId: 'job-2', status: 'queued' }), {
    'job-id': 'job-2',
    status: 'queued',
  });
});

test('error code messages include known Korean guidance and unknown HTTP details', () => {
  assert.match(
    getApiErrorMessage(409, { code: 'idempotency_conflict' }),
    /HTTP 409, idempotency_conflict/,
  );
  assert.match(
    getApiErrorMessage(400, { code: 'ref_not_allowed' }),
    /허용되지 않습니다/,
  );
  assert.equal(
    getApiErrorMessage(418, { code: 'future_code' }),
    'Deplite 요청 실패 (HTTP 418, future_code).',
  );
});

test('workflow_invalid explains duplicate names and appends the sanitized device reason', () => {
  const message = getApiErrorMessage(409, {
    code: 'workflow_invalid',
    invalidCode: 'duplicate_name',
    reason: 'workflow "hello": name is defined in 2 files (hello.yml, team/hello.yml)',
    message: 'Workflow "hello" is invalid: internal text',
  });
  assert.match(message, /같은 이름의 워크플로우 파일이 기기에 여러 개/);
  assert.match(message, /사유: workflow "hello": name is defined in 2 files \(hello\.yml, team\/hello\.yml\)$/);
  assert.doesNotMatch(message, /internal text|is invalid:/);
});

test('workflow_invalid uses general guidance for unknown codes and absent reasons', () => {
  const unknownCode = getApiErrorMessage(409, {
    code: 'workflow_invalid',
    invalidCode: 'future_reason',
    reason: 'reported by device',
  });
  assert.match(unknownCode, /기기가 이 워크플로우를 무효로 보고해 실행할 수 없습니다/);
  assert.match(unknownCode, /사유: reported by device$/);

  const noReason = getApiErrorMessage(409, {
    code: 'workflow_invalid',
    invalidCode: 'duplicate_name',
  });
  assert.match(noReason, /같은 이름의 워크플로우 파일이 기기에 여러 개/);
  assert.doesNotMatch(noReason, /사유:/);
});

test('workflow_invalid sanitizes controls and truncates reasons by code point', () => {
  const unsafeReason = getApiErrorMessage(409, {
    code: 'workflow_invalid',
    reason: ' first\n::error::x\tsecond  part ',
  });
  assert.match(unsafeReason, /사유: first ::error::x second part$/);
  assert.doesNotMatch(unsafeReason, /\n|\t/);

  const longReason = 'a'.repeat(499) + '😀' + 'tail';
  const truncated = getApiErrorMessage(409, {
    code: 'workflow_invalid',
    reason: longReason,
  });
  const displayedReason = truncated.slice(truncated.indexOf('사유: ') + '사유: '.length);
  assert.equal(Array.from(displayedReason).length, 501);
  assert.equal(Array.from(displayedReason).at(-1), '…');
  assert.equal(Array.from(displayedReason).slice(0, 500).join(''), 'a'.repeat(499) + '😀');
});

test('workflow_invalid ignores non-string reasons and reason fields for other codes', () => {
  const nonStringReason = getApiErrorMessage(409, {
    code: 'workflow_invalid',
    reason: { detail: 'not a string' },
  });
  assert.doesNotMatch(nonStringReason, /사유:/);

  const otherCode = getApiErrorMessage(409, {
    code: 'idempotency_conflict',
    reason: 'must be ignored',
    invalidCode: 'duplicate_name',
  });
  assert.match(otherCode, /멱등 키/);
  assert.doesNotMatch(otherCode, /must be ignored|같은 이름의 워크플로우/);
});

test('parsePositiveInteger accepts positive values and rejects malformed values', () => {
  assert.equal(parsePositiveInteger('60', 'wait-timeout-minutes'), 60);
  assert.throws(() => parsePositiveInteger('0', 'wait-timeout-minutes'));
  assert.throws(() => parsePositiveInteger('1.5', 'wait-timeout-minutes'));
});

test('waitForJob polls logs, reads late logs, and fetches final job data', async () => {
  const calls: string[] = [];
  const originalFetch = globalThis.fetch;
  let logsCall = 0;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url);
    if (url.includes('/logs?after=')) {
      logsCall += 1;
      if (logsCall === 1) {
        return new Response(
          JSON.stringify({
            items: [{ seq: 1, content: 'started' }],
            nextAfter: 1,
            jobStatus: 'running',
            finished: false,
          }),
          { status: 200 },
        );
      }
      if (logsCall === 2) {
        return new Response(
          JSON.stringify({ items: [], nextAfter: 1, jobStatus: 'success', finished: true }),
          { status: 200 },
        );
      }
      if (logsCall === 3) {
        return new Response(
          JSON.stringify({
            items: [{ seq: 2, content: 'late' }],
            nextAfter: 2,
            jobStatus: 'success',
            finished: true,
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({ items: [], nextAfter: 2, jobStatus: 'success', finished: true }),
        { status: 200 },
      );
    }
    return new Response(
      JSON.stringify({
        jobId: 'job-1',
        status: 'success',
        exitCode: 0,
        output: { ok: true },
      }),
      { status: 200 },
    );
  }) as typeof fetch;
  const inputs: ActionInputs = {
    apiToken: 'token',
    agent: 'edge',
    workflow: 'deploy',
    debug: false,
    wait: true,
    waitTimeoutMinutes: 1,
    logs: true,
    idempotencyKey: 'key',
    baseUrl: 'https://api.example.test/v1',
  };
  try {
    const job = await waitForJob(inputs, {
      jobId: 'job-1',
      status: 'queued',
      consoleUrl: 'https://console.example.test/jobs/job-1',
    });
    assert.equal(job.status, 'success');
    assert.equal(logsCall, 4);
    assert.deepEqual(
      calls.map((url) => new URL(url).pathname + new URL(url).search),
      [
        '/v1/jobs/job-1/logs?after=0&limit=500',
        '/v1/jobs/job-1/logs?after=1&limit=500',
        '/v1/jobs/job-1/logs?after=1&limit=500',
        '/v1/jobs/job-1/logs?after=2&limit=500',
        '/v1/jobs/job-1',
      ],
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('waitForJob retries 429 responses before continuing the poll', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    if (calls === 1) {
      return new Response(JSON.stringify({ code: 'rate_limited' }), {
        status: 429,
        headers: { 'Retry-After': '0' },
      });
    }
    if (calls === 2) {
      return new Response(
        JSON.stringify({ items: [], nextAfter: 0, jobStatus: 'success', finished: true }),
        { status: 200 },
      );
    }
    if (calls === 3) {
      return new Response(
        JSON.stringify({ items: [], nextAfter: 0, jobStatus: 'success', finished: true }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify({ jobId: 'job-2', status: 'success' }), {
      status: 200,
    });
  }) as typeof fetch;
  const inputs: ActionInputs = {
    apiToken: 'token',
    agent: 'edge',
    workflow: 'deploy',
    debug: false,
    wait: true,
    waitTimeoutMinutes: 1,
    logs: true,
    idempotencyKey: 'key',
    baseUrl: 'https://api.example.test/v1',
  };
  try {
    const job = await waitForJob(inputs, { jobId: 'job-2', status: 'queued' });
    assert.equal(job.status, 'success');
    assert.equal(calls, 4);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
