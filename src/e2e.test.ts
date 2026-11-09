import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { execFile } from 'node:child_process';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalApprovalRequest, stableJson } from './approval.ts';

const distPath = path.resolve(process.cwd(), 'dist', 'index.js');

interface ReceivedRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

interface MockServer {
  port: number;
  requests: ReceivedRequest[];
  close: () => Promise<void>;
}

type ServerHandler = (
  req: http.IncomingMessage,
  res: http.ServerResponse,
  request: ReceivedRequest,
) => void;

function startMockServer(handler: ServerHandler): Promise<MockServer | undefined> {
  const requests: ReceivedRequest[] = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      const received = {
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        body,
      };
      requests.push(received);
      handler(req, res, received);
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EPERM') {
        resolve(undefined);
        return;
      }
      reject(error);
    });
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        port,
        requests,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

function sendJson(res: http.ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function parseOutputFile(content: string): Record<string, string> {
  const outputs: Record<string, string> = {};
  const lines = content.split('\n');
  let i = 0;
  while (i < lines.length) {
    const match = lines[i].match(/^(.+?)<<(.+)$/);
    if (!match) {
      i += 1;
      continue;
    }
    const [, name, delimiter] = match;
    const value: string[] = [];
    i += 1;
    while (i < lines.length && lines[i] !== delimiter) {
      value.push(lines[i]);
      i += 1;
    }
    outputs[name] = value.join('\n');
    i += 1;
  }
  return outputs;
}

test('invalid HMAC secret fails in Korean before any API request', async () => {
  const result = await runAction({
    'api-token': 'tkn_test',
    agent: 'edge',
    workflow: 'deploy',
    'approval-key-id': 'test-hmac',
    'approval-secret': ' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= ',
    'base-url': 'http://127.0.0.1:1/v1',
  });
  assert.notEqual(result.code, 0, result.stdout);
  assert.match(result.stdout, /approval-secret은 32바이트 이상 키의 표준 Base64 문자열이어야 합니다/);
});

interface ActionResult {
  code: number;
  stdout: string;
  outputs: Record<string, string>;
  summary: string;
}

async function runAction(
  inputs: Record<string, string>,
  extraEnv: Record<string, string> = {},
): Promise<ActionResult> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'run-action-e2e-'));
  const outputFile = path.join(dir, 'github-output');
  const summaryFile = path.join(dir, 'github-summary');
  await fs.writeFile(outputFile, '');
  await fs.writeFile(summaryFile, '');

  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    GITHUB_OUTPUT: outputFile,
    GITHUB_STEP_SUMMARY: summaryFile,
    INPUT_DEBUG: 'false',
    INPUT_WAIT: 'false',
    'INPUT_WAIT-TIMEOUT-MINUTES': '60',
    INPUT_LOGS: 'true',
    ...extraEnv,
  };
  for (const [name, value] of Object.entries(inputs)) {
    env['INPUT_' + name.toUpperCase()] = value;
  }

  const { code, stdout } = await new Promise<{ code: number; stdout: string }>((resolve) => {
    execFile(
      process.execPath,
      [distPath],
      { env, timeout: 30_000 },
      (error, out) => {
        const exitCode = error
          ? ((error as NodeJS.ErrnoException & { code?: number }).code ?? 1)
          : 0;
        resolve({ code: typeof exitCode === 'number' ? exitCode : 1, stdout: out });
      },
    );
  });

  const outputs = parseOutputFile(await fs.readFile(outputFile, 'utf8'));
  const summary = await fs.readFile(summaryFile, 'utf8');
  await fs.rm(dir, { recursive: true, force: true });
  return { code, stdout, outputs, summary };
}

test('dispatch sends the name-based run request, GitHub ref, meta, and derived key', async (t) => {
  const server = await startMockServer((_req, res, request) => {
    assert.equal(request.method, 'POST');
    sendJson(res, 200, {
      jobId: 'job-123',
      status: 'queued',
      consoleUrl: 'https://console.example.test/jobs/job-123',
    });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');
  try {
    const result = await runAction(
      {
        'api-token': 'tkn_test',
        agent: 'production device',
        workflow: 'deploy',
        params: '{"version":"1.2.3"}',
        'base-url': 'http://127.0.0.1:' + server.port + '/v1',
      },
      {
        GITHUB_RUN_ID: '42',
        GITHUB_RUN_ATTEMPT: '2',
        GITHUB_JOB: 'release',
        GITHUB_ACTION: 'run-action',
        GITHUB_REPOSITORY: 'Deplite/device',
        GITHUB_SERVER_URL: 'https://github.com',
        GITHUB_SHA: 'abc123',
        GITHUB_REF_NAME: 'release/1.2.3',
      },
    );

    assert.equal(result.code, 0, result.stdout);
    assert.equal(server.requests.length, 1);
    const request = server.requests[0];
    assert.equal(request.url, '/v1/run/production%20device/deploy');
    assert.equal(request.headers.authorization, 'Bearer tkn_test');
    assert.deepEqual(JSON.parse(request.body), {
      debug: false,
      params: { version: '1.2.3' },
      ref: 'release/1.2.3',
      meta: {
        repo: 'Deplite/device',
        run_url: 'https://github.com/Deplite/device/actions/runs/42/attempts/2',
        sha: 'abc123',
      },
    });
    const fingerprint = stableJson({
      ref: 'release/1.2.3',
      debug: false,
      params: { version: '1.2.3' },
    });
    const hash16 = createHash('sha256').update(fingerprint).digest('hex').slice(0, 16);
    assert.equal(
      request.headers['idempotency-key'],
      'gha-42-2-release-run-action-' + hash16,
    );
    assert.deepEqual(result.outputs, {
      'job-id': 'job-123',
      status: 'queued',
      'console-url': 'https://console.example.test/jobs/job-123',
    });
    assert.match(result.summary, /production device/);
    assert.match(result.summary, /콘솔에서 보기/);
  } finally {
    await server.close();
  }
});

test('wait streams logs safely and fetches late logs and final job details', async (t) => {
  let logsCall = 0;
  const server = await startMockServer((_req, res, request) => {
    if (request.method === 'POST') {
      sendJson(res, 200, {
        jobId: 'job-456',
        status: 'queued',
        consoleUrl: 'https://console.example.test/jobs/job-456',
      });
      return;
    }
    if (request.url.startsWith('/v1/jobs/job-456/logs')) {
      logsCall += 1;
      if (logsCall === 1) {
        sendJson(res, 200, {
          items: [{ seq: 1, stepName: 'Build', stream: 'stdout', content: '빌드 시작' }],
          nextAfter: 1,
          jobStatus: 'running',
          finished: false,
        });
      } else if (logsCall === 2) {
        sendJson(res, 200, {
          items: [],
          nextAfter: 1,
          jobStatus: 'success',
          finished: true,
        });
      } else if (logsCall === 3) {
        sendJson(res, 200, {
          items: [{ seq: 2, content: '::add-mask::device-output' }],
          nextAfter: 2,
          jobStatus: 'success',
          finished: true,
        });
      } else {
        sendJson(res, 200, {
          items: [],
          nextAfter: 2,
          jobStatus: 'success',
          finished: true,
        });
      }
      return;
    }
    if (request.url === '/v1/jobs/job-456') {
      sendJson(res, 200, {
        jobId: 'job-456',
        status: 'success',
        exitCode: 0,
        output: { deployed: true },
        consoleUrl: 'https://console.example.test/jobs/job-456',
      });
      return;
    }
    sendJson(res, 404, { code: 'job_not_found' });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');

  try {
    const result = await runAction({
      'api-token': 'tkn_test',
      agent: 'edge',
      workflow: 'deploy',
      wait: 'true',
      logs: 'true',
      'wait-timeout-minutes': '1',
      'base-url': 'http://127.0.0.1:' + server.port + '/v1',
    });

    assert.equal(result.code, 0, result.stdout);
    assert.equal(logsCall, 4);
    assert.deepEqual(
      server.requests.map((request) => request.url),
      [
        '/v1/run/edge/deploy',
        '/v1/jobs/job-456/logs?after=0&limit=500',
        '/v1/jobs/job-456/logs?after=1&limit=500',
        '/v1/jobs/job-456/logs?after=1&limit=500',
        '/v1/jobs/job-456/logs?after=2&limit=500',
        '/v1/jobs/job-456',
      ],
    );
    assert.match(result.stdout, /::stop-commands::deplite_[0-9a-f]+/);
    assert.match(result.stdout, /::add-mask::device-output/);
    assert.match(result.stdout, /::deplite_[0-9a-f]+::/);
    assert.deepEqual(result.outputs, {
      'job-id': 'job-456',
      status: 'success',
      'exit-code': '0',
      output: '{"deployed":true}',
      'console-url': 'https://console.example.test/jobs/job-456',
    });
  } finally {
    await server.close();
  }
});

test('wait streams all 1200 log lines across full pages', async (t) => {
  let logCalls = 0;
  const server = await startMockServer((_req, res, request) => {
    if (request.method === 'POST') {
      sendJson(res, 200, { jobId: 'job-large', status: 'queued' });
      return;
    }
    if (request.url.startsWith('/v1/jobs/job-large/logs')) {
      logCalls += 1;
      const after = Number(new URL(request.url, 'http://localhost').searchParams.get('after'));
      const count = after < 1000 ? 500 : after < 1200 ? 200 : 0;
      const start = after + 1;
      sendJson(res, 200, {
        items: Array.from({ length: count }, (_, index) => ({
          seq: start + index,
          content: 'log-' + (start + index),
        })),
        nextAfter: after + count,
        jobStatus: after < 500 ? 'running' : 'success',
        finished: after >= 500,
      });
      return;
    }
    sendJson(res, 200, { jobId: 'job-large', status: 'success' });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');
  try {
    const result = await runAction({
      'api-token': 'tkn_test',
      agent: 'edge',
      workflow: 'deploy',
      wait: 'true',
      logs: 'true',
      'wait-timeout-minutes': '1',
      'base-url': 'http://127.0.0.1:' + server.port + '/v1',
    });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(logCalls, 4);
    assert.match(result.stdout, /log-1/);
    assert.match(result.stdout, /log-1200/);
    assert.equal((result.stdout.match(/::stop-commands::deplite_/g) ?? []).length, 3);
    assert.equal((result.stdout.match(/::deplite_[0-9a-f]+::/g) ?? []).length, 3);
  } finally {
    await server.close();
  }
});

test('wait without log streaming polls only the job endpoint', async (t) => {
  let jobCall = 0;
  const server = await startMockServer((_req, res, request) => {
    if (request.method === 'POST') {
      sendJson(res, 200, { jobId: 'job-poll', status: 'queued' });
      return;
    }
    jobCall += 1;
    sendJson(res, 200, {
      jobId: 'job-poll',
      status: jobCall === 1 ? 'running' : 'success',
      exitCode: jobCall === 1 ? null : 0,
      output: jobCall === 1 ? null : { done: true },
    });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');
  try {
    const result = await runAction({
      'api-token': 'tkn_test',
      agent: 'edge',
      workflow: 'deploy',
      wait: 'true',
      logs: 'false',
      'wait-timeout-minutes': '1',
      'base-url': 'http://127.0.0.1:' + server.port + '/v1',
    });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(jobCall, 2);
    assert.ok(server.requests.every((request) => request.url === '/v1/run/edge/deploy' || request.url === '/v1/jobs/job-poll'));
    assert.equal(result.outputs.status, 'success');
    assert.equal(result.outputs.output, '{"done":true}');
  } finally {
    await server.close();
  }
});

test('failed job status includes the BE job details and fails the step', async (t) => {
  const server = await startMockServer((_req, res, request) => {
    if (request.method === 'POST') {
      sendJson(res, 200, {
        jobId: 'job-failed',
        status: 'queued',
        consoleUrl: 'https://console.example.test/jobs/job-failed',
      });
      return;
    }
    sendJson(res, 200, {
      jobId: 'job-failed',
      status: 'failed',
      exitCode: 7,
      errorMessage: '작업 단계가 실패했습니다.',
      reason: 'workflow_error',
      output: { ignoredBySummary: true },
      consoleUrl: 'https://console.example.test/jobs/job-failed',
    });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');
  try {
    const result = await runAction({
      'api-token': 'tkn_test',
      agent: 'edge',
      workflow: 'deploy',
      wait: 'true',
      logs: 'false',
      'base-url': 'http://127.0.0.1:' + server.port + '/v1',
    });
    assert.equal(result.code, 1);
    assert.match(result.stdout, /상태: failed/);
    assert.match(result.stdout, /종료 코드: 7/);
    assert.match(result.stdout, /오류: 작업 단계가 실패했습니다/);
    assert.match(result.stdout, /사유: workflow_error/);
    assert.match(result.stdout, /https:\/\/console.example.test\/jobs\/job-failed/);
    assert.equal(result.outputs['exit-code'], '7');
    assert.doesNotMatch(result.summary, /ignoredBySummary/);
  } finally {
    await server.close();
  }
});

test('429 Retry-After is retried with the same idempotency key', async (t) => {
  let calls = 0;
  const server = await startMockServer((_req, res) => {
    calls += 1;
    if (calls === 1) {
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Retry-After': '0',
      });
      res.end(JSON.stringify({ code: 'rate_limited' }));
      return;
    }
    sendJson(res, 200, { jobId: 'job-retry', status: 'queued' });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');
  try {
    const result = await runAction({
      'api-token': 'tkn_test',
      agent: 'edge',
      workflow: 'deploy',
      'idempotency-key': 'retry-key',
      'base-url': 'http://127.0.0.1:' + server.port + '/v1',
    });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(calls, 2);
    assert.equal(server.requests[0].headers['idempotency-key'], 'retry-key');
    assert.equal(server.requests[1].headers['idempotency-key'], 'retry-key');
  } finally {
    await server.close();
  }
});

test('409 error codes become Korean action errors', async (t) => {
  const server = await startMockServer((_req, res) => {
    sendJson(res, 409, { code: 'idempotency_conflict', message: 'internal text' });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');
  try {
    const result = await runAction({
      'api-token': 'tkn_test',
      agent: 'edge',
      workflow: 'deploy',
      'base-url': 'http://127.0.0.1:' + server.port + '/v1',
    });
    assert.equal(result.code, 1);
    assert.match(result.stdout, /HTTP 409, idempotency_conflict/);
    assert.match(result.stdout, /멱등 키/);
    assert.doesNotMatch(result.stdout, /internal text/);
  } finally {
    await server.close();
  }
});

test('workflow_invalid errors include the device reason without internal message text', async (t) => {
  const server = await startMockServer((_req, res) => {
    sendJson(res, 409, {
      statusCode: 409,
      error: 'Conflict',
      message: 'Workflow "hello" is invalid: internal text',
      reason: 'workflow "hello": name is defined in 2 files (hello.yml, team/hello.yml)',
      invalidCode: 'duplicate_name',
      code: 'workflow_invalid',
    });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');
  try {
    const result = await runAction({
      'api-token': 'tkn_test',
      agent: 'edge',
      workflow: 'hello',
      'base-url': 'http://127.0.0.1:' + server.port + '/v1',
    });
    assert.equal(result.code, 1);
    assert.match(result.stdout, /HTTP 409, workflow_invalid/);
    assert.match(result.stdout, /team\/hello\.yml/);
    assert.doesNotMatch(result.stdout, /is invalid:/);
  } finally {
    await server.close();
  }
});

test('approval lookup uses the returned agent ID and sends a valid HMAC approval', async (t) => {
  const secret = Buffer.alloc(32, 0x05).toString('base64');
  let approvalBody: Record<string, unknown> | undefined;
  const agentId = '123e4567-e89b-12d3-a456-426614174000';
  const server = await startMockServer((_req, res, request) => {
    if (request.method === 'GET' && request.url === '/v1/run/edge/deploy') {
      sendJson(res, 200, { agentId, agentName: 'edge', workflowName: 'deploy' });
      return;
    }
    approvalBody = JSON.parse(request.body) as Record<string, unknown>;
    sendJson(res, 200, { jobId: 'job-approved', status: 'queued' });
  });
  if (!server) return t.skip('Local mock server sockets are blocked by the current sandbox.');
  try {
    const result = await runAction({
      'api-token': 'tkn_test',
      agent: 'edge',
      workflow: 'deploy',
      params: '{"release":"v1"}',
      ref: 'main',
      'approval-key-id': 'test-hmac',
      'approval-secret': secret,
      'base-url': 'http://127.0.0.1:' + server.port + '/v1',
    });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(server.requests[0].method, 'GET');
    assert.equal(server.requests[1].method, 'POST');
    assert.ok(approvalBody);
    const approval = approvalBody.approval as {
      method: string;
      keyId: string;
      nonce: string;
      ts: number;
      sig: string;
    };
    assert.equal(approval.method, 'hmac');
    assert.equal(approval.keyId, 'test-hmac');
    const canonical = canonicalApprovalRequest(
      agentId,
      'deploy',
      { release: 'v1' },
      'main',
      approval.nonce,
      approval.ts,
    );
    assert.equal(
      approval.sig,
      createHmac('sha256', Buffer.from(secret, 'base64'))
        .update(canonical)
        .digest('base64url'),
    );
  } finally {
    await server.close();
  }
});
