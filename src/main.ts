import * as core from '@actions/core';
import { createHash, randomBytes } from 'node:crypto';
import {
  buildApproval,
  stableJson,
  type ApprovalCredential,
  validateHmacSecret,
} from './approval.ts';

const DEFAULT_BASE_URL = 'https://api.deplite.io/v1';
const MAX_REQUEST_ATTEMPTS = 5;
const REQUEST_TIMEOUT_MS = 30_000;
const LOG_PAGE_LIMIT = 500;
const TERMINAL_STATUSES = new Set(['success', 'failed', 'timeout', 'rejected', 'canceled']);

export interface ActionInputs {
  apiToken: string;
  agent: string;
  workflow: string;
  params?: Record<string, unknown>;
  ref?: string;
  debug: boolean;
  wait: boolean;
  waitTimeoutMinutes: number;
  logs: boolean;
  idempotencyKey: string;
  baseUrl: string;
  approval?: ApprovalCredential;
}

export interface JobResponse {
  jobId: string;
  status: string;
  exitCode?: number | null;
  errorMessage?: string | null;
  reason?: string | null;
  output?: unknown;
  consoleUrl?: string;
  queuedAt?: string;
  startedAt?: string | null;
  finishedAt?: string | null;
}

interface DispatchResponse {
  jobId: string;
  status: string;
  consoleUrl?: string;
  idempotent?: boolean;
}

interface LogsResponse {
  items: Array<{
    seq: number;
    stream?: string;
    stepName?: string | null;
    level?: string;
    content: string;
    eventAt?: string;
  }>;
  nextAfter: number;
  jobStatus: string;
  finished: boolean;
}

interface ApiErrorBody {
  code?: string;
  message?: string | string[];
  reason?: unknown;
  invalidCode?: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(
    status: number,
    code: string | undefined,
    message: string,
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.name = 'ApiError';
  }
}

export class WaitTimeoutError extends Error {
  readonly jobId: string;
  readonly consoleUrl: string | undefined;

  constructor(jobId: string, consoleUrl?: string) {
    super(
      '기기 워크플로우 실행이 제한 시간 안에 끝나지 않았습니다. job ' +
        jobId +
        '은 계속 실행되며, 현재 취소 API는 제공되지 않습니다.' +
        (consoleUrl ? ' 콘솔: ' + consoleUrl : ''),
    );
    this.jobId = jobId;
    this.consoleUrl = consoleUrl;
    this.name = 'WaitTimeoutError';
  }
}

const ERROR_MESSAGES: Record<string, string> = {
  token_missing: 'api-token 입력이 필요합니다.',
  token_invalid: 'API 토큰이 유효하지 않습니다.',
  token_not_authorized: 'API 토큰에 해당 워크플로우 실행 권한이 없습니다.',
  agent_not_found: '지정한 기기를 찾을 수 없습니다.',
  agent_name_ambiguous: '같은 이름의 기기가 여러 대 있습니다. 기기 이름을 고유하게 바꿔주세요.',
  workflow_not_found: '지정한 워크플로우를 찾을 수 없습니다.',
  not_callable: '이 워크플로우는 외부 실행을 허용하지 않습니다. 기기 워크플로우 YAML의 on 설정을 확인해주세요.',
  workflow_locked: '이 워크플로우는 콘솔에서 잠겨 있습니다.',
  ref_required: '이 워크플로우를 실행하려면 허용된 ref가 필요합니다.',
  ref_not_allowed: '지정한 ref가 워크플로우에서 허용되지 않습니다.',
  ref_blocked: '지정한 ref가 콘솔의 실행 제한에 의해 차단되었습니다.',
  invalid_params: 'params가 워크플로우 입력 규격과 맞지 않습니다.',
  workflow_invalid: '기기가 이 워크플로우를 무효로 보고해 실행할 수 없습니다.',
  invalid_approval: '승인 정보의 형식이 올바르지 않습니다.',
  approval_required: '이 워크플로우는 승인이 필요합니다.',
  approval_method_not_allowed: '이 워크플로우에서 허용하지 않는 승인 방식입니다.',
  approval_invalid: '승인 서명을 확인하지 못했습니다.',
  approval_expired: '승인 시간이 만료되었습니다.',
  approval_replayed: '승인 nonce가 이미 사용되었습니다. 새 실행을 시작해주세요.',
  approval_untrusted_cert: '승인 인증서를 신뢰할 수 없습니다.',
  approval_agent_mismatch: '승인 정보가 다른 기기를 대상으로 생성되었습니다.',
  idempotency_conflict: '같은 멱등 키가 다른 실행 내용에 이미 사용되었습니다.',
  rate_limited: '요청이 너무 많습니다. 잠시 후 다시 실행해주세요.',
  job_not_found: '이 토큰으로 조회할 수 있는 실행 job이 없습니다.',
  invalid_request: '요청 형식이 올바르지 않습니다.',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function parseParams(raw: string): Record<string, unknown> | undefined {
  if (!raw.trim()) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error('params 입력은 올바른 JSON 객체여야 합니다.');
  }
  if (!isRecord(value)) {
    throw new Error('params 입력은 JSON 객체여야 합니다.');
  }
  return value;
}

export function buildMeta(env: NodeJS.ProcessEnv): Record<string, string> | undefined {
  const meta: Record<string, string> = {};
  if (env.GITHUB_REPOSITORY) meta.repo = env.GITHUB_REPOSITORY;
  if (
    env.GITHUB_SERVER_URL &&
    env.GITHUB_REPOSITORY &&
    env.GITHUB_RUN_ID &&
    env.GITHUB_RUN_ATTEMPT
  ) {
    meta.run_url =
      env.GITHUB_SERVER_URL.replace(/\/+$/, '') +
      '/' +
      env.GITHUB_REPOSITORY +
      '/actions/runs/' +
      env.GITHUB_RUN_ID +
      '/attempts/' +
      env.GITHUB_RUN_ATTEMPT;
  }
  if (env.GITHUB_SHA) meta.sha = env.GITHUB_SHA;
  return Object.keys(meta).length > 0 ? meta : undefined;
}

export function resolveRef(input: string, env: NodeJS.ProcessEnv): string | undefined {
  if (Object.prototype.hasOwnProperty.call(env, 'INPUT_REF')) {
    return input || undefined;
  }
  return env.GITHUB_REF_NAME || undefined;
}

export function resolveIdempotencyKey(
  explicit: string,
  env: NodeJS.ProcessEnv,
  input: Pick<ActionInputs, 'ref' | 'debug' | 'params'>,
): string {
  if (explicit) return explicit;
  const fingerprint = stableJson({
    ref: input.ref ?? null,
    debug: input.debug,
    params: input.params ?? {},
  });
  const hash16 = createHash('sha256').update(fingerprint).digest('hex').slice(0, 16);
  return [
    'gha',
    env.GITHUB_RUN_ID ?? '',
    env.GITHUB_RUN_ATTEMPT ?? '',
    env.GITHUB_JOB ?? '',
    env.GITHUB_ACTION ?? '',
    hash16,
  ].join('-');
}

export function buildDispatchRequest(
  inputs: Pick<ActionInputs, 'apiToken' | 'agent' | 'workflow' | 'params' | 'ref' | 'debug' | 'baseUrl' | 'idempotencyKey'>,
  env: NodeJS.ProcessEnv,
  approval?: Record<string, unknown>,
): { url: string; headers: Record<string, string>; body: Record<string, unknown> } {
  const baseUrl = inputs.baseUrl.replace(/\/+$/, '');
  const body: Record<string, unknown> = {
    debug: inputs.debug,
  };
  if (inputs.params) body.params = inputs.params;
  if (inputs.ref) body.ref = inputs.ref;
  const meta = buildMeta(env);
  if (meta) body.meta = meta;
  if (approval) body.approval = approval;
  return {
    url:
      baseUrl +
      '/run/' +
      encodeURIComponent(inputs.agent) +
      '/' +
      encodeURIComponent(inputs.workflow),
    headers: {
      Authorization: 'Bearer ' + inputs.apiToken,
      'Content-Type': 'application/json',
      'Idempotency-Key': inputs.idempotencyKey,
    },
    body,
  };
}

export function collectOutputs(
  job: Pick<JobResponse, 'jobId' | 'status' | 'exitCode' | 'output' | 'consoleUrl'>,
): Record<string, string> {
  const outputs: Record<string, string> = {
    'job-id': job.jobId,
    status: job.status,
  };
  if (job.exitCode !== undefined && job.exitCode !== null) {
    outputs['exit-code'] = String(job.exitCode);
  }
  if (job.output !== undefined) {
    outputs.output = typeof job.output === 'string' ? job.output : JSON.stringify(job.output);
  }
  if (job.consoleUrl) outputs['console-url'] = job.consoleUrl;
  return outputs;
}

function retryAfterMs(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1000);
  const date = Date.parse(value);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - Date.now());
}

async function delay(milliseconds: number): Promise<void> {
  let remaining = Math.max(0, milliseconds);
  const maxTimerDelay = 2_147_000_000;
  while (remaining > 0) {
    const chunk = Math.min(remaining, maxTimerDelay);
    await new Promise<void>((resolve) => setTimeout(resolve, chunk));
    remaining -= chunk;
  }
}

async function waitBeforeRetry(
  milliseconds: number,
  deadline: number | undefined,
  context: string,
): Promise<void> {
  if (deadline === undefined) {
    await delay(milliseconds);
    return;
  }
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new WaitTimeoutError(context);
  await delay(Math.min(milliseconds, remaining));
  if (milliseconds >= remaining || Date.now() >= deadline) {
    throw new WaitTimeoutError(context);
  }
}

async function fetchWithRetry(
  url: string,
  init: RequestInit,
  context: string,
  deadline?: number,
): Promise<Response> {
  for (let attempt = 0; attempt < MAX_REQUEST_ATTEMPTS; attempt += 1) {
    if (deadline !== undefined && Date.now() >= deadline) {
      throw new WaitTimeoutError(context);
    }
    let response: Response;
    try {
      const remaining = deadline === undefined ? REQUEST_TIMEOUT_MS : Math.max(1, deadline - Date.now());
      response = await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(Math.min(REQUEST_TIMEOUT_MS, remaining)),
      });
    } catch {
      if (deadline !== undefined && Date.now() >= deadline) {
        throw new WaitTimeoutError(context);
      }
      if (attempt + 1 === MAX_REQUEST_ATTEMPTS) break;
      const backoff = Math.min(1000 * 2 ** attempt, 30_000);
      core.warning('Deplite API 연결에 실패했습니다. ' + backoff / 1000 + '초 후 재시도합니다.');
      await waitBeforeRetry(backoff, deadline, context);
      continue;
    }
    if (response.status !== 429 && response.status < 500) return response;
    if (attempt + 1 === MAX_REQUEST_ATTEMPTS) return response;
    const waitMs =
      response.status === 429
        ? retryAfterMs(response.headers.get('retry-after')) ?? Math.min(1000 * 2 ** attempt, 30_000)
        : Math.min(1000 * 2 ** attempt, 30_000);
    core.warning(
      context +
        ' 요청이 HTTP ' +
        response.status +
        '로 실패했습니다. ' +
        waitMs / 1000 +
        '초 후 재시도합니다.',
    );
    try {
      await response.body?.cancel();
    } catch {}
    await waitBeforeRetry(waitMs, deadline, context);
  }
  throw new Error(
    context + ' 요청을 완료하지 못했습니다. 네트워크 상태를 확인해주세요.',
  );
}

async function requestJson<T>(
  url: string,
  init: RequestInit,
  context: string,
  deadline?: number,
): Promise<T> {
  const response = await fetchWithRetry(url, init, context, deadline);
  const text = await response.text();
  let body: unknown = {};
  if (text) {
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      if (response.ok) throw new Error('Deplite API 응답을 JSON으로 읽을 수 없습니다.');
    }
  }
  if (!response.ok) {
    const errorBody = isRecord(body) ? (body as ApiErrorBody) : {};
    throw new ApiError(
      response.status,
      typeof errorBody.code === 'string' ? errorBody.code : undefined,
      getApiErrorMessage(response.status, errorBody),
    );
  }
  return body as T;
}

export function getApiErrorMessage(status: number, body: ApiErrorBody): string {
  if (body.code === 'workflow_invalid') {
    const invalidCode =
      typeof body.invalidCode === 'string' ? body.invalidCode : undefined;
    const guidance =
      invalidCode === 'duplicate_name'
        ? '같은 이름의 워크플로우 파일이 기기에 여러 개 있어 실행할 수 없습니다. 파일을 하나만 남겨주세요.'
        : ERROR_MESSAGES.workflow_invalid;
    const reason =
      typeof body.reason === 'string'
        ? Array.from(
            body.reason
              .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ')
              .replace(/\s+/g, ' ')
              .trim(),
          )
        : [];
    const safeReason =
      reason.length > 500 ? reason.slice(0, 500).join('') + '…' : reason.join('');
    return (
      'Deplite 요청 실패 (HTTP ' +
      status +
      ', workflow_invalid): ' +
      guidance +
      (safeReason ? ' 사유: ' + safeReason : '')
    );
  }
  const known = body.code ? ERROR_MESSAGES[body.code] : undefined;
  if (known) return 'Deplite 요청 실패 (HTTP ' + status + ', ' + body.code + '): ' + known;
  if (body.code) return 'Deplite 요청 실패 (HTTP ' + status + ', ' + body.code + ').';
  return 'Deplite 요청 실패 (HTTP ' + status + ').';
}

function authHeaders(apiToken: string): Record<string, string> {
  return { Authorization: 'Bearer ' + apiToken, Accept: 'application/json' };
}

async function getAgentId(inputs: ActionInputs): Promise<string> {
  const url =
    inputs.baseUrl.replace(/\/+$/, '') +
    '/run/' +
    encodeURIComponent(inputs.agent) +
    '/' +
    encodeURIComponent(inputs.workflow);
  const response = await requestJson<unknown>(
    url,
    { method: 'GET', headers: authHeaders(inputs.apiToken) },
    '워크플로우 정보 조회',
  );
  if (
    !isRecord(response) ||
    typeof response.agentId !== 'string' ||
    response.agentId.length === 0
  ) {
    throw new Error('워크플로우 정보 응답에 기기 ID가 없습니다.');
  }
  return response.agentId;
}

function requireDispatchResponse(value: DispatchResponse): DispatchResponse {
  if (
    !value ||
    typeof value.jobId !== 'string' ||
    value.jobId.length === 0 ||
    typeof value.status !== 'string'
  ) {
    throw new Error('Deplite API가 실행 job ID 또는 상태를 반환하지 않았습니다.');
  }
  return value;
}

function requireJobResponse(value: JobResponse): JobResponse {
  if (
    !value ||
    typeof value.jobId !== 'string' ||
    value.jobId.length === 0 ||
    typeof value.status !== 'string'
  ) {
    throw new Error('Deplite API가 job ID 또는 상태를 반환하지 않았습니다.');
  }
  return value;
}

function emitDeviceLogs(items: LogsResponse['items']): void {
  if (items.length === 0) return;
  const stopToken = 'deplite_' + randomBytes(18).toString('hex');
  process.stdout.write('::stop-commands::' + stopToken + '\n');
  for (const item of items) {
    const label = [item.stepName, item.stream].filter(Boolean).join(' / ');
    const prefix = label ? '[' + label + '] ' : '';
    let content = prefix + item.content;
    if (!content.endsWith('\n')) content += '\n';
    process.stdout.write(content);
  }
  process.stdout.write('::' + stopToken + '::\n');
}

function validateLogsResponse(value: LogsResponse): LogsResponse {
  if (
    !value ||
    !Array.isArray(value.items) ||
    typeof value.nextAfter !== 'number' ||
    typeof value.jobStatus !== 'string' ||
    typeof value.finished !== 'boolean'
  ) {
    throw new Error('Deplite API가 job 로그 응답을 올바르게 반환하지 않았습니다.');
  }
  for (const item of value.items) {
    if (typeof item.content !== 'string' || typeof item.seq !== 'number') {
      throw new Error('Deplite API 로그 항목의 형식이 올바르지 않습니다.');
    }
  }
  return value;
}

function appendAuth(token: string): RequestInit {
  return { method: 'GET', headers: authHeaders(token) };
}

async function fetchLogs(
  inputs: ActionInputs,
  jobId: string,
  after: number,
  deadline: number,
): Promise<LogsResponse> {
  const url =
    inputs.baseUrl.replace(/\/+$/, '') +
    '/jobs/' +
    encodeURIComponent(jobId) +
    '/logs?after=' +
    String(after) +
    '&limit=' +
    String(LOG_PAGE_LIMIT);
  return validateLogsResponse(
    await requestJson<LogsResponse>(
      url,
      appendAuth(inputs.apiToken),
      '기기 로그 조회',
      deadline,
    ),
  );
}

async function fetchJob(inputs: ActionInputs, jobId: string, deadline: number): Promise<JobResponse> {
  const url = inputs.baseUrl.replace(/\/+$/, '') + '/jobs/' + encodeURIComponent(jobId);
  return requireJobResponse(
    await requestJson<JobResponse>(
      url,
      appendAuth(inputs.apiToken),
      'job 상태 조회',
      deadline,
    ),
  );
}

function applyLogs(result: LogsResponse): void {
  emitDeviceLogs(result.items);
}

export async function waitForJob(
  inputs: ActionInputs,
  dispatch: DispatchResponse,
): Promise<JobResponse> {
  const deadline = Date.now() + inputs.waitTimeoutMinutes * 60_000;
  let interval = 2_000;
  try {
    if (inputs.logs) {
      let after = 0;
      while (Date.now() < deadline) {
        const result = await fetchLogs(inputs, dispatch.jobId, after, deadline);
        applyLogs(result);
        const hadLogs = result.items.length > 0;
        after = result.nextAfter;
        if (result.finished) {
          await delay(Math.min(1_000, Math.max(0, deadline - Date.now())));
          while (Date.now() < deadline) {
            const lateLogs = await fetchLogs(inputs, dispatch.jobId, after, deadline);
            applyLogs(lateLogs);
            after = lateLogs.nextAfter;
            if (lateLogs.items.length === 0) break;
          }
          if (Date.now() >= deadline) {
            throw new WaitTimeoutError(dispatch.jobId, dispatch.consoleUrl);
          }
          return await fetchJob(inputs, dispatch.jobId, deadline);
        }
        if (result.items.length >= LOG_PAGE_LIMIT) continue;
        if (Date.now() >= deadline) break;
        await delay(Math.min(interval, deadline - Date.now()));
        interval = hadLogs ? 2_000 : Math.min(interval * 2, 10_000);
      }
    } else {
      while (Date.now() < deadline) {
        const job = await fetchJob(inputs, dispatch.jobId, deadline);
        if (TERMINAL_STATUSES.has(job.status)) return job;
        if (Date.now() >= deadline) break;
        await delay(Math.min(interval, deadline - Date.now()));
        interval = Math.min(interval * 2, 10_000);
      }
    }
  } catch (error) {
    if (error instanceof WaitTimeoutError) {
      throw new WaitTimeoutError(dispatch.jobId, dispatch.consoleUrl);
    }
    throw error;
  }
  throw new WaitTimeoutError(dispatch.jobId, dispatch.consoleUrl);
}

function setOutputs(job: JobResponse): void {
  for (const [name, value] of Object.entries(collectOutputs(job))) {
    core.setOutput(name, value);
  }
}

function escapeSummaryHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function summaryCode(value: string): string {
  return '<code>' + escapeSummaryHtml(value.replace(/[\r\n]+/g, ' ')) + '</code>';
}

async function writeSummary(
  inputs: ActionInputs,
  job: JobResponse,
  startedAt: number,
): Promise<void> {
  const elapsedSeconds = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
  const rows: Array<Array<string | { data: string; header?: boolean }>> = [
    [{ data: '항목', header: true }, { data: '값', header: true }],
    ['Agent', summaryCode(inputs.agent)],
    ['워크플로우', summaryCode(inputs.workflow)],
    ['상태', summaryCode(job.status)],
    ['소요 시간', elapsedSeconds + '초'],
  ];
  const summary = core.summary.addHeading('Deplite 워크플로우 실행', 3).addTable(rows);
  if (job.consoleUrl) {
    try {
      const url = new URL(job.consoleUrl);
      if (url.protocol === 'https:' || url.protocol === 'http:') {
        summary.addLink('콘솔에서 보기', escapeSummaryHtml(url.href));
      }
    } catch {}
  }
  await summary.write();
}

function assertJobSuccess(job: JobResponse): void {
  if (job.status === 'success') return;
  const details = [
    '기기 워크플로우가 성공하지 않았습니다.',
    '상태: ' + job.status,
    job.exitCode !== undefined && job.exitCode !== null ? '종료 코드: ' + job.exitCode : undefined,
    job.errorMessage ? '오류: ' + job.errorMessage : undefined,
    job.reason ? '사유: ' + job.reason : undefined,
    job.consoleUrl ? '콘솔: ' + job.consoleUrl : undefined,
  ].filter((value): value is string => Boolean(value));
  throw new Error(details.join(' / '));
}

export function parsePositiveInteger(raw: string, name: string): number {
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(name + '은 1 이상의 정수여야 합니다.');
  }
  return value;
}

function readApprovalInputs(): ApprovalCredential | undefined {
  const keyId = core.getInput('approval-key-id');
  const secret = core.getInput('approval-secret', { trimWhitespace: false });
  const privateKey = core.getInput('approval-private-key');
  if (secret) core.setSecret(secret);
  if (privateKey) core.setSecret(privateKey);
  if (secret) validateHmacSecret(secret);
  if (!keyId && !secret && !privateKey) return undefined;
  if (!keyId || keyId.length > 128 || Boolean(secret) === Boolean(privateKey)) {
    throw new Error(
      '승인을 사용하려면 approval-key-id와 approval-secret 또는 approval-private-key 중 하나를 입력해야 합니다.',
    );
  }
  return secret ? { keyId, secret } : { keyId, privateKey };
}

export function readInputs(env: NodeJS.ProcessEnv = process.env): ActionInputs {
  const apiToken = core.getInput('api-token');
  if (!apiToken) throw new Error('api-token 입력이 필요합니다.');
  core.setSecret(apiToken);
  const agent = core.getInput('agent');
  if (!agent) throw new Error('agent 입력이 필요합니다.');
  const workflow = core.getInput('workflow');
  if (!workflow) throw new Error('workflow 입력이 필요합니다.');
  const params = parseParams(core.getInput('params'));
  const ref = resolveRef(core.getInput('ref'), env);
  let debug: boolean;
  let wait: boolean;
  let logs: boolean;
  try {
    debug = core.getBooleanInput('debug');
    wait = core.getBooleanInput('wait');
    logs = core.getBooleanInput('logs');
  } catch {
    throw new Error('debug, wait, logs 입력은 true 또는 false여야 합니다.');
  }
  const waitTimeoutMinutes = parsePositiveInteger(
    core.getInput('wait-timeout-minutes') || '60',
    'wait-timeout-minutes',
  );
  if (waitTimeoutMinutes > Math.floor((Number.MAX_SAFE_INTEGER - Date.now()) / 60_000)) {
    throw new Error('wait-timeout-minutes 값이 너무 큽니다.');
  }
  const baseUrl = core.getInput('base-url') || DEFAULT_BASE_URL;
  let parsedBase: URL;
  try {
    parsedBase = new URL(baseUrl);
  } catch {
    throw new Error('base-url이 올바른 URL이 아닙니다.');
  }
  if (
    (parsedBase.protocol !== 'https:' && parsedBase.protocol !== 'http:') ||
    parsedBase.search ||
    parsedBase.hash
  ) {
    throw new Error('base-url은 http 또는 https 주소여야 합니다.');
  }
  const initial: Pick<ActionInputs, 'ref' | 'debug' | 'params'> = { ref, debug, params };
  const idempotencyKey = resolveIdempotencyKey(
    core.getInput('idempotency-key'),
    env,
    initial,
  );
  return {
    apiToken,
    agent,
    workflow,
    params,
    ref,
    debug,
    wait,
    waitTimeoutMinutes,
    logs,
    idempotencyKey,
    baseUrl,
    approval: readApprovalInputs(),
  };
}

export async function main(): Promise<void> {
  const inputs = readInputs();
  const startedAt = Date.now();
  let approval: Record<string, unknown> | undefined;
  if (inputs.approval) {
    const agentId = await getAgentId(inputs);
    approval = buildApproval(
      inputs.approval,
      agentId,
      inputs.workflow,
      inputs.params ?? {},
      inputs.ref,
    );
  }

  const request = buildDispatchRequest(inputs, process.env, approval);
  core.info('Deplite 워크플로우 실행을 요청합니다.');
  const dispatched = requireDispatchResponse(
    await requestJson<DispatchResponse>(
      request.url,
      {
        method: 'POST',
        headers: request.headers,
        body: JSON.stringify(request.body),
      },
      '워크플로우 실행 요청',
    ),
  );
  core.info(
    'job ' +
      dispatched.jobId +
      ' 실행을 시작했습니다 (' +
      dispatched.status +
      (dispatched.idempotent ? ', 기존 실행 재사용' : '') +
      ').',
  );

  if (!inputs.wait) {
    setOutputs({
      jobId: dispatched.jobId,
      status: dispatched.status,
      consoleUrl: dispatched.consoleUrl,
    });
    await writeSummary(
      inputs,
      { jobId: dispatched.jobId, status: dispatched.status, consoleUrl: dispatched.consoleUrl },
      startedAt,
    );
    return;
  }

  try {
    const job = await waitForJob(inputs, dispatched);
    setOutputs(job);
    await writeSummary(inputs, job, startedAt);
    assertJobSuccess(job);
  } catch (error) {
    if (error instanceof WaitTimeoutError) {
      setOutputs({
        jobId: dispatched.jobId,
        status: 'timeout',
        consoleUrl: error.consoleUrl ?? dispatched.consoleUrl,
      });
      await writeSummary(
        inputs,
        {
          jobId: dispatched.jobId,
          status: 'timeout',
          consoleUrl: error.consoleUrl ?? dispatched.consoleUrl,
        },
        startedAt,
      );
    }
    throw error;
  }
}
