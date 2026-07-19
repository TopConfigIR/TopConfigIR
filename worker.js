const apiBase = 'https://api.cloudflare.com/client/v4';
const compatDate = '2026-01-20';
const bindingName = 'C';
const remoteSourceBase = 'https://raw.githubusercontent.com/TopConfigIR/TopConfigIR/main';

export default {
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;
    if (path.startsWith('/api/')) {
      const context = {
        request,
        env,
        waitUntil: ctx?.waitUntil?.bind(ctx),
        passThroughOnException: ctx?.passThroughOnException?.bind(ctx)
      };
      return request.method === 'POST' ? onRequestPost(context) : onRequest(context);
    }
    if (env?.ASSETS?.fetch) return env.ASSETS.fetch(request);
    return new Response('Not Found', { status: 404 });
  }
};

export async function onRequestPost(context) {
  try {
    const data = await context.request.json().catch(() => ({}));
    const path = new URL(context.request.url).pathname.replace(/^\/api\/?/, '');
    if (path === 'accounts') {
      const accounts = await callApi(data.credentials, '/accounts?per_page=50');
      return returnValJSON(200, { ok: true, accounts: accounts.map(account => ({ id: account.id, name: account.name })) });
    }
    if (path === 'zones') {
      const zones = await callApi(data.credentials, '/zones?status=active&per_page=100');
      return returnValJSON(200, { ok: true, zones: zones.map(zone => ({ id: zone.id, name: zone.name })) });
    }
    if (path === 'resources') {
      if (!data.accountId) throw new Error('missing Account ID');
      const resources = await readResourceList(data.credentials, data.accountId);
      return returnValJSON(200, { ok: true, ...resources });
    }
    if (path === 'deploy') {
      const result = await deploy(data, context);
      return returnValJSON(200, { ok: true, ...result });
    }
    return returnValJSON(404, { ok: false, error: 'apiNotFound' });
  } catch (error) {
    return returnValJSON(500, { ok: false, error: error.message || String(error) });
  }
}

export function onRequest() {
  return returnValJSON(405, { ok: false, error: 'onlySupports POST' });
}

async function deploy(data, context) {
  data = await fillDeployDefaults(data);
  validateDeployParams(data);
  const log = [];
  const record = text => log.push(`[${new Date().toLocaleTimeString()}] ${text}`);
  const uuid = data.uuid || crypto.randomUUID();
  const opMode = data.deployMode === 'update' ? 'update' : 'create';
  const rawProjectName = String(data.projectName || '').trim();
  const projectName = opMode === 'update' ? rawProjectName : sanitizeProjectName(rawProjectName || generateRandomName('TopConfigIR'));
  const mode = data.sourceMode === 'plain' ? 'plain' : 'encoded';
  const deployKind = data.deployType === 'worker' ? 'worker' : 'pages';
  record(`prepare${opMode === 'update' ? 'update' : 'deploy'} ${deployKind === 'pages' ? 'Pages' : 'Worker'}: ${projectName}`);
  record(`deploySource: ${mode === 'plain' ? 'plainSourceLabel' : 'encodedSourceLabel'}，liveFetchOverNetwork`);
  if (opMode === 'update') {
    if (deployKind === 'worker') {
      await syncWorkercode(data.credentials, {
        accountId: data.accountId,
        scriptName: projectName,
        sourceMode: mode
      }, context, record);
    } else {
      await syncPagescode(data.credentials, {
        accountId: data.accountId,
        projectName: projectName,
        sourceMode: mode
      }, context, record);
    }
    record('updateModeCodeOnly，unchanged UUID、KV、domainOrProjectConfig');
    return { deployType: deployKind, projectName: projectName, sourceMode: mode, logs: log };
  }
  const namespace = await getOrCreateKV(data.credentials, data.accountId, {
    id: data.kvId,
    title: data.kvTitle || generateRandomName('TopConfigIR-kv')
  }, record);
  if (namespace.created) {
    await initializeKV(data.credentials, data.accountId, namespace.id, record);
  } else {
    record('reuseExisting KV，keepOriginalConfig');
  }
  if (deployKind === 'worker') {
    await deployWorker(data.credentials, {
      accountId: data.accountId,
      scriptName: projectName,
      sourceMode: mode,
      uuid,
      kvId: namespace.id,
      enableWorkersDev: !!data.enableWorkersDev
    }, context, record);
  } else {
    await deployPages(data.credentials, {
      accountId: data.accountId,
      projectName: projectName,
      sourceMode: mode,
      uuid,
      kvId: namespace.id
    }, context, record);
  }
  let domain = null;
  if (data.hostname && data.zoneId) {
    domain = await bindDomain(data.credentials, {
      accountId: data.accountId,
      deployType: deployKind,
      projectName: projectName,
      zoneId: data.zoneId,
      hostname: data.hostname
    }, record);
  }
  const domains = await listBoundDomains(data.credentials, {
    accountId: data.accountId,
    deployType: deployKind,
    projectName: projectName
  }, record);
  record('deployDone');
  return {
    deployType: deployKind,
    projectName: projectName,
    sourceMode: mode,
    uuid,
    kv: { id: namespace.id, title: namespace.title || data.kvTitle || '' },
    domain,
    domains,
    logs: log
  };
}

async function fillDeployDefaults(data) {
  if (!data?.credentials?.email || !data?.credentials?.key) return data;
  const output = { ...data };
  let zones = null;
  if (!output.accountId) {
    const accounts = await callApi(output.credentials, '/accounts?per_page=50');
    if (!accounts.length) throw new Error('noAccountForCredentials');
    output.accountId = accounts[0].id;
    output.accountName = accounts[0].name;
  }
  if (!output.deployType) output.deployType = 'pages';
  if (!output.sourceMode) output.sourceMode = 'encoded';
  if (output.deployMode === 'update') return output;
  if (output.autoDomain && !output.hostname) {
    zones = await callApi(output.credentials, '/zones?status=active&per_page=100');
    if (zones.length) {
      output.zoneId = output.zoneId || zones[0].id;
      output.zoneName = zones[0].name;
      output.hostname = `${generateRandomName('TopConfigIR')}.${zones[0].name}`;
    }
  }
  if (output.hostname && !output.zoneId) {
    zones = zones || await callApi(output.credentials, '/zones?status=active&per_page=100');
    const zone = zones
      .filter(zone => output.hostname === zone.name || output.hostname.endsWith(`.${zone.name}`))
      .sort((a, b) => b.name.length - a.name.length)[0];
    if (!zone) throw new Error(`noMatchingZoneFound ${output.hostname} _of Cloudflare Zone`);
    output.zoneId = zone.id;
    output.zoneName = zone.name;
  }
  if (output.hostname && output.zoneId) {
    zones = zones || await callApi(output.credentials, '/zones?status=active&per_page=100');
    const zone = zones.find(zone => zone.id === output.zoneId) || (output.zoneName ? { id: output.zoneId, name: output.zoneName } : null);
    if (zone && output.hostname === zone.name) {
      output.hostname = `${generateRandomName('TopConfigIR')}.${zone.name}`;
      output.zoneName = zone.name;
    }
  }
  return output;
}

async function readResourceList(credentials, accountId) {
  const [workerResult, pagesResult, kvResult] = await Promise.allSettled([
    callApi(credentials, `/accounts/${accountId}/workers/scripts?per_page=100`),
    readPagesprojectList(credentials, accountId),
    callApi(credentials, `/accounts/${accountId}/storage/kv/namespaces?per_page=100`)
  ]);
  const warnings = [];
  const workers = extractList(workerResult, warnings, 'Worker')
    .map(project => ({ name: project.id || project.script_name || project.name, title: project.id || project.script_name || project.name }))
    .filter(project => project.name);
  const pages = extractList(pagesResult, warnings, 'Pages')
    .map(project => ({
      name: project.name,
      title: project.name,
      kvId: extractPagesKV(project),
      domains: project.domains || []
    }))
    .filter(project => project.name);
  const kvs = extractList(kvResult, warnings, 'KV')
    .map(space => ({ id: space.id, title: space.title }))
    .filter(space => space.id);
  return { workers, pages, kvs, warnings };
}

function extractPagesKV(project) {
  const config = project?.deployment_configs || {};
  for (const env of ['production', 'preview']) {
    const namespace = config[env]?.kv_namespaces || {};
    const binding = namespace[bindingName] || Object.values(namespace)[0];
    if (binding?.namespace_id) return binding.namespace_id;
    if (typeof binding === 'string') return binding;
  }
  return '';
}

async function readPagesprojectList(credentials, accountId) {
  try {
    return await callApi(credentials, `/accounts/${accountId}/pages/projects`);
  } catch (error) {
    if (!String(error.message || '').includes('Invalid list options')) throw error;
    return await callApi(credentials, `/accounts/${accountId}/pages/projects?page=1`);
  }
}

function extractList(result, warnings, label) {
  if (result.status === 'fulfilled') return Array.isArray(result.value) ? result.value : [];
  warnings.push(`${label} listReadFailed: ${result.reason?.message || result.reason}`);
  return [];
}

function validateDeployParams(data) {
  if (!data?.credentials?.email || !data?.credentials?.key) throw new Error('missing Cloudflare emailOr Global API Key');
  if (!data.accountId) throw new Error('missing Account ID');
  if (data.deployMode === 'update' && !String(data.projectName || '').trim()) throw new Error('projectNameRequiredForUpdate');
  if (data.deployMode === 'update') return;
  if (data.hostname && !data.zoneId) throw new Error('zoneRequiredForDomainBind Zone');
}

async function deployWorker(credentials, options, context, record) {
  const code = await readSourceCode(options.sourceMode, context);
  const form = new FormData();
  const metadata = {
    main_module: 'worker.js',
    compatibility_date: compatDate,
    bindings: [
      { type: 'plain_text', name: 'u', text: options.uuid },
      { type: 'kv_namespace', name: bindingName, namespace_id: options.kvId }
    ]
  };
  form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }), 'metadata.json');
  form.append('worker.js', new Blob([code], { type: 'application/javascript+module' }), 'worker.js');
  await callApi(credentials, `/accounts/${options.accountId}/workers/scripts/${encodeURIComponent(options.scriptName)}`, {
    method: 'PUT',
    body: form
  });
  record('Worker scriptUploadDone');
  if (options.enableWorkersDev) {
    await enableWorkersDev(credentials, options.accountId, options.scriptName);
    record('workers.dev defaultDomainEnabled');
  }
}

async function syncWorkercode(credentials, options, context, record) {
  const code = await readSourceCode(options.sourceMode, context);
  const settings = await readWorkersettings(credentials, options.accountId, options.scriptName);
  const metadata = generateKeptWorkermetadata(settings);
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }), 'metadata.json');
  form.append('worker.js', new Blob([code], { type: 'application/javascript+module' }), 'worker.js');
  await callApi(credentials, `/accounts/${options.accountId}/workers/scripts/${encodeURIComponent(options.scriptName)}`, {
    method: 'PUT',
    body: form
  });
  record('Worker codeSynced，existingBindingsKeptAsIs');
}

async function readWorkersettings(credentials, accountId, scriptName) {
  try {
    return await callApi(credentials, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/settings`);
  } catch (error) {
    throw new Error(`readExisting Worker settingsFailed，stoppedToAvoidOverwrite KV/UUID config: ${error.message}`);
  }
}

function generateKeptWorkermetadata(settings) {
  const metadata = {};
  for (const field of [
    'main_module',
    'compatibility_date',
    'compatibility_flags',
    'bindings',
    'migrations',
    'usage_model',
    'limits',
    'placement',
    'tail_consumers',
    'logpush'
  ]) {
    if (settings?.[field] !== undefined && settings?.[field] !== null) metadata[field] = settings[field];
  }
  if (!metadata.main_module) metadata.main_module = 'worker.js';
  if (!metadata.compatibility_date) throw new Error('cannotReadExisting Worker compatibility_date，stoppedToAvoidConfigChange');
  if (!Array.isArray(metadata.bindings)) throw new Error('cannotReadExisting Worker binding，stoppedToAvoidOverwrite KV/UUID config');
  return metadata;
}

async function deployPages(credentials, options, context, record) {
  const project = await createOrUpdatePagesproject(credentials, options, record);
  const code = await readSourceCode(options.sourceMode, context);
  await uploadPagesdeploy(credentials, options.accountId, options.projectName, code, record);
  record(`Pages projectConfigured: ${project.name}`);
  record('Pages deployUploadDone');
}

async function syncPagescode(credentials, options, context, record) {
  try {
    await callApi(credentials, `/accounts/${options.accountId}/pages/projects/${encodeURIComponent(options.projectName)}`);
  } catch (error) {
    if (String(error.message).includes('404')) throw new Error(`existingNotFound Pages project: ${options.projectName}`);
    throw error;
  }
  const code = await readSourceCode(options.sourceMode, context);
  record('Pages updateModeNoChange KV/variable/domainConfig');
  await uploadPagesdeploy(credentials, options.accountId, options.projectName, code, record);
  record('Pages codeSyncDone');
}

async function uploadPagesdeploy(credentials, accountId, projectName, workerCode, record) {
  const manifest = await uploadPagesstaticAssets(credentials, accountId, projectName);
  const form = new FormData();
  form.append('manifest', JSON.stringify(manifest));
  form.append('branch', 'main');
  form.append('commit_dirty', 'true');
  form.append('commit_message', 'deploy from TopConfigIR panel');
  const workerBundle = await generateWorkerBundle(workerCode);
  form.append('_worker.bundle', workerBundle, '_worker.bundle');
  const deployment = await callApi(credentials, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}/deployments`, {
    method: 'POST',
    body: form
  });
  if (deployment?.url) record(`Pages url: ${deployment.url}`);
}

async function uploadPagesstaticAssets(credentials, accountId, projectName) {
  const { jwt } = await callApi(credentials, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}/upload-token`);
  const content = '<!doctype html><meta charset="utf-8"><title>Deploy</title>';
  const bytes = new TextEncoder().encode(content);
  const hash = await computeAssetHash(bytes, 'html');
  const missing = await callJWTapi(jwt, '/pages/assets/check-missing', {
    method: 'POST',
    body: { hashes: [hash] }
  });
  if (!Array.isArray(missing) || missing.includes(hash)) {
    await callJWTapi(jwt, '/pages/assets/upload', {
      method: 'POST',
      body: [{
        key: hash,
        value: bytesToBase64(bytes),
        metadata: { contentType: 'text/html; charset=utf-8' },
        base64: true
      }]
    });
  }
  await callJWTapi(jwt, '/pages/assets/upsert-hashes', {
    method: 'POST',
    body: { hashes: [hash] }
  }).catch(() => null);
  return { '/index.html': hash };
}

async function generateWorkerBundle(workerCode) {
  const inner = new FormData();
  const metadata = {
    main_module: 'worker.js',
    compatibility_date: compatDate
  };
  inner.set('metadata', JSON.stringify(metadata));
  inner.set('worker.js', new Blob([workerCode], { type: 'application/javascript+module' }), 'worker.js');
  return await new Response(inner).blob();
}

async function createOrUpdatePagesproject(credentials, options, record) {
  let project = null;
  try {
    project = await callApi(credentials, `/accounts/${options.accountId}/pages/projects/${encodeURIComponent(options.projectName)}`);
  } catch (error) {
    if (!String(error.message).includes('404')) throw error;
  }
  if (!project) {
    project = await callApi(credentials, `/accounts/${options.accountId}/pages/projects`, {
      method: 'POST',
      body: {
        name: options.projectName,
        production_branch: 'main',
        deployment_configs: generatePagesconfig(options)
      }
    });
    record('Pages projectCreated');
    return project;
  }
  await callApi(credentials, `/accounts/${options.accountId}/pages/projects/${encodeURIComponent(options.projectName)}`, {
    method: 'PATCH',
    body: { deployment_configs: mergePagesconfig(project.deployment_configs || {}, options) }
  });
  record('Pages projectConfigUpdated');
  return project;
}

function generatePagesconfig(options) {
  const singleItem = {
    compatibility_date: compatDate,
    env_vars: { u: { type: 'plain_text', value: options.uuid } },
    kv_namespaces: { [bindingName]: { namespace_id: options.kvId } }
  };
  return { production: singleItem, preview: singleItem };
}

function mergePagesconfig(existing, options) {
  const output = structuredClone(existing || {});
  for (const name of ['production', 'preview']) {
    output[name] = output[name] || {};
    output[name].compatibility_date = compatDate;
    output[name].env_vars = output[name].env_vars || {};
    output[name].env_vars.u = { type: 'plain_text', value: options.uuid };
    output[name].kv_namespaces = output[name].kv_namespaces || {};
    output[name].kv_namespaces[bindingName] = { namespace_id: options.kvId };
  }
  return output;
}

async function getOrCreateKV(credentials, accountId, options, record) {
  const list = await callApi(credentials, `/accounts/${accountId}/storage/kv/namespaces?per_page=100`);
  if (options.id) {
    const selected = list.find(item => item.id === options.id);
    if (selected) {
      record(`reuse KV: ${selected.title}`);
      return { ...selected, created: false };
    }
    record(`useSpecified KV: ${options.id}`);
    return { id: options.id, title: options.title || options.id, created: false };
  }
  const title = options.title;
  const existing = list.find(item => item.title === title);
  if (existing) {
    record(`reuse KV: ${title}`);
    return { ...existing, created: false };
  }
  const createResult = await callApi(credentials, `/accounts/${accountId}/storage/kv/namespaces`, {
    method: 'POST',
    body: { title: title }
  });
  record(`create KV: ${title}`);
  return { ...createResult, title: title, created: true };
}

async function initializeKV(credentials, accountId, namespaceId, record) {
  await callRawApi(credentials, `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/c`, {
    method: 'PUT',
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    body: '{}'
  });
  await callRawApi(credentials, `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/c_ver`, {
    method: 'PUT',
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    body: String(Date.now())
  });
  record('KV initialConfigWritten');
}

async function enableWorkersDev(credentials, accountId, scriptName) {
  const path = `/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/subdomain`;
  try {
    await callApi(credentials, path, { method: 'POST', body: { enabled: true } });
  } catch {
    await callApi(credentials, path, { method: 'PUT', body: { enabled: true } });
  }
}

async function bindDomain(credentials, options, record) {
  if (options.deployType === 'pages') {
    const result = await callApi(credentials, `/accounts/${options.accountId}/pages/projects/${encodeURIComponent(options.projectName)}/domains`, {
      method: 'POST',
      body: { name: options.hostname }
    });
    record(`Pages domainBound: ${options.hostname}`);
    // autoCreate CNAME logPointer Pages project，sameAccountDomainAutoVerified
    try {
      await callApi(credentials, `/zones/${options.zoneId}/dns_records`, {
        method: 'POST',
        body: { type: 'CNAME', name: options.hostname, content: `${options.projectName}.pages.dev`, proxied: true }
      });
      record(`CNAME logCreated: ${options.hostname} → ${options.projectName}.pages.dev`);
    } catch (dnserror) {
      record(`CNAME logCreateSkipped(mayAlreadyExist): ${dnserror.message}`);
    }
    return { hostname: result.name || options.hostname, type: 'pages' };
  }
  const requestBody = {
    environment: 'production',
    hostname: options.hostname,
    service: options.projectName,
    zone_id: options.zoneId
  };
  try {
    const result = await callApi(credentials, `/accounts/${options.accountId}/workers/domains`, {
      method: 'PUT',
      body: requestBody
    });
    record(`Worker customDomainBound: ${options.hostname}`);
    return { hostname: result.hostname || options.hostname, type: 'worker' };
  } catch (error) {
    await callApi(credentials, `/zones/${options.zoneId}/workers/routes`, {
      method: 'POST',
      body: { pattern: `${options.hostname}/*`, script: options.projectName }
    });
    record(`Worker Route bound: ${options.hostname}/*`);
    return { hostname: options.hostname, type: 'route', warning: error.message };
  }
}

async function listBoundDomains(credentials, options, record) {
  try {
    if (options.deployType === 'pages') {
      const list = await callApi(credentials, `/accounts/${options.accountId}/pages/projects/${encodeURIComponent(options.projectName)}/domains`);
      return list.map(item => ({ hostname: item.name || item.hostname, status: item.status || '' }));
    }
    const list = await callApi(credentials, `/accounts/${options.accountId}/workers/domains?per_page=100`);
    return list
      .filter(item => item.service === options.projectName || item.script === options.projectName)
      .map(item => ({ hostname: item.hostname || item.domain, status: item.status || '' }));
  } catch (error) {
    record(`domainListReadFailed: ${error.message}`);
    return [];
  }
}

async function readSourceCode(mode, context) {
  const fileName = mode === 'plain' ? 'plain.js' : 'worker.js';
  const remoteUrl = `${remoteSourceBase}/${encodeURIComponent(fileName)}?t=${Date.now()}`;
  const response = await fetch(remoteUrl, {
    headers: {
      'Cache-Control': 'no-cache',
      Pragma: 'no-cache'
    }
  });
  if (!response.ok) throw new Error(`liveSourceFetchFailed: ${response.status} ${response.statusText}`);
  const content = await response.text();
  if (!content.trim()) throw new Error('liveSourceFetchFailed: remoteSourceEmpty');
  return content;
}

async function callApi(credentials, path, options = {}) {
  const responseBody = await callRawApi(credentials, path, options);
  if (responseBody && typeof responseBody === 'object' && 'success' in responseBody) {
    if (!responseBody.success) {
      const message = (responseBody.errors || []).map(error => error.message || JSON.stringify(error)).join('; ') || 'Cloudflare API requestFailed';
      const exception = new Error(message);
      exception.response = responseBody;
      throw exception;
    }
    return responseBody.result;
  }
  return responseBody;
}

async function callRawApi(credentials, path, options = {}) {
  const headers = {
    'X-Auth-Email': credentials.email,
    'X-Auth-Key': credentials.key,
    ...(options.headers || {})
  };
  return await requestJSON(`${apiBase}${path}`, headers, options);
}

async function callJWTapi(jwt, path, options = {}) {
  const headers = {
    Authorization: `Bearer ${jwt}`,
    ...(options.headers || {})
  };
  return await requestJSON(`${apiBase}${path}`, headers, options);
}

async function requestJSON(url, headers, options = {}) {
  let body = options.body;
  if (body && !(body instanceof FormData) && typeof body !== 'string') {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    body = JSON.stringify(body);
  }
  const response = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body
  });
  const contentType = response.headers.get('content-type') || '';
  const responseBody = contentType.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) {
    const message = typeof responseBody === 'string'
      ? responseBody
      : (responseBody.errors || []).map(error => error.message || JSON.stringify(error)).join('; ');
    throw new Error(`${response.status} ${response.statusText}${message ? ` - ${message}` : ''}`);
  }
  if (responseBody && typeof responseBody === 'object' && 'success' in responseBody) {
    if (!responseBody.success) {
      const message = (responseBody.errors || []).map(error => error.message || JSON.stringify(error)).join('; ') || 'Cloudflare API requestFailed';
      throw new Error(message);
    }
    return responseBody.result;
  }
  return responseBody;
}

async function computeAssetHash(bytes, extension) {
  const summary = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${bytesToBase64(bytes)}${extension}`));
  return [...new Uint8Array(summary)].map(byte => byte.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

function bytesToBase64(bytes) {
  let binary = '';
  const step = 0x8000;
  for (let index = 0; index < bytes.length; index += step) {
    binary += String.fromCharCode(...bytes.slice(index, index + step));
  }
  return btoa(binary);
}

function returnValJSON(statusCode, data) {
  return new Response(JSON.stringify(data), {
    status: statusCode,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

function sanitizeProjectName(name) {
  return String(name || generateRandomName('TopConfigIR')).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '') || generateRandomName('TopConfigIR');
}

function generateRandomName(prefix) {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}
