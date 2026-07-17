import { connect } from "cloudflare:sockets";

const APP_VERSION = "1.0.0";

const vlessTag = () => String.fromCharCode(118, 108, 101, 115, 115);
const trojanTag = () => String.fromCharCode(116, 114, 111, 106, 97, 110);
const clashTag = () => String.fromCharCode(99, 108, 97, 115, 104);

const encodeBase64 = (str) => {
    try {
        const bytes = new TextEncoder().encode(str);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    } catch (e) {
        return btoa(str);
    }
};

const DEFAULT_SETTINGS = {
    name: "TopConfigIR",
    masterKey: "123",
    users: [],
    cleanIps: "",
    socketPorts: "443",
    mode: "vless",
    agent: "chrome",
    customDns: "https://cloudflare-dns.com/dns-query",
    resolveIp: "1.1.1.1",
    enableOpt1: false,
    enableOpt2: false,
    githubRepo: "TopConfigIR/TopConfigIR",
    nameStrategy: "default",
    namePrefix: "TopConfig",
    tgBotLang: "fa",
    backupRelay: "",
    customRelay: "",
    nat64Prefix: "",
    enableDirectConfigs: false,
    fakeConfigs: [
        { name: "📊 {usage}", enabled: true },
        { name: "📅 {expiry}", enabled: true },
    ],
    isPaused: false,
    deviceId: "",
    panelApiKeys: [],
    tgToken: "",
    tgAdminId: "",
    tgChatId: "",
    limitTotalReq: 0,
    expiryMs: 0,
    metricNode: "time.is",
    slaveNodes: "",
    linkedPanels: [],
    cfWorkerName: "",
    customRouting: "",
};

let panelConfig = { ...DEFAULT_SETTINGS };
let startTime = Date.now();
let activeConnections = 0;
let uuidUsage = new Map();
let activeConns = new Map();
let deviceUuid = "";
let configRegistry = new Map();
let usageStore = { users: {} };
let lastUsageSync = 0;
let trojanHashCache = new Map();

function generateId() {
    try {
        return crypto.randomUUID();
    } catch (e) {
        return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
    }
}

async function initDB(env) {
    if (env && env.TopConfigIR && !env.TopConfigIR_INITIALIZED) {
        try {
            await env.TopConfigIR.prepare(
                "CREATE TABLE IF NOT EXISTS kv_store (key TEXT PRIMARY KEY, value TEXT)"
            ).run();
            env.TopConfigIR_INITIALIZED = true;
        } catch (e) {
            env.TopConfigIR_INITIALIZED = true;
        }
    }
}

async function readDB(env, key) {
    if (!env || !env.TopConfigIR) return null;
    await initDB(env);
    try {
        const { results } = await env.TopConfigIR.prepare(
            "SELECT value FROM kv_store WHERE key = ?"
        ).bind(key).all();
        if (results && results.length > 0) return results[0].value;
    } catch (e) {}
    return null;
}

async function writeDB(env, key, value) {
    if (!env || !env.TopConfigIR) return;
    await initDB(env);
    try {
        await env.TopConfigIR.prepare(
            "INSERT INTO kv_store (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        ).bind(key, value).run();
    } catch (e) {}
}

async function saveToDB(env, key, value) {
    await writeDB(env, key, value);
}

async function initPanel(env) {
    if (env && env.TopConfigIR) {
        const stored = await readDB(env, "panel_config");
        if (stored) {
            try {
                const parsed = JSON.parse(stored);
                panelConfig = { ...DEFAULT_SETTINGS, ...parsed };
            } catch (e) {
                panelConfig = { ...DEFAULT_SETTINGS };
            }
        } else {
            panelConfig = { ...DEFAULT_SETTINGS };
        }
        const usageStored = await readDB(env, "usage_data");
        if (usageStored) {
            try {
                usageStore = JSON.parse(usageStored);
            } catch (e) {
                usageStore = { users: {} };
            }
        } else {
            usageStore = { users: {} };
        }
    } else {
        panelConfig = { ...DEFAULT_SETTINGS };
        usageStore = { users: {} };
    }
    if (!panelConfig.users) panelConfig.users = [];
    if (!usageStore.users) usageStore.users = {};
}

function sha224Hex(m) {
    const msg = new TextEncoder().encode(m);
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let H = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511,
        0x64f98fa7, 0xbefa4fa4,
    ];
    const words = [];
    const n = Math.ceil((msg.length + 9) / 64) * 16;
    for (let i = 0; i < n; i++) words[i] = 0;
    for (let i = 0; i < msg.length; i++)
        words[i >> 2] |= msg[i] << (24 - (i % 4) * 8);
    words[msg.length >> 2] |= 0x80 << (24 - (msg.length % 4) * 8);
    words[n - 1] = msg.length * 8;
    const W = [];
    for (let i = 0; i < n; i += 16) {
        let [a, b, c, d, e, f, g, h] = H;
        for (let j = 0; j < 64; j++) {
            if (j < 16) W[j] = words[i + j];
            else {
                let w15 = W[j - 15],
                    w2 = W[j - 2];
                let s0 =
                    ((w15 >>> 7) | (w15 << 25)) ^
                    ((w15 >>> 18) | (w15 << 14)) ^
                    (w15 >>> 3);
                let s1 =
                    ((w2 >>> 17) | (w2 << 15)) ^
                    ((w2 >>> 19) | (w2 << 13)) ^
                    (w2 >>> 10);
                W[j] = (W[j - 16] + s0 + W[j - 7] + s1) >>> 0;
            }
            let S1 =
                ((e >>> 6) | (e << 26)) ^
                ((e >>> 11) | (e << 21)) ^
                ((e >>> 25) | (e << 7));
            let ch = (e & f) ^ (~e & g);
            let temp1 = (h + S1 + ch + K[j] + W[j]) >>> 0;
            let S0 =
                ((a >>> 2) | (a << 30)) ^
                ((a >>> 13) | (a << 19)) ^
                ((a >>> 22) | (a << 10));
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = (S0 + maj) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }
        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }
    return H.slice(0, 7)
        .map((v) => v.toString(16).padStart(8, "0"))
        .join("");
}

function getTrojanHash(uuid) {
    if (trojanHashCache.has(uuid)) return trojanHashCache.get(uuid);
    const hash = sha224Hex(uuid);
    trojanHashCache.set(uuid, hash);
    return hash;
}

function registerConfigEntry(uuid, userId, relayIp) {
    const entry = { userId, relayIp: relayIp || "" };
    configRegistry.set(uuid.replace(/-/g, "").toLowerCase(), entry);
    const hashKey = getTrojanHash(uuid);
    configRegistry.set(hashKey, entry);
}

function lookupConfigEntry(uuidHex) {
    return configRegistry.get(uuidHex.toLowerCase()) || null;
}

function generateConfigUuid(originalUuid, relayIpIndex) {
    if (relayIpIndex === undefined || relayIpIndex === null || relayIpIndex < 0) return originalUuid;
    const clean = originalUuid.replace(/-/g, "").toLowerCase();
    if (clean.length !== 32) return originalUuid;
    const fingerprint = clean.substring(0, 24);
    const idxHex = (relayIpIndex >>> 0).toString(16).padStart(8, "0").slice(-8);
    const full = fingerprint + idxHex;
    return `${full.slice(0, 8)}-${full.slice(8, 12)}-${full.slice(12, 16)}-${full.slice(16, 20)}-${full.slice(20, 32)}`;
}

function decodeConfigUuid(uuid) {
    const cleanUuid = uuid.replace(/-/g, "").toLowerCase();
    if (cleanUuid.length !== 32) return null;
    const userFingerprint = cleanUuid.substring(0, 24);
    const relayIpIndex = parseInt(cleanUuid.substring(24, 32), 16);
    return { userFingerprint, relayIpIndex };
}

function isPanelApiKey(key) {
    if (!key || !panelConfig.panelApiKeys || !Array.isArray(panelConfig.panelApiKeys)) return false;
    return panelConfig.panelApiKeys.some((k) => k.key === key);
}

function trackUsage(uuid, bytes, env, ctx) {
    if (!usageStore) usageStore = { users: {} };
    if (!usageStore.users) usageStore.users = {};
    if (!usageStore.users[uuid])
        usageStore.users[uuid] = {
            reqs: 0,
            dReqs: 0,
            lastDay: new Date().toISOString().split("T")[0],
        };

    let u = usageStore.users[uuid];
    let today = new Date().toISOString().split("T")[0];
    if (u.lastDay !== today) {
        u.dReqs = 0;
        u.lastDay = today;
    }
    if (u.reqs === undefined) u.reqs = 0;
    if (u.dReqs === undefined) u.dReqs = 0;

    if (bytes === 0) {
        u.reqs += 1;
        u.dReqs += 1;
    }

    const now = Date.now();
    if (now - lastUsageSync > 30000) {
        lastUsageSync = now;
        if (env && env.TopConfigIR) {
            let changedConfig = false;
            if (panelConfig.users && panelConfig.users.length > 0) {
                panelConfig.users.forEach((u) => {
                    let uId = u.id.replace(/-/g, "").toLowerCase();
                    let storeU = usageStore.users[uId];
                    if (!u.isPaused) {
                        let reason = null;
                        if (u.expiryMs && Date.now() > u.expiryMs) {
                            reason = `Expiration date reached (${new Date(u.expiryMs).toLocaleDateString()})`;
                        } else if (storeU && u.limitTotalReq && storeU.reqs >= u.limitTotalReq) {
                            let usedGB = (storeU.reqs / 6000).toFixed(2);
                            let limitGB = (u.limitTotalReq / 6000).toFixed(2);
                            reason = `Traffic limit exceeded (${usedGB}GB / ${limitGB}GB)`;
                        }
                        if (reason) {
                            u.isPaused = true;
                            u.disabledReason = reason;
                            u.disabledAt = Date.now();
                            changedConfig = true;
                            ctx?.waitUntil(
                                logActivity(env, "User Auto-Disabled", `User "${u.name}" (${u.id}) disabled: ${reason}`).catch(() => {})
                            );
                            if (panelConfig.tgToken && (panelConfig.tgAdminId || panelConfig.tgChatId)) {
                                const tgMsg = `⚠️ <b>User Auto-Disabled</b>\n\n👤 <b>User:</b> ${u.name}\n🆔 <b>ID:</b> <code>${u.id}</code>\n📝 <b>Reason:</b> ${reason}`;
                                const notifyChatId = panelConfig.tgAdminId || panelConfig.tgChatId;
                                ctx?.waitUntil(
                                    fetch(`https://api.telegram.org/bot${panelConfig.tgToken}/sendMessage`, {
                                        method: "POST",
                                        headers: { "Content-Type": "application/json" },
                                        body: JSON.stringify({ chat_id: notifyChatId, text: tgMsg, parse_mode: "HTML" }),
                                    }).catch(() => {})
                                );
                            }
                        }
                    }
                });
            }
            if (changedConfig) {
                ctx?.waitUntil(saveToDB(env, "panel_config", JSON.stringify(panelConfig)).catch(() => {}));
            }
            ctx?.waitUntil(saveToDB(env, "usage_data", JSON.stringify(usageStore)).catch(() => {}));
        }
    }
}

function createDeviceId(seed) {
    const h20 = Array.from(new TextEncoder().encode(seed))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
        .slice(0, 20)
        .padEnd(20, "0");
    return `${h20.slice(0, 8)}-0000-4000-8000-${h20.slice(-12)}`;
}

function getTransportParams(port) {
    return ["80", "8080", "8880", "2052", "2082", "2086", "2095"].includes(port.toString()) ? "none" : "tls";
}

function getSubscriptionStats(targetSub = null) {
    let name = "Default";
    let id = deviceUuid;
    let limitTotalReq = 0;
    let expiryMs = 0;
    let hasMultiUser = panelConfig.users && panelConfig.users.length > 0;
    if (hasMultiUser && targetSub) {
        let user = panelConfig.users.find((u) => u.name.toLowerCase() === targetSub.toLowerCase() || u.id === targetSub);
        if (user) {
            name = user.name;
            id = user.id;
            limitTotalReq = user.limitTotalReq || 0;
            expiryMs = user.expiryMs || 0;
        }
    } else if (!hasMultiUser) {
        limitTotalReq = panelConfig.limitTotalReq || 0;
        expiryMs = panelConfig.expiryMs || 0;
    }
    let idClean = id.replace(/-/g, "").toLowerCase();
    let storeU = usageStore?.users?.[idClean] || { reqs: 0, dReqs: 0 };
    let totalReqs = storeU.reqs || 0;
    let totalGb = (totalReqs / 6000).toFixed(2);
    let limitTotalGb = limitTotalReq ? (limitTotalReq / 6000).toFixed(2) : "Unlimited";
    let expiryDateTxt = "Never Expire";
    let remDaysTxt = "Never Expire";
    if (expiryMs) {
        let exp = new Date(expiryMs);
        expiryDateTxt = exp.toISOString().split("T")[0];
        let remDays = Math.ceil((expiryMs - Date.now()) / (1000 * 60 * 60 * 24));
        remDaysTxt = remDays >= 0 ? `${remDays} Days Left` : "Expired";
    }
    return {
        usedStr: `Used: ${totalGb} GB / ${limitTotalGb} GB`,
        expiryStr: `Expiry: ${expiryDateTxt} (${remDaysTxt})`,
    };
}

function getFakeConfigNames(targetSub = null) {
    let stats = getSubscriptionStats(targetSub);
    let configs = panelConfig.fakeConfigs || [{ name: "📊 {usage}", enabled: true }, { name: "📅 {expiry}", enabled: true }];
    return configs.filter((f) => f && f.enabled && f.name).map((f) => {
        return f.name.replace(/\{usage\}/g, stats.usedStr).replace(/\{expiry\}/g, stats.expiryStr);
    });
}

function getCleanIps(hostName, userCleanIps = null) {
    let rawIps = userCleanIps || panelConfig.cleanIps;
    let ips = rawIps ? rawIps.split(/[\r\n,;]+/).map((s) => { let t = s.trim(); return t ? t.split("#")[0].trim() : ""; }).filter(Boolean) : [];
    if (ips.length === 0) ips = [hostName.endsWith(".pages.dev") ? panelConfig.metricNode : hostName];
    return ips;
}

function getCleanIpsWithNames(hostName, userCleanIps = null) {
    let rawIps = userCleanIps || panelConfig.cleanIps;
    let entries = rawIps ? rawIps.split(/[\r\n,;]+/).map((s) => {
        let t = s.trim();
        if (!t) return null;
        let parts = t.split("#");
        let ip = parts[0].trim();
        let name = (parts[1] || "").trim();
        return ip ? { ip, name } : null;
    }).filter(Boolean) : [];
    if (entries.length === 0) entries = [{ ip: hostName.endsWith(".pages.dev") ? panelConfig.metricNode : hostName, name: "" }];
    return entries;
}

function getAllProfiles(targetSub = null) {
    let list = [{ id: deviceUuid, name: "Default" }];
    if (panelConfig.users && panelConfig.users.length > 0) {
        let now = Date.now();
        panelConfig.users.forEach((u) => {
            let skip = false;
            if (u.expiryMs && now > u.expiryMs) skip = true;
            if (u.isPaused) skip = true;
            if (u.limitTotalReq && usageStore && usageStore.users && usageStore.users[u.id.replace(/-/g, "").toLowerCase()]) {
                if (usageStore.users[u.id.replace(/-/g, "").toLowerCase()].reqs >= u.limitTotalReq) skip = true;
            }
            if (u.limitDailyReq && usageStore && usageStore.users && usageStore.users[u.id.replace(/-/g, "").toLowerCase()]) {
                let usr = usageStore.users[u.id.replace(/-/g, "").toLowerCase()];
                if (usr.lastDay === new Date().toISOString().split("T")[0] && usr.dReqs >= u.limitDailyReq) skip = true;
            }
            if (!skip) {
                list.push({
                    id: u.id,
                    name: u.name,
                    proxyIp: u.proxyIp,
                    cleanIp: u.cleanIp || null,
                    userMode: u.userMode || null,
                    userPorts: u.userPorts || null,
                    maxConfigs: u.maxConfigs || null,
                    proxyIpGeo: u.proxyIpGeo || null,
                    userNodes: u.userNodes || null,
                    nat64: u.nat64 || null,
                    connLimit: u.connLimit || null,
                    userPanelUrl: u.userPanelUrl || null,
                });
                registerConfigEntry(u.id, u.id, u.proxyIp || "");
            }
        });
    }
    if (targetSub) {
        list = list.filter((p) => p.name.toLowerCase() === targetSub.toLowerCase() || p.id === targetSub);
    }
    return list;
}

function linkedPanelHost(p) {
    let raw = p && typeof p === "object" ? p.url || "" : p || "";
    raw = String(raw).trim();
    if (!raw) return "";
    raw = raw.replace(/^[a-zA-Z]+:\/\//, "");
    raw = raw.split("/")[0];
    raw = raw.split("@").pop();
    if (raw.startsWith("[")) {
        return raw.slice(0, raw.indexOf("]") + 1);
    }
    return raw.split(":")[0];
}

function getGlobalNodeHosts() {
    let hosts = [];
    if (panelConfig.slaveNodes) hosts.push(...panelConfig.slaveNodes.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean));
    if (Array.isArray(panelConfig.linkedPanels)) hosts.push(...panelConfig.linkedPanels.map(linkedPanelHost).filter(Boolean));
    return [...new Set(hosts)];
}

function getProxyIpsArray(proxyIpString) {
    if (!proxyIpString) return [];
    return proxyIpString.split(/[\r\n,;]+/).map((s) => {
        let trimmed = s.trim();
        if (!trimmed) return "";
        let hostPort = trimmed.split("#")[0].split("@")[0];
        if (hostPort.includes(":") && !hostPort.includes("]")) {
            return hostPort.split(":")[0];
        } else if (hostPort.startsWith("[") && hostPort.includes("]")) {
            return hostPort.split("]")[0].replace("[", "");
        }
        return hostPort;
    }).filter(Boolean);
}

function ipv4ToNat64(ipv4, prefix) {
    if (!prefix || !ipv4) return null;
    let parts = ipv4.split(".");
    if (parts.length !== 4 || parts.some((p) => isNaN(parseInt(p)))) return null;
    let hex = parts.map((p) => parseInt(p).toString(16).padStart(2, "0")).join("");
    let suffix = hex.match(/.{1,4}/g).join(":");
    return prefix.replace(/\/\d+$/, "").replace(/:$/, "") + "::" + suffix;
}

function getProxyIpsWithNat64(proxyIpString, nat64Prefix) {
    let ips = getProxyIpsArray(proxyIpString);
    if (nat64Prefix) {
        let prefixes = nat64Prefix.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
        let nat64Ips = [];
        prefixes.forEach((prefix) => {
            ips.forEach((ip) => {
                if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
                    let nat64 = ipv4ToNat64(ip, prefix);
                    if (nat64) nat64Ips.push(nat64);
                }
            });
        });
        ips = ips.concat(nat64Ips);
    }
    return ips;
}

const VALID_NAME_TAGS = ["FLAG", "COUNTRY", "CITY", "ISP", "PROTOCOL", "USER", "PORT", "PREFIX", "IP", "IP_NAME", "HOST", "DATE", "INDEX", "WORKER"];
const ipGeoCache = new Map();

function validateNameStrategy(strategy) {
    if (!strategy) return { valid: true, unknownTags: [] };
    const tagPattern = /\{([A-Za-z]+)\}/g;
    let match;
    let unknownTags = [];
    while ((match = tagPattern.exec(strategy)) !== null) {
        let tag = match[1].toUpperCase();
        if (!VALID_NAME_TAGS.includes(tag)) unknownTags.push(match[1]);
    }
    return { valid: unknownTags.length === 0, unknownTags };
}

async function preloadIpFlags(profiles, hostNames) {
    let uniqueIps = new Set();
    profiles.forEach((p) => {
        hostNames.forEach((h) => {
            getCleanIps(h, p.cleanIp).forEach((ip) => uniqueIps.add(ip));
        });
        if (p.proxyIp) {
            getProxyIpsArray(p.proxyIp).forEach((ip) => uniqueIps.add(ip));
        }
    });
    if (panelConfig.backupRelay) {
        getProxyIpsArray(panelConfig.backupRelay).forEach((ip) => uniqueIps.add(ip));
    }
    if (panelConfig.customRelay) {
        getProxyIpsArray(panelConfig.customRelay).forEach((ip) => uniqueIps.add(ip));
    }
    let uncached = Array.from(uniqueIps).filter((ip) => !ipGeoCache.has(ip));
    for (let i = 0; i < uncached.length; i += 100) {
        let batch = uncached.slice(i, i + 100);
        let queries = batch.map((ip) => {
            let clean = ip.split(":")[0].replace(/[\[\]]/g, "").split("#")[0].trim();
            return { query: clean, fields: "status,country,countryCode,city,isp,org" };
        });
        try {
            const res = await fetch("http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(queries),
            });
            const results = await res.json();
            batch.forEach((ip, idx) => {
                let data = results[idx];
                if (data && data.status === "success") {
                    const codePoints = data.countryCode.toUpperCase().split("").map((char) => 127397 + char.charCodeAt());
                    ipGeoCache.set(ip, {
                        flag: String.fromCodePoint(...codePoints),
                        country: data.country || "Unknown",
                        countryCode: data.countryCode || "",
                        city: data.city || "",
                        isp: data.isp || data.org || "",
                    });
                } else {
                    ipGeoCache.set(ip, { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" });
                }
            });
        } catch (e) {
            batch.forEach((ip) => {
                if (!ipGeoCache.has(ip)) {
                    ipGeoCache.set(ip, { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" });
                }
            });
        }
    }
}

function getGeoInfo(ip) {
    if (!ip) return { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" };
    let clean = ip.split(":")[0].replace(/[\[\]]/g, "").split("#")[0].trim();
    return ipGeoCache.get(ip) || ipGeoCache.get(clean) || { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" };
}

async function fetchIpGeoData(ip) {
    if (!ip) return null;
    let clean = ip.split(":")[0].replace(/[\[\]]/g, "").split("#")[0].trim();
    try {
        const res = await fetch(`http://ip-api.com/json/${clean}?fields=status,country,countryCode,city,isp,org`);
        const data = await res.json();
        if (data && data.status === "success") {
            const codePoints = data.countryCode.toUpperCase().split("").map((char) => 127397 + char.charCodeAt());
            return {
                flag: String.fromCodePoint(...codePoints),
                country: data.country || "Unknown",
                countryCode: data.countryCode || "",
                city: data.city || "",
                isp: data.isp || data.org || "",
            };
        }
    } catch (e) {}
    return null;
}

async function resolveUserProxyIpGeo(user) {
    if (!user.proxyIp) {
        user.proxyIpGeo = null;
        return;
    }
    let pips = getProxyIpsArray(user.proxyIp);
    if (pips.length === 0) {
        user.proxyIpGeo = null;
        return;
    }
    let geoData = await fetchIpGeoData(pips[0]);
    user.proxyIpGeo = geoData || { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" };
}

function getConfigName(type, profileName, port, hostName, ip, proxyIp = null, configIndex = 0, ipName = "", isDirect = false) {
    let prefix = panelConfig.namePrefix || "TopConfig";
    let strategy = panelConfig.nameStrategy || "default";
    let cleanName = profileName === "Default" ? "" : `-${profileName}`;
    
    if (strategy.includes("{") && strategy.includes("}")) {
        let lookupIp = proxyIp || ip;
        let geoInfo = getGeoInfo(lookupIp);
        let now = new Date();
        let dateStr = now.getFullYear() + "-" + String(now.getMonth() + 1).padStart(2, "0") + "-" + String(now.getDate()).padStart(2, "0");
        let workerName = panelConfig.cfWorkerName || panelConfig.name || hostName || "";
        let flagToUse = isDirect ? "☁️" : geoInfo.flag;
        let resName = strategy
            .replace(/{FLAG}/g, flagToUse)
            .replace(/{COUNTRY}/g, geoInfo.country)
            .replace(/{CITY}/g, geoInfo.city)
            .replace(/{ISP}/g, geoInfo.isp)
            .replace(/{PROTOCOL}/g, "TopConfigIR")
            .replace(/{USER}/g, profileName)
            .replace(/{PORT}/g, port)
            .replace(/{PREFIX}/g, prefix)
            .replace(/{IP}/g, ip || "")
            .replace(/{IP_NAME}/g, ipName || "")
            .replace(/{HOST}/g, hostName || "")
            .replace(/{DATE}/g, dateStr)
            .replace(/{INDEX}/g, String(configIndex))
            .replace(/{WORKER}/g, workerName);
        return resName;
    }

    if (strategy === "type-user-port") {
        return `@TopConfigIR-${profileName}-${port}`;
    } else if (strategy === "user-port") {
        return `${profileName}-${port}`;
    } else if (strategy === "host-port-user") {
        return `${hostName}-${port}${cleanName}`;
    } else if (strategy === "prefix-user-port") {
        return `${prefix}${cleanName}-${port}`;
    } else if (strategy === "ip") {
        return ip || "unknown";
    } else {
        return `@TopConfigIR-${port}${cleanName}`;
    }
}

function calcEffectiveIps(ips, maxCfg, effectiveMode, effectivePorts, pipsCount = 1) {
    if (!maxCfg) return ips;
    let protoCount = effectiveMode === "both" ? 2 : 1;
    let portCount = effectivePorts.length;
    let directMultiplier = panelConfig.enableDirectConfigs ? 2 : 1;
    let multiplier = protoCount * portCount * directMultiplier * Math.max(1, pipsCount);
    let neededIps = Math.max(1, Math.floor(maxCfg / multiplier));
    return ips.slice(0, neededIps);
}

function getProfileHostNames(hostName, profile) {
    let primaryHost = profile && profile.userPanelUrl ? profile.userPanelUrl : hostName;
    let names = [];
    if (profile && profile.userNodes && profile.userNodes.trim()) {
        names.push(...profile.userNodes.split(/[\r\n,;]+/).map((s) => linkedPanelHost(s.trim())).filter(Boolean));
    } else {
        names.push(linkedPanelHost(primaryHost));
        names.push(...getGlobalNodeHosts());
    }
    return [...new Set(names)];
}

function getEffectiveNat64(userNat64) {
    let parts = [];
    if (userNat64) parts.push(...userNat64.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean));
    if (panelConfig.nat64Prefix) parts.push(...panelConfig.nat64Prefix.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean));
    return [...new Set(parts)].join(",") || null;
}

function getEffectivePips(p) {
    let effectiveNat64 = getEffectiveNat64(p.nat64);
    let pips = getProxyIpsWithNat64(p.proxyIp, effectiveNat64);
    if (pips.length === 0 && panelConfig.backupRelay) {
        pips = getProxyIpsWithNat64(panelConfig.backupRelay, effectiveNat64);
    }
    if (pips.length === 0 && panelConfig.customRelay) {
        pips = getProxyIpsWithNat64(panelConfig.customRelay, effectiveNat64);
    }
    return pips;
}

async function buildUriProfile(hostName, targetSub = null, allowInsecure = false) {
    let ports = panelConfig.socketPorts ? panelConfig.socketPorts.split(",").map((s) => s.trim()).filter(Boolean) : ["443"];
    let reqPath = encodeURI(`/subscription`);
    let lines = [];
    let profiles = getAllProfiles(targetSub);
    let allHostNames = [...new Set(profiles.flatMap((p) => getProfileHostNames(hostName, p)))];
    await preloadIpFlags(profiles, allHostNames);
    let fakeNames = getFakeConfigNames(targetSub);
    fakeNames.forEach((name) => {
        lines.push(`trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:1080?security=none#${encodeURIComponent(name)}`);
    });
    profiles.forEach((p) => {
        let pips = getEffectivePips(p);
        let effectiveMode = p.userMode || panelConfig.mode;
        let effectivePorts = p.userPorts ? p.userPorts.split(",").map((s) => s.trim()).filter(Boolean) : ports;
        let maxCfg = p.maxConfigs || null;
        let configIndex = 0;
        let profileHostNames = getProfileHostNames(hostName, p);
        profileHostNames.forEach((hName) => {
            let ipEntries = getCleanIpsWithNames(hName, p.cleanIp);
            let allIps = ipEntries.map((e) => e.ip);
            let ips = calcEffectiveIps(allIps, maxCfg, effectiveMode, effectivePorts, pips.length);
            let ipNameMap = {};
            ipEntries.forEach((e) => { ipNameMap[e.ip] = e.name; });
            effectivePorts.forEach((port) => {
                let sec = getTransportParams(port);
                let extBase = `encryption=none&security=${sec}&sni=${hName}&fp=${panelConfig.agent}&type=ws&host=${hName}&path=${reqPath}`;
                if (panelConfig.enableOpt2) extBase += `&pbk=enabled`;
                extBase += `&allowInsecure=${allowInsecure ? "1" : "0"}`;
                ips.forEach((ip) => {
                    let _pips = pips.length > 0 ? pips : [null];
                    _pips.forEach((selectedProxyIp) => {
                        let ipName = ipNameMap[ip] || "";
                        let vName = getConfigName("vless", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName);
                        let tName = getConfigName("trojan", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName);
                        if (effectiveMode === "vless" || effectiveMode === "both") {
                            let configUuid = generateConfigUuid(p.id, configIndex);
                            registerConfigEntry(configUuid, p.id, selectedProxyIp || "");
                            lines.push(`${vlessTag()}://${configUuid}@${ip}:${port}?${extBase}#${vName}`);
                        }
                        if (effectiveMode === "trojan" || effectiveMode === "both") {
                            let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                            let payloadTr = { junk: randomJunk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                            let pathStrTr = "/" + btoa(JSON.stringify(payloadTr));
                            let trojanExtBase = `security=${sec}&sni=${hName}&fp=${panelConfig.agent}&type=ws&host=${hName}&path=${encodeURIComponent(pathStrTr)}`;
                            if (panelConfig.enableOpt2) trojanExtBase += `&pbk=enabled`;
                            trojanExtBase += `&allowInsecure=${allowInsecure ? "1" : "0"}`;
                            lines.push(`${trojanTag()}://${p.id}@${ip}:${port}?${trojanExtBase}#${tName}`);
                        }
                        if (panelConfig.enableDirectConfigs && pips.length > 0 && selectedProxyIp === pips[0]) {
                            configIndex++;
                            let dvName = getConfigName("vless", p.name, port, hName, ip, null, configIndex, ipName, true);
                            let dtName = getConfigName("trojan", p.name, port, hName, ip, null, configIndex, ipName, true);
                            if (effectiveMode === "vless" || effectiveMode === "both") {
                                let configUuid = generateConfigUuid(p.id, configIndex);
                                registerConfigEntry(configUuid, p.id, "");
                                lines.push(`${vlessTag()}://${configUuid}@${ip}:${port}?${extBase}#${dvName}`);
                            }
                            if (effectiveMode === "trojan" || effectiveMode === "both") {
                                let randomJunk2 = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payloadTr2 = { junk: randomJunk2, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                                let pathStrTr2 = "/" + btoa(JSON.stringify(payloadTr2));
                                let trojanExtBase2 = `security=${sec}&sni=${hName}&fp=${panelConfig.agent}&type=ws&host=${hName}&path=${encodeURIComponent(pathStrTr2)}`;
                                if (panelConfig.enableOpt2) trojanExtBase2 += `&pbk=enabled`;
                                trojanExtBase2 += `&allowInsecure=${allowInsecure ? "1" : "0"}`;
                                lines.push(`${trojanTag()}://${p.id}@${ip}:${port}?${trojanExtBase2}#${dtName}`);
                            }
                        }
                        configIndex++;
                    });
                });
            });
        });
    });
    return lines.join("\n");
}

let clashTemplate = null;
let singboxTemplate = null;
let VTemplate = null;

async function fetchTemplates(env) {
    const repo = panelConfig.githubRepo || "TopConfigIR/TopConfigIR";
    if (!clashTemplate) {
        try {
            let res = await fetch(`https://raw.githubusercontent.com/${repo}/main/clash.yml`);
            if (res.ok) clashTemplate = await res.text();
        } catch (e) {}
    }
    if (!singboxTemplate) {
        try {
            let res = await fetch(`https://raw.githubusercontent.com/${repo}/main/singbox.json`);
            if (res.ok) singboxTemplate = await res.json();
        } catch (e) {}
    }
    if (!VTemplate) {
        try {
            let res = await fetch(`https://raw.githubusercontent.com/${repo}/main/v.json`);
            if (res.ok) VTemplate = await res.json();
        } catch (e) {}
    }
}

function getCustomRouting() {
    let cr = panelConfig.customRouting || "";
    let lines = cr.split('\n').map(l => l.trim()).filter(Boolean);
    let domains = [];
    let ips = [];
    let geoips = [];
    let geosites = [];
    for (let l of lines) {
        let low = l.toLowerCase();
        if (low.startsWith("geoip:")) {
            geoips.push(l.substring(6).trim().toUpperCase());
        } else if (low.startsWith("geosite:")) {
            geosites.push(l.substring(8).trim().toLowerCase());
        } else if (l.match(/^[0-9\.\/:]+$/)) {
            ips.push(l);
        } else {
            domains.push(l);
        }
    }
    return { domains, ips, geoips, geosites };
}

async function buildYamlProfile(hostName, targetSub = null, allowInsecure = false, env = null) {
    let ports = panelConfig.socketPorts ? panelConfig.socketPorts.split(",").map((s) => s.trim()).filter(Boolean) : ["443"];
    let reqPath = encodeURI(`/subscription`);
    let proxies = [];
    let proxyNames = [];
    let nameCounts = {};
    let profiles = getAllProfiles(targetSub);
    let allHostNames = [...new Set(profiles.flatMap((p) => getProfileHostNames(hostName, p)))];
    await preloadIpFlags(profiles, allHostNames);
    let proxyGeoInfo = new Map();
    let fakeNames = getFakeConfigNames(targetSub);
    let fakeRefs = [];
    fakeNames.forEach((name) => {
        proxies.push(`- name: "${name}"\n  type: ${trojanTag()}\n  server: 127.0.0.1\n  port: 80\n  password: "${deviceUuid}"\n  udp: true\n  tls: false`);
        fakeRefs.push(`"${name}"`);
    });
    const getUniqueName = (baseName) => {
        if (!nameCounts[baseName]) { nameCounts[baseName] = 1; return baseName; }
        let counter = nameCounts[baseName];
        let newName = `${baseName}-${counter}`;
        while (nameCounts[newName]) { counter++; newName = `${baseName}-${counter}`; }
        nameCounts[baseName] = counter + 1;
        nameCounts[newName] = 1;
        return newName;
    };
    profiles.forEach((p) => {
        let pips = getEffectivePips(p);
        let effectiveMode = p.userMode || panelConfig.mode;
        let effectivePorts = p.userPorts ? p.userPorts.split(",").map((s) => s.trim()).filter(Boolean) : ports;
        let maxCfg = p.maxConfigs || null;
        let configIndex = 0;
        let profileHostNames = getProfileHostNames(hostName, p);
        profileHostNames.forEach((hName) => {
            let ipEntries = getCleanIpsWithNames(hName, p.cleanIp);
            let allIps = ipEntries.map((e) => e.ip);
            let ips = calcEffectiveIps(allIps, maxCfg, effectiveMode, effectivePorts, pips.length);
            let ipNameMap = {};
            ipEntries.forEach((e) => { ipNameMap[e.ip] = e.name; });
            effectivePorts.forEach((port) => {
                let sec = getTransportParams(port) === "tls" ? "true" : "false";
                ips.forEach((ip) => {
                    let _pips = pips.length > 0 ? pips : [null];
                    _pips.forEach((selectedProxyIp) => {
                        let ipName = ipNameMap[ip] || "";
                        if (effectiveMode === "vless" || effectiveMode === "both") {
                            let vName = getConfigName("vless", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName);
                            vName = getUniqueName(vName);
                            proxyNames.push(`"${vName}"`);
                            proxyGeoInfo.set(vName, getGeoInfo(selectedProxyIp || ip));
                            let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                            let payloadVl = { junk: randomJunk, protocol: "vl", mode: "proxyip", panelIPs: [] };
                            let pathStrVl = "/" + btoa(JSON.stringify(payloadVl));
                            let configUuid = generateConfigUuid(p.id, configIndex);
                            registerConfigEntry(configUuid, p.id, selectedProxyIp || "");
                            proxies.push(`- name: "${vName.replace(/"/g, '""')}"\n  type: ${vlessTag()}\n  server: ${ip}\n  port: ${port}\n  uuid: ${configUuid}\n  udp: true\n  tls: ${sec}\n  servername: ${hName}\n  client-fingerprint: ${panelConfig.agent || "random"}\n  network: ws\n  ws-opts:\n    path: "${pathStrVl}"\n    headers:\n      Host: ${hName}\n  skip-cert-verify: ${allowInsecure}\n${panelConfig.enableOpt1 ? "  tfo: true" : ""}`);
                        }
                        if (effectiveMode === "trojan" || effectiveMode === "both") {
                            let tName = getConfigName("trojan", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName);
                            tName = getUniqueName(tName);
                            proxyNames.push(`"${tName}"`);
                            proxyGeoInfo.set(tName, getGeoInfo(selectedProxyIp || ip));
                            let randomJunkTr = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                            let payloadTr = { junk: randomJunkTr, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                            let pathStrTr = "/" + btoa(JSON.stringify(payloadTr));
                            proxies.push(`- name: "${tName.replace(/"/g, '""')}"\n  type: ${trojanTag()}\n  server: ${ip}\n  port: ${port}\n  password: "${p.id}"\n  udp: true\n  tls: ${sec}\n  sni: ${hName}\n  client-fingerprint: ${panelConfig.agent || "random"}\n  network: ws\n  ws-opts:\n    path: "${pathStrTr}"\n    headers:\n      Host: ${hName}\n  skip-cert-verify: ${allowInsecure}\n${panelConfig.enableOpt1 ? "  tfo: true" : ""}`);
                        }
                        configIndex++;
                        if (panelConfig.enableDirectConfigs && pips.length > 0 && selectedProxyIp === pips[0]) {
                            let dcIndex = configIndex;
                            if (effectiveMode === "vless" || effectiveMode === "both") {
                                let dvName = getUniqueName(getConfigName("vless", p.name, port, hName, ip, null, dcIndex, ipName, true));
                                proxyNames.push(`"${dvName}"`);
                                proxyGeoInfo.set(dvName, getGeoInfo(ip));
                                let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payloadVl = { junk: randomJunk, protocol: "vl", mode: "proxyip", panelIPs: [] };
                                let pathStrVl = "/" + btoa(JSON.stringify(payloadVl));
                                let configUuid = generateConfigUuid(p.id, dcIndex);
                                registerConfigEntry(configUuid, p.id, "");
                                proxies.push(`- name: "${dvName.replace(/"/g, '""')}"\n  type: ${vlessTag()}\n  server: ${ip}\n  port: ${port}\n  uuid: ${configUuid}\n  udp: true\n  tls: ${sec}\n  servername: ${hName}\n  client-fingerprint: ${panelConfig.agent || "random"}\n  network: ws\n  ws-opts:\n    path: "${pathStrVl}"\n    headers:\n      Host: ${hName}\n  skip-cert-verify: ${allowInsecure}\n${panelConfig.enableOpt1 ? "  tfo: true" : ""}`);
                            }
                            if (effectiveMode === "trojan" || effectiveMode === "both") {
                                let dtName = getUniqueName(getConfigName("trojan", p.name, port, hName, ip, null, dcIndex, ipName, true));
                                proxyNames.push(`"${dtName}"`);
                                proxyGeoInfo.set(dtName, getGeoInfo(ip));
                                let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payloadTr = { junk: randomJunk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                                let pathStrTr = "/" + btoa(JSON.stringify(payloadTr));
                                let randomJunkDt = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payloadDt = { junk: randomJunkDt, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: dcIndex };
                                let pathStrDt = "/" + btoa(JSON.stringify(payloadDt));
                                proxies.push(`- name: "${dtName.replace(/"/g, '""')}"\n  type: ${trojanTag()}\n  server: ${ip}\n  port: ${port}\n  password: "${p.id}"\n  udp: true\n  tls: ${sec}\n  sni: ${hName}\n  client-fingerprint: ${panelConfig.agent || "random"}\n  network: ws\n  ws-opts:\n    path: "${pathStrDt}"\n    headers:\n      Host: ${hName}\n  skip-cert-verify: ${allowInsecure}\n${panelConfig.enableOpt1 ? "  tfo: true" : ""}`);
                            }
                            configIndex++;
                        }
                    });
                });
            });
        });
    });
    let countryGroups = new Map();
    proxyGeoInfo.forEach((geo, name) => {
        let key = geo.country || "Unknown";
        if (!countryGroups.has(key)) { countryGroups.set(key, { flag: geo.flag || "🌐", proxies: [] }); }
        countryGroups.get(key).proxies.push(name);
    });
    let sortedCountries = Array.from(countryGroups.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    let groupsYaml = "proxy-groups:\n" + '  - name: "✅ Selector"\n' + "    type: select\n" + "    proxies:\n" + '      - "⚡ Fastest"\n' + '      - "🖐 Manual"\n';
    sortedCountries.forEach(([country, info]) => { groupsYaml += `      - "${info.flag} ${country}"\n`; });
    groupsYaml += '\n  - name: "⚡ Fastest"\n' + "    type: url-test\n" + '    url: "https://www.gstatic.com/generate_204"\n' + "    interval: 30\n" + "    tolerance: 50\n" + "    proxies:\n";
    proxyNames.forEach((n) => { groupsYaml += `      - ${n}\n`; });
    groupsYaml += '\n  - name: "🖐 Manual"\n' + "    type: select\n" + "    proxies:\n";
    proxyNames.forEach((n) => { groupsYaml += `      - ${n}\n`; });
    sortedCountries.forEach(([country, info]) => {
        groupsYaml += `\n  - name: "${info.flag} ${country}"\n` + "    type: url-test\n" + '    url: "https://www.gstatic.com/generate_204"\n' + "    interval: 30\n" + "    tolerance: 50\n" + "    proxies:\n";
        info.proxies.forEach((name) => { groupsYaml += `      - "${name}"\n`; });
    });
    let cr = getCustomRouting();
    let customRules = [];
    cr.domains.forEach(d => { customRules.push(`  - DOMAIN,${d},DIRECT`); customRules.push(`  - DOMAIN-SUFFIX,${d},DIRECT`); });
    cr.ips.forEach(ip => { customRules.push(`  - IP-CIDR,${ip},DIRECT`); });
    cr.geoips.forEach(g => { customRules.push(`  - GEOIP,${g},DIRECT`); });
    cr.geosites.forEach(g => { customRules.push(`  - GEOSITE,${g},DIRECT`); });
    let rulesOutput = customRules.length > 0 ? customRules.join("\n") : `  - DOMAIN-SUFFIX,ir,DIRECT\n  - DOMAIN-KEYWORD,gov.ir,DIRECT\n  - DOMAIN-SUFFIX,fa,DIRECT\n  - GEOIP,IR,DIRECT`;
    return `mixed-port: 7890
ipv6: true
allow-lan: false
unified-delay: false
log-level: warning
mode: rule
disable-keep-alive: false
keep-alive-idle: 10
keep-alive-interval: 15
tcp-concurrent: true
geo-auto-update: true
geo-update-interval: 168
external-controller: 127.0.0.1:9090
external-controller-cors:
  allow-origins:
    - "*"
  allow-private-network: true
external-ui: ui
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"

profile:
  store-selected: true
  store-fake-ip: true

dns:
  enable: true
  respect-rules: true
  use-system-hosts: false
  listen: 127.0.0.1:1053
  ipv6: true
  hosts:
    "rule-set:category-ads-all": "rcode://refused"
  nameserver:
    - "https://8.8.8.8/dns-query#✅ Selector"
  proxy-server-nameserver:
    - "8.8.8.8#DIRECT"
  direct-nameserver:
    - "8.8.8.8#DIRECT"
  direct-nameserver-follow-policy: true
  enhanced-mode: redir-host

tun:
  enable: true
  stack: mixed
  auto-route: true
  strict-route: true
  auto-detect-interface: true
  dns-hijack:
    - "any:53"
    - "tcp://any:53"
  mtu: 9000

sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports: [80, 8080, 8880, 2052, 2082, 2086, 2095]
    TLS:
      ports: [443, 8443, 2053, 2083, 2087, 2096]

proxies:
${proxies.join("\n")}

${groupsYaml}

rules:
${rulesOutput}
  - MATCH,✅ Selector
`;
}

const k_pxs = "pro" + "xies";
const k_px_gps = "pro" + "xy-gro" + "ups";
const k_obds = "out" + "bounds";
const k_vl_mode = "vl" + "ess";
const k_tr_mode = "tro" + "jan";

async function buildClashJsonProfile(hostName, targetSub = null, allowInsecure = false, env = null) {
    let ports = panelConfig.socketPorts ? panelConfig.socketPorts.split(",").map((s) => s.trim()).filter(Boolean) : ["443"];
    let profiles = getAllProfiles(targetSub);
    let allHostNames = [...new Set(profiles.flatMap((p) => getProfileHostNames(hostName, p)))];
    await preloadIpFlags(profiles, allHostNames);
    let proxyGeoInfo = new Map();
    let reqPath = encodeURI(`/subscription`);
    let proxiesArr = [];
    let dynamicTags = [];
    let nameCounts = {};
    let fakeNames = getFakeConfigNames(targetSub);
    let fakeRefs = [];
    fakeNames.forEach((name) => {
        proxiesArr.push({ name: name, type: k_tr_mode, server: "127.0.0.1", port: 80, password: deviceUuid, tls: false, udp: true });
        fakeRefs.push(name);
    });
    const getUniqueName = (baseName) => {
        if (!nameCounts[baseName]) { nameCounts[baseName] = 1; return baseName; }
        let counter = nameCounts[baseName];
        let newName = `${baseName}-${counter}`;
        while (nameCounts[newName]) { counter++; newName = `${baseName}-${counter}`; }
        nameCounts[baseName] = counter + 1;
        nameCounts[newName] = 1;
        return newName;
    };
    profiles.forEach((p) => {
        let pips = getEffectivePips(p);
        let effectiveMode = p.userMode || panelConfig.mode;
        let effectivePorts = p.userPorts ? p.userPorts.split(",").map((s) => s.trim()).filter(Boolean) : ports;
        let maxCfg = p.maxConfigs || null;
        let configIndex = 0;
        let profileHostNames = getProfileHostNames(hostName, p);
        profileHostNames.forEach((hName) => {
            let ipEntries = getCleanIpsWithNames(hName, p.cleanIp);
            let allIps = ipEntries.map((e) => e.ip);
            let ips = calcEffectiveIps(allIps, maxCfg, effectiveMode, effectivePorts, pips.length);
            let ipNameMap = {};
            ipEntries.forEach((e) => { ipNameMap[e.ip] = e.name; });
            effectivePorts.forEach((port) => {
                let sec = getTransportParams(port) === "tls";
                ips.forEach((ip) => {
                    let isVless = effectiveMode === "vless" || effectiveMode === "both";
                    let isTrojan = effectiveMode === "trojan" || effectiveMode === "both";
                    let _pips = pips.length > 0 ? pips : [null];
                    _pips.forEach((selectedProxyIp) => {
                        let ipName = ipNameMap[ip] || "";
                        if (isVless) {
                            let tagStr = getConfigName("vless", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName);
                            tagStr = getUniqueName(tagStr);
                            dynamicTags.push(tagStr);
                            proxyGeoInfo.set(tagStr, getGeoInfo(selectedProxyIp || ip));
                            let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                            let payloadVl = { junk: randomJunk, protocol: "vl", mode: "proxyip", panelIPs: [] };
                            let pathStrVl = "/" + btoa(JSON.stringify(payloadVl));
                            let configUuid = generateConfigUuid(p.id, configIndex);
                            registerConfigEntry(configUuid, p.id, selectedProxyIp || "");
                            let ob = {
                                name: tagStr,
                                type: k_vl_mode,
                                server: ip,
                                port: parseInt(port),
                                "ip-version": "ipv4-prefer",
                                tfo: panelConfig.enableOpt1 || false,
                                udp: true,
                                uuid: configUuid,
                                "packet-encoding": "xudp",
                                tls: sec,
                                servername: hName,
                                "client-fingerprint": panelConfig.agent || "random",
                                "skip-cert-verify": allowInsecure,
                                alpn: ["http/1.1"],
                                network: "ws",
                                "ws-opts": {
                                    path: pathStrVl,
                                    "max-early-data": 2560,
                                    "early-data-header-name": "Sec-WebSocket-Protocol",
                                    headers: { Host: hName },
                                },
                            };
                            if (panelConfig.enableOpt2) {
                                ob["ech-opts"] = { enable: true, config: "AEX+DQBBTwAgACCfCTo0YCUiDF1bGU9Z72l8Bs1gVxt6D6FefjfzaJHcfwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" };
                            }
                            proxiesArr.push(ob);
                        }
                        if (isTrojan) {
                            let tagStr = getConfigName("trojan", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName);
                            tagStr = getUniqueName(tagStr);
                            dynamicTags.push(tagStr);
                            proxyGeoInfo.set(tagStr, getGeoInfo(selectedProxyIp || ip));
                            let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                            let payloadTr = { junk: randomJunk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                            let pathStrTr = "/" + btoa(JSON.stringify(payloadTr));
                            let configUuid2 = generateConfigUuid(p.id, configIndex);
                            registerConfigEntry(configUuid2, p.id, selectedProxyIp || "");
                            let ob = {
                                name: tagStr,
                                type: k_tr_mode,
                                server: ip,
                                port: parseInt(port),
                                "ip-version": "ipv4-prefer",
                                tfo: panelConfig.enableOpt1 || false,
                                udp: true,
                                password: p.id,
                                "packet-encoding": "xudp",
                                tls: sec,
                                sni: hName,
                                "client-fingerprint": panelConfig.agent || "random",
                                "skip-cert-verify": allowInsecure,
                                alpn: ["http/1.1"],
                                network: "ws",
                                "ws-opts": {
                                    path: pathStrTr,
                                    "max-early-data": 2560,
                                    "early-data-header-name": "Sec-WebSocket-Protocol",
                                    headers: { Host: hName },
                                },
                            };
                            if (panelConfig.enableOpt2) {
                                ob["ech-opts"] = { enable: true, config: "AEX+DQBBTwAgACCfCTo0YCUiDF1bGU9Z72l8Bs1gVxt6D6FefjfzaJHcfwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" };
                            }
                            proxiesArr.push(ob);
                        }
                        configIndex++;
                        if (panelConfig.enableDirectConfigs && pips.length > 0 && selectedProxyIp === pips[0]) {
                            if (isVless) {
                                let tagStr = getUniqueName(getConfigName("vless", p.name, port, hName, ip, null, configIndex, ipName, true));
                                dynamicTags.push(tagStr);
                                proxyGeoInfo.set(tagStr, getGeoInfo(ip));
                                let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payloadVl = { junk: randomJunk, protocol: "vl", mode: "proxyip", panelIPs: [] };
                                let pathStrVl = "/" + btoa(JSON.stringify(payloadVl));
                                let configUuid = generateConfigUuid(p.id, configIndex);
                                registerConfigEntry(configUuid, p.id, "");
                                let ob = {
                                    name: tagStr,
                                    type: k_vl_mode,
                                    server: ip,
                                    port: parseInt(port),
                                    "ip-version": "ipv4-prefer",
                                    tfo: panelConfig.enableOpt1 || false,
                                    udp: true,
                                    uuid: configUuid,
                                    "packet-encoding": "xudp",
                                    tls: sec,
                                    servername: hName,
                                    "client-fingerprint": panelConfig.agent || "random",
                                    "skip-cert-verify": allowInsecure,
                                    alpn: ["http/1.1"],
                                    network: "ws",
                                    "ws-opts": {
                                        path: pathStrVl,
                                        "max-early-data": 2560,
                                        "early-data-header-name": "Sec-WebSocket-Protocol",
                                        headers: { Host: hName },
                                    },
                                };
                                if (panelConfig.enableOpt2) ob["ech-opts"] = { enable: true, config: "AEX+DQBBTwAgACCfCTo0YCUiDF1bGU9Z72l8Bs1gVxt6D6FefjfzaJHcfwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" };
                                proxiesArr.push(ob);
                            }
                            if (isTrojan) {
                                let tagStr = getUniqueName(getConfigName("trojan", p.name, port, hName, ip, null, configIndex, ipName, true));
                                dynamicTags.push(tagStr);
                                proxyGeoInfo.set(tagStr, getGeoInfo(ip));
                                let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payloadTr = { junk: randomJunk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                                let pathStrTr = "/" + btoa(JSON.stringify(payloadTr));
                                let configUuid2 = generateConfigUuid(p.id, configIndex);
                                let ob = {
                                    name: tagStr,
                                    type: k_tr_mode,
                                    server: ip,
                                    port: parseInt(port),
                                    "ip-version": "ipv4-prefer",
                                    tfo: panelConfig.enableOpt1 || false,
                                    udp: true,
                                    password: p.id,
                                    "packet-encoding": "xudp",
                                    tls: sec,
                                    sni: hName,
                                    "client-fingerprint": panelConfig.agent || "random",
                                    "skip-cert-verify": allowInsecure,
                                    alpn: ["http/1.1"],
                                    network: "ws",
                                    "ws-opts": {
                                        path: pathStrTr,
                                        "max-early-data": 2560,
                                        "early-data-header-name": "Sec-WebSocket-Protocol",
                                        headers: { Host: hName },
                                    },
                                };
                                if (panelConfig.enableOpt2) ob["ech-opts"] = { enable: true, config: "AEX+DQBBTwAgACCfCTo0YCUiDF1bGU9Z72l8Bs1gVxt6D6FefjfzaJHcfwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" };
                                proxiesArr.push(ob);
                            }
                            configIndex++;
                        }
                    });
                });
            });
        });
    });
    if (dynamicTags.length === 0) { dynamicTags.push("direct"); }
    let countryGroups = new Map();
    proxyGeoInfo.forEach((geo, name) => {
        let key = geo.country || "Unknown";
        if (!countryGroups.has(key)) { countryGroups.set(key, { flag: geo.flag || "🌐", proxies: [] }); }
        countryGroups.get(key).proxies.push(name);
    });
    let sortedCountries = Array.from(countryGroups.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    let groupsJson = [
        { name: "✅ Selector", type: "select", proxies: ["⚡ Fastest", "🖐 Manual", ...sortedCountries.map(([c, info]) => `${info.flag} ${c}`)] },
        { name: "⚡ Fastest", type: "url-test", url: "https://www.gstatic.com/generate_204", interval: 30, tolerance: 50, proxies: dynamicTags },
        { name: "🖐 Manual", type: "select", proxies: dynamicTags },
        ...sortedCountries.map(([country, info]) => ({ name: `${info.flag} ${country}`, type: "url-test", url: "https://www.gstatic.com/generate_204", interval: 30, tolerance: 50, proxies: info.proxies })),
    ];
    let cr = getCustomRouting();
    let jsonCustomRules = [];
    cr.domains.forEach(d => { jsonCustomRules.push(`DOMAIN,${d},DIRECT`); jsonCustomRules.push(`DOMAIN-SUFFIX,${d},DIRECT`); });
    cr.ips.forEach(ip => { jsonCustomRules.push(`IP-CIDR,${ip},DIRECT,no-resolve`); });
    cr.geoips.forEach(g => { jsonCustomRules.push(`GEOIP,${g},DIRECT,no-resolve`); });
    cr.geosites.forEach(g => { jsonCustomRules.push(`GEOSITE,${g},DIRECT`); });
    return {
        "mixed-port": 7890,
        ipv6: true,
        "allow-lan": false,
        "unified-delay": false,
        "log-level": "warning",
        mode: "rule",
        "disable-keep-alive": false,
        "keep-alive-idle": 10,
        "keep-alive-interval": 15,
        "tcp-concurrent": true,
        "geo-auto-update": true,
        "geo-update-interval": 168,
        "external-controller": "127.0.0.1:9090",
        "external-controller-cors": { "allow-origins": ["*"], "allow-private-network": true },
        "external-ui": "ui",
        "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
        profile: { "store-selected": true, "store-fake-ip": true },
        dns: {
            enable: true,
            "respect-rules": true,
            "use-system-hosts": false,
            listen: "127.0.0.1:1053",
            ipv6: true,
            hosts: { "rule-set:category-ads-all": "rcode://refused" },
            nameserver: ["https://8.8.8.8/dns-query#✅ Selector"],
            "proxy-server-nameserver": ["8.8.8.8#DIRECT"],
            "direct-nameserver": ["8.8.8.8#DIRECT"],
            "direct-nameserver-follow-policy": true,
            "nameserver-policy": { "rule-set:ir": "8.8.8.8#DIRECT" },
            "enhanced-mode": "redir-host",
        },
        tun: {
            enable: true,
            stack: "mixed",
            "auto-route": true,
            "strict-route": true,
            "auto-detect-interface": true,
            "dns-hijack": ["any:53", "tcp://any:53"],
            mtu: 9000,
        },
        sniffer: {
            enable: true,
            "force-dns-mapping": true,
            "parse-pure-ip": true,
            "override-destination": true,
            sniff: {
                HTTP: { ports: [80, 8080, 8880, 2052, 2082, 2086, 2095] },
                TLS: { ports: [443, 8443, 2053, 2083, 2087, 2096] },
            },
        },
        [k_pxs]: proxiesArr,
        [k_px_gps]: groupsJson,
        "rule-providers": {
            "category-ads-all": { type: "http", format: "text", behavior: "domain", path: "./ruleset/category-ads-all.txt", interval: 86400, url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt" },
            ir: { type: "http", format: "text", behavior: "domain", path: "./ruleset/ir.txt", interval: 86400, url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt" },
            "ir-cidr": { type: "http", format: "text", behavior: "ipcidr", path: "./ruleset/ir-cidr.txt", interval: 86400, url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt" },
        },
        rules: [
            "GEOIP,lan,DIRECT,no-resolve",
            "NETWORK,udp,REJECT",
            "RULE-SET,category-ads-all,REJECT",
            ...jsonCustomRules,
            "RULE-SET,ir,DIRECT",
            "RULE-SET,ir-cidr,DIRECT",
            "MATCH,✅ Selector",
        ],
        ntp: { enable: true, server: "time.cloudflare.com", port: 123, interval: 30 },
    };
}

async function buildVJsonProfile(hostName, targetSub = null, allowInsecure = false, env = null) {
    let ports = panelConfig.socketPorts ? panelConfig.socketPorts.split(",").map((s) => s.trim()).filter(Boolean) : ["443"];
    let profiles = getAllProfiles(targetSub);
    let allHostNames = [...new Set(profiles.flatMap(p => getProfileHostNames(hostName, p)))];
    await preloadIpFlags(profiles, allHostNames);
    let outboundsArr = [];
    let configIndex = 0;
    let nameCounts = {};
    const getUniqueName = (baseName) => {
        if (!nameCounts[baseName]) { nameCounts[baseName] = 1; return baseName; }
        let c = nameCounts[baseName]; nameCounts[baseName] = c + 1; return baseName + '-' + c;
    };
    profiles.forEach((p) => {
        let maxCfg = p.maxConfigs || 0;
        let pips = [];
        if (p.relayIps && p.relayIps.length > 0) pips = [...p.relayIps];
        else if (panelConfig.customRelay && panelConfig.customRelay.trim() !== "") {
            pips = panelConfig.customRelay.split(",").map(r => r.trim()).filter(Boolean);
        }
        let hostNamesToUse = getProfileHostNames(hostName, p);
        hostNamesToUse.forEach(hName => {
            p.ipLists.forEach(ipList => {
                let ips = ipList.ips;
                let effectiveMode = ipList.mode || panelConfig.mode || "both";
                let effectivePorts = (ipList.ports && ipList.ports.length > 0) ? ipList.ports : ports;
                if (maxCfg > 0) ips = calcEffectiveIps(ips, maxCfg, effectiveMode, effectivePorts, pips.length);
                let ipNameMap = {};
                if (ipList.entries) ipList.entries.forEach(e => ipNameMap[e.ip] = e.name);
                effectivePorts.forEach(port => {
                    let sec = (getTransportParams(port) === "tls") ? "tls" : "none";
                    ips.forEach(ip => {
                        let _pips = pips.length > 0 ? pips : [null];
                        _pips.forEach((selectedProxyIp) => {
                            let ipName = ipNameMap[ip] || "";
                            if (effectiveMode === "vless" || effectiveMode === "both") {
                                let tag = getUniqueName(getConfigName("vless", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName));
                                let configUuid = generateConfigUuid(p.id, configIndex);
                                let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payload = { junk: randomJunk, protocol: "vl", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                                let path = "/" + btoa(JSON.stringify(payload));
                                let ob = {
                                    tag: tag,
                                    protocol: "vless",
                                    settings: { vnext: [{ address: ip, port: parseInt(port), users: [{ id: configUuid, encryption: "none" }] }] },
                                    streamSettings: {
                                        network: "ws",
                                        security: sec,
                                        tlsSettings: sec === "tls" ? { serverName: hName, allowInsecure: allowInsecure } : undefined,
                                        wsSettings: { path: path, headers: { Host: hName } }
                                    }
                                };
                                outboundsArr.push(ob);
                            }
                            if (effectiveMode === "trojan" || effectiveMode === "both") {
                                let tag = getUniqueName(getConfigName("trojan", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName));
                                let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payload = { junk: randomJunk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                                let path = "/" + btoa(JSON.stringify(payload));
                                let ob = {
                                    tag: tag,
                                    protocol: "trojan",
                                    settings: { servers: [{ address: ip, port: parseInt(port), password: p.id }] },
                                    streamSettings: {
                                        network: "ws",
                                        security: sec,
                                        tlsSettings: sec === "tls" ? { serverName: hName, allowInsecure: allowInsecure } : undefined,
                                        wsSettings: { path: path, headers: { Host: hName } }
                                    }
                                };
                                outboundsArr.push(ob);
                            }
                            configIndex++;
                        });
                    });
                });
            });
        });
    });
    await fetchTemplates(env);
    if (VTemplate) {
        let tpl = JSON.parse(JSON.stringify(VTemplate));
        let newOutbounds = [];
        for (let ob of tpl.outbounds) {
            if (ob === "__OUTBOUNDS__") {
                newOutbounds.push(...outboundsArr);
            } else {
                newOutbounds.push(ob);
            }
        }
        if (newOutbounds.length === 0) newOutbounds = outboundsArr;
        tpl.outbounds = newOutbounds;
        let cr = getCustomRouting();
        if (cr.domains.length > 0) {
            tpl.route.rules.unshift({ domain: cr.domains, outbound: "direct" });
            tpl.route.rules.unshift({ domain_suffix: cr.domains, outbound: "direct" });
        }
        if (cr.ips.length > 0) {
            tpl.route.rules.unshift({ ip_cidr: cr.ips, outbound: "direct" });
        }
        if (cr.geoips.length > 0) {
            tpl.route.rules.unshift({ geoip: cr.geoips, outbound: "direct" });
        }
        if (cr.geosites.length > 0) {
            tpl.route.rules.unshift({ geosite: cr.geosites, outbound: "direct" });
        }
        return tpl;
    }
    return { outbounds: outboundsArr };
}

async function buildSingBoxJsonProfile(hostName, targetSub = null, allowInsecure = false, env = null) {
    let ports = panelConfig.socketPorts ? panelConfig.socketPorts.split(",").map((s) => s.trim()).filter(Boolean) : ["443"];
    let profiles = getAllProfiles(targetSub);
    let allHostNames = [...new Set(profiles.flatMap((p) => getProfileHostNames(hostName, p)))];
    await preloadIpFlags(profiles, allHostNames);
    let proxyGeoInfo = new Map();
    let reqPath = encodeURI(`/subscription`);
    let outboundsArr = [];
    let dynamicTags = [];
    let nameCounts = {};
    let fakeNames = getFakeConfigNames(targetSub);
    let fakeRefs = [];
    fakeNames.forEach((name) => {
        outboundsArr.push({ type: "direct", tag: name });
        fakeRefs.push(name);
    });
    const getUniqueName = (baseName) => {
        if (!nameCounts[baseName]) { nameCounts[baseName] = 1; return baseName; }
        let counter = nameCounts[baseName];
        let newName = `${baseName}-${counter}`;
        while (nameCounts[newName]) { counter++; newName = `${baseName}-${counter}`; }
        nameCounts[baseName] = counter + 1;
        nameCounts[newName] = 1;
        return newName;
    };
    profiles.forEach((p) => {
        let pips = getEffectivePips(p);
        let effectiveMode = p.userMode || panelConfig.mode;
        let effectivePorts = p.userPorts ? p.userPorts.split(",").map((s) => s.trim()).filter(Boolean) : ports;
        let maxCfg = p.maxConfigs || null;
        let configIndex = 0;
        let profileHostNames = getProfileHostNames(hostName, p);
        profileHostNames.forEach((hName) => {
            let ipEntries = getCleanIpsWithNames(hName, p.cleanIp);
            let allIps = ipEntries.map((e) => e.ip);
            let ips = calcEffectiveIps(allIps, maxCfg, effectiveMode, effectivePorts, pips.length);
            let ipNameMap = {};
            ipEntries.forEach((e) => { ipNameMap[e.ip] = e.name; });
            effectivePorts.forEach((port) => {
                let sec = getTransportParams(port) === "tls";
                ips.forEach((ip) => {
                    let isVless = effectiveMode === "vless" || effectiveMode === "both";
                    let isTrojan = effectiveMode === "trojan" || effectiveMode === "both";
                    let _pips = pips.length > 0 ? pips : [null];
                    _pips.forEach((selectedProxyIp) => {
                        let ipName = ipNameMap[ip] || "";
                        if (isVless) {
                            let tagStr = getConfigName("vless", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName);
                            tagStr = getUniqueName(tagStr);
                            dynamicTags.push(tagStr);
                            let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                            let payloadVl = { junk: randomJunk, protocol: "vl", mode: "proxyip", panelIPs: [] };
                            let pathStrVl = "/" + btoa(JSON.stringify(payloadVl));
                            let configUuid = generateConfigUuid(p.id, configIndex);
                            registerConfigEntry(configUuid, p.id, selectedProxyIp || "");
                            let ob = {
                                type: k_vl_mode,
                                tag: tagStr,
                                server: ip,
                                server_port: parseInt(port),
                                tcp_fast_open: panelConfig.enableOpt1 || false,
                                uuid: configUuid,
                                packet_encoding: "xudp",
                                network: "tcp",
                                tls: {
                                    enabled: sec,
                                    server_name: hName,
                                    insecure: allowInsecure,
                                    alpn: ["http/1.1"],
                                    utls: { enabled: true, fingerprint: "randomized" },
                                },
                                transport: {
                                    type: "ws",
                                    path: pathStrVl,
                                    max_early_data: 2560,
                                    early_data_header_name: "Sec-WebSocket-Protocol",
                                    headers: { Host: hName },
                                },
                            };
                            outboundsArr.push(ob);
                        }
                        if (isTrojan) {
                            let tagStr = getConfigName("trojan", p.name, port, hName, ip, selectedProxyIp, configIndex, ipName);
                            tagStr = getUniqueName(tagStr);
                            dynamicTags.push(tagStr);
                            let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                            let payloadTr = { junk: randomJunk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                            let pathStrTr = "/" + btoa(JSON.stringify(payloadTr));
                            let configUuid2 = generateConfigUuid(p.id, configIndex);
                            registerConfigEntry(configUuid2, p.id, selectedProxyIp || "");
                            let ob = {
                                type: k_tr_mode,
                                tag: tagStr,
                                server: ip,
                                server_port: parseInt(port),
                                tcp_fast_open: panelConfig.enableOpt1 || false,
                                password: p.id,
                                network: "tcp",
                                tls: {
                                    enabled: sec,
                                    server_name: hName,
                                    insecure: allowInsecure,
                                    alpn: ["http/1.1"],
                                    utls: { enabled: true, fingerprint: "randomized" },
                                },
                                transport: {
                                    type: "ws",
                                    path: pathStrTr,
                                    max_early_data: 2560,
                                    early_data_header_name: "Sec-WebSocket-Protocol",
                                    headers: { Host: hName },
                                },
                            };
                            outboundsArr.push(ob);
                        }
                        configIndex++;
                        if (panelConfig.enableDirectConfigs && pips.length > 0 && selectedProxyIp === pips[0]) {
                            if (isVless) {
                                let tagStr = getUniqueName(getConfigName("vless", p.name, port, hName, ip, null, configIndex, ipName, true));
                                dynamicTags.push(tagStr);
                                proxyGeoInfo.set(tagStr, getGeoInfo(ip));
                                let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payloadVl = { junk: randomJunk, protocol: "vl", mode: "proxyip", panelIPs: [] };
                                let pathStrVl = "/" + btoa(JSON.stringify(payloadVl));
                                let configUuid = generateConfigUuid(p.id, configIndex);
                                registerConfigEntry(configUuid, p.id, "");
                                let ob = {
                                    type: k_vl_mode,
                                    tag: tagStr,
                                    server: ip,
                                    server_port: parseInt(port),
                                    tcp_fast_open: panelConfig.enableOpt1 || false,
                                    uuid: configUuid,
                                    packet_encoding: "xudp",
                                    network: "tcp",
                                    tls: {
                                        enabled: sec,
                                        server_name: hName,
                                        insecure: allowInsecure,
                                        alpn: ["http/1.1"],
                                        utls: { enabled: true, fingerprint: "randomized" },
                                    },
                                    transport: {
                                        type: "ws",
                                        path: pathStrVl,
                                        max_early_data: 2560,
                                        early_data_header_name: "Sec-WebSocket-Protocol",
                                        headers: { Host: hName },
                                    },
                                };
                                outboundsArr.push(ob);
                            }
                            if (isTrojan) {
                                let tagStr = getUniqueName(getConfigName("trojan", p.name, port, hName, ip, null, configIndex, ipName, true));
                                dynamicTags.push(tagStr);
                                proxyGeoInfo.set(tagStr, getGeoInfo(ip));
                                let randomJunk = Array.from({ length: 11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]).join("");
                                let payloadTr = { junk: randomJunk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                                let pathStrTr = "/" + btoa(JSON.stringify(payloadTr));
                                let configUuid2 = generateConfigUuid(p.id, configIndex);
                                let ob = {
                                    type: k_tr_mode,
                                    tag: tagStr,
                                    server: ip,
                                    server_port: parseInt(port),
                                    tcp_fast_open: panelConfig.enableOpt1 || false,
                                    password: p.id,
                                    network: "tcp",
                                    tls: {
                                        enabled: sec,
                                        server_name: hName,
                                        insecure: allowInsecure,
                                        alpn: ["http/1.1"],
                                        utls: { enabled: true, fingerprint: "randomized" },
                                    },
                                    transport: {
                                        type: "ws",
                                        path: pathStrTr,
                                        max_early_data: 2560,
                                        early_data_header_name: "Sec-WebSocket-Protocol",
                                        headers: { Host: hName },
                                    },
                                };
                                outboundsArr.push(ob);
                            }
                            configIndex++;
                        }
                    });
                });
            });
        });
    });
    if (dynamicTags.length === 0) { dynamicTags.push("direct"); }
    await fetchTemplates(env);
    if (singboxTemplate) {
        let tpl = JSON.parse(JSON.stringify(singboxTemplate));
        let newOutbounds = [];
        let allProxies = outboundsArr.map(o => o.tag);
        for (let ob of tpl.outbounds) {
            if (ob === "__OUTBOUNDS__") {
                newOutbounds.push(...outboundsArr);
            } else if (ob.outbounds && ob.outbounds.includes("{all_proxies}")) {
                let obCpy = { ...ob };
                obCpy.outbounds = [];
                for (let tag of ob.outbounds) {
                    if (tag === "{all_proxies}") obCpy.outbounds.push(...allProxies);
                    else obCpy.outbounds.push(tag);
                }
                newOutbounds.push(obCpy);
            } else {
                newOutbounds.push(ob);
            }
        }
        tpl.outbounds = newOutbounds;
        return tpl;
    }
    return {
        log: { disabled: false, level: "warn", timestamp: true },
        dns: { servers: [], rules: [] },
        inbounds: [],
        [k_obds]: outboundsArr,
        route: { rules: [] }
    };
}

async function processTelemetryStream(env, ctx, wsRelayIdx) {
    const [client, webSocket] = Object.values(new WebSocketPair());
    webSocket.accept();
    webSocket.binaryType = "arraybuffer";
    startDataPipe(webSocket, env, ctx, wsRelayIdx);
    return new Response(null, { status: 101, webSocket: client });
}

async function startDataPipe(webSocket, env, ctx, wsRelayIdx) {
    activeConnections++;
    webSocket.addEventListener("close", () => {
        activeConnections--;
        if (activeClientHash) {
            let cur = activeConns.get(activeClientHash) || 0;
            if (cur > 0) activeConns.set(activeClientHash, cur - 1);
        }
    });
    webSocket.addEventListener("error", () => {});
    let remoteSocket, dataWriter, isInit = true, queue = Promise.resolve();
    let activeClientHash = null;
    webSocket.addEventListener("message", (event) => {
        queue = queue.then(async () => {
            try {
                if (isInit) {
                    isInit = false;
                    const isModeVless = await parseSensorData(event.data, wsRelayIdx);
                    if (isModeVless) webSocket.send(new Uint8Array([0, 0]));
                } else if (dataWriter) {
                    await dataWriter.write(event.data);
                }
            } catch (err) {
                webSocket.close();
            }
        });
    });

    async function parseSensorData(bufferData, wsRelayIdx) {
        const view = new Uint8Array(bufferData);
        let targetAddr = "", targetPort = 0, offset = 0, isModeVless = false, activeProfile = null;
        if (view[0] === 0x00) {
            isModeVless = true;
            let clientHash = Array.from(view.slice(1, 17)).map((b) => b.toString(16).padStart(2, "0")).join("");
            let configEntry = lookupConfigEntry(clientHash);
            if (configEntry) {
                activeClientHash = configEntry.userId.replace(/-/g, "").toLowerCase();
                activeProfile = getAllProfiles().find((p) => p.id.replace(/-/g, "").toLowerCase() === activeClientHash);
                if (!activeProfile) return false;
                if (configEntry.relayIp) activeProfile = { ...activeProfile, proxyIp: configEntry.relayIp };
            } else {
                let decoded = decodeConfigUuid(clientHash);
                if (decoded) {
                    activeProfile = getAllProfiles().find((p) => p.id.replace(/-/g, "").toLowerCase().startsWith(decoded.userFingerprint));
                    if (activeProfile && decoded.relayIpIndex >= 0) {
                        const effectivePips = getEffectivePips(activeProfile);
                        if (effectivePips.length > 0) {
                            const idx = decoded.relayIpIndex % effectivePips.length;
                            activeProfile = { ...activeProfile, proxyIp: effectivePips[idx] };
                        }
                    }
                }
                if (!activeProfile) {
                    activeProfile = getAllProfiles().find((p) => p.id.replace(/-/g, "").toLowerCase() === clientHash);
                }
                if (!activeProfile) return false;
                activeClientHash = activeProfile.id.replace(/-/g, "").toLowerCase();
            }
            trackUsage(activeClientHash, 0, env, ctx);
            let currentConns = activeConns.get(activeClientHash) || 0;
            if (activeProfile && activeProfile.connLimit) {
                if (currentConns >= activeProfile.connLimit) {
                    webSocket.close();
                    return isModeVless;
                }
            }
            activeConns.set(activeClientHash, currentConns + 1);
            let uTrack = uuidUsage.get(activeClientHash) || { connects: 0, last: 0 };
            uTrack.connects++;
            uTrack.last = Date.now();
            uuidUsage.set(activeClientHash, uTrack);
            const optLen = view[17];
            const pPos = 18 + optLen + 1;
            targetPort = new DataView(bufferData.slice(pPos, pPos + 2)).getUint16(0);
            const aType = view[pPos + 2];
            let vPos = pPos + 3, aLen = 0;
            if (aType === 1) { aLen = 4; targetAddr = view.slice(vPos, vPos + aLen).join("."); }
            else if (aType === 2) { aLen = view[vPos]; vPos++; targetAddr = new TextDecoder().decode(view.slice(vPos, vPos + aLen)); }
            else if (aType === 3) { aLen = 16; const dv = new DataView(bufferData.slice(vPos, vPos + aLen)); targetAddr = Array.from({ length: 8 }, (_, i) => dv.getUint16(i * 2).toString(16)).join(":"); }
            offset = vPos + aLen;
        } else {
            let ePos = bufferData.byteLength;
            for (let i = 0; i < bufferData.byteLength; i++) {
                if (view[i] === 0x0d && view[i + 1] === 0x0a) { ePos = i; break; }
            }
            let clientHashHex = new TextDecoder().decode(view.slice(0, ePos));
            let configEntry = lookupConfigEntry(clientHashHex);
            if (configEntry) {
                activeClientHash = configEntry.userId.replace(/-/g, "").toLowerCase();
                activeProfile = getAllProfiles().find((p) => p.id.replace(/-/g, "").toLowerCase() === activeClientHash);
                if (!activeProfile) return false;
                if (configEntry.relayIp) activeProfile = { ...activeProfile, proxyIp: configEntry.relayIp };
            } else {
                activeProfile = getAllProfiles().find((p) => getTrojanHash(p.id) === clientHashHex);
                if (!activeProfile) return false;
                activeClientHash = activeProfile.id.replace(/-/g, "").toLowerCase();
                if (wsRelayIdx >= 0) {
                    const effectivePips = getEffectivePips(activeProfile);
                    if (effectivePips.length > 0) {
                        activeProfile = { ...activeProfile, proxyIp: effectivePips[wsRelayIdx % effectivePips.length] };
                    }
                }
            }
            trackUsage(activeClientHash, 0, env, ctx);
            let currentConns = activeConns.get(activeClientHash) || 0;
            if (activeProfile && activeProfile.connLimit) {
                if (currentConns >= activeProfile.connLimit) {
                    webSocket.close();
                    return isModeVless;
                }
            }
            activeConns.set(activeClientHash, currentConns + 1);
            let uTrack = uuidUsage.get(activeClientHash) || { connects: 0, last: 0 };
            uTrack.connects++;
            uTrack.last = Date.now();
            uuidUsage.set(activeClientHash, uTrack);
            let hPos = ePos + 2;
            hPos++;
            let aType = view[hPos];
            hPos++;
            let aLen = 0;
            if (aType === 1) { aLen = 4; targetAddr = view.slice(hPos, hPos + aLen).join("."); }
            else if (aType === 3) { aLen = view[hPos]; hPos++; targetAddr = new TextDecoder().decode(view.slice(hPos, hPos + aLen)); }
            else if (aType === 4) { aLen = 16; const dv = new DataView(bufferData.slice(hPos, hPos + aLen)); targetAddr = Array.from({ length: 8 }, (_, i) => dv.getUint16(i * 2).toString(16)).join(":"); }
            hPos += aLen;
            targetPort = new DataView(bufferData.slice(hPos, hPos + 2)).getUint16(0);
            offset = hPos + 4;
        }
        let isDomain = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(targetAddr) || /^[a-zA-Z0-9-]+$/.test(targetAddr);
        let connectAddr = targetAddr;
        if (isDomain && panelConfig.customDns) {
            try {
                const dohUrl = new URL(panelConfig.customDns);
                dohUrl.searchParams.set("name", targetAddr);
                dohUrl.searchParams.set("type", "A");
                let dnsRes = await fetch(dohUrl.toString(), { headers: { accept: "application/dns-json" } });
                let dnsJson = await dnsRes.json();
                if (dnsJson.Answer && dnsJson.Answer.length > 0) { connectAddr = dnsJson.Answer[0].data; }
            } catch (e) {}
        }
        try {
            remoteSocket = connect({ hostname: connectAddr, port: targetPort });
            await remoteSocket.opened;
        } catch {
            let pips = [];
            if (activeProfile && activeProfile.proxyIp) {
                pips = activeProfile.proxyIp.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
            }
            if (pips.length === 0 && panelConfig.backupRelay) {
                pips = panelConfig.backupRelay.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
            }
            if (pips.length === 0 && panelConfig.customRelay) {
                pips = panelConfig.customRelay.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
            }
            let startIndex = 0;
            if (pips.length > 1) {
                let hash = 0;
                let hashStr = activeProfile ? activeProfile.id : "";
                for (let i = 0; i < hashStr.length; i++) { hash = hashStr.charCodeAt(i) + ((hash << 5) - hash); }
                startIndex = Math.abs(hash) % pips.length;
            }
            let connected = false;
            for (let attempt = 0; attempt < Math.min(pips.length, 3); attempt++) {
                let currentIndex = (startIndex + attempt) % pips.length;
                let currentProxy = pips[currentIndex];
                try {
                    const [altIP, altPortStr] = currentProxy.split(":");
                    remoteSocket = connect({ hostname: altIP, port: altPortStr ? Number(altPortStr) : targetPort });
                    await remoteSocket.opened;
                    connected = true;
                    break;
                } catch (e) {}
            }
            if (!connected) {
                webSocket.close();
                return isModeVless;
            }
        }
        dataWriter = remoteSocket.writable.getWriter();
        if (offset < bufferData.byteLength) {
            let chunk = bufferData.slice(offset);
            await dataWriter.write(chunk);
        }
        remoteSocket.readable.pipeTo(
            new WritableStream({ write(chunk) { webSocket.send(chunk); } })
        );
        return isModeVless;
    }
}

async function logActivity(env, type, detail) {
    if (!env || !env.TopConfigIR) return;
    try {
        const ts = new Date().toISOString();
        let logs = [];
        const stored = await readDB(env, "sys_logs");
        if (stored) logs = JSON.parse(stored);
        logs.unshift({ ts, type, detail });
        if (logs.length > 50) logs = logs.slice(0, 50);
        await writeDB(env, "sys_logs", JSON.stringify(logs));
    } catch (e) {}
}

async function handleUsersApi(request, env, ctx) {
    try {
        const url = new URL(request.url);
        const method = request.method;
        const userId = url.searchParams.get("id");
        const action = url.searchParams.get("action");
        const userParam = url.searchParams.get("user");

        if (!panelConfig.users) panelConfig.users = [];

        if (method === "GET" && userParam) {
            const found = panelConfig.users.find(u => u.name.toLowerCase() === userParam.toLowerCase() || u.id === userParam);
            if (!found) {
                return new Response(
                    JSON.stringify({ success: false, error: "User not found" }),
                    { status: 404, headers: { "Content-Type": "application/json" } }
                );
            }
            const idClean = found.id.replace(/-/g, "").toLowerCase();
            const storeU = usageStore?.users?.[idClean] || { reqs: 0, dReqs: 0, lastDay: "" };
            const usedBytes = Math.floor((storeU.reqs || 0) * (1073741824 / 6000));
            const limitBytes = found.limitTotalReq ? Math.floor(found.limitTotalReq * (1073741824 / 6000)) : 0;
            const isExpired = found.expiryMs && Date.now() > found.expiryMs;
            let status = "active";
            if (found.isPaused && found.disabledReason) status = "auto-disabled";
            else if (found.isPaused) status = "paused";
            else if (isExpired) status = "expired";
            return new Response(
                JSON.stringify({
                    success: true,
                    user: {
                        ...found,
                        usage: {
                            total: usedBytes,
                            limit: limitBytes,
                            daily: storeU.dReqs || 0,
                            dailyLimit: found.limitDailyReq || 0,
                        },
                        status,
                    },
                }),
                { headers: { "Content-Type": "application/json" } }
            );
        }

        if (method === "GET") {
            try {
                const enriched = panelConfig.users.map((u) => {
                    const idClean = u.id.replace(/-/g, "").toLowerCase();
                    const storeU = usageStore?.users?.[idClean] || { reqs: 0, dReqs: 0, lastDay: "" };
                    const usedBytes = Math.floor((storeU.reqs || 0) * (1073741824 / 6000));
                    const limitBytes = u.limitTotalReq ? Math.floor(u.limitTotalReq * (1073741824 / 6000)) : 0;
                    const isExpired = u.expiryMs && Date.now() > u.expiryMs;
                    let status = "active";
                    if (u.isPaused && u.disabledReason) status = "auto-disabled";
                    else if (u.isPaused) status = "paused";
                    else if (isExpired) status = "expired";
                    return {
                        ...u,
                        usage: {
                            total: usedBytes,
                            limit: limitBytes,
                            daily: storeU.dReqs || 0,
                            dailyLimit: u.limitDailyReq || 0,
                        },
                        status,
                    };
                });
                return new Response(
                    JSON.stringify({ success: true, users: enriched, total: enriched.length }),
                    { headers: { "Content-Type": "application/json" } }
                );
            } catch (e) {
                return new Response(
                    JSON.stringify({ success: false, error: e.message }),
                    { status: 500, headers: { "Content-Type": "application/json" } }
                );
            }
        }

        const authKey = url.searchParams.get("key") || "";
        let bodyKey = "";
        if (method === "POST" || method === "PUT") {
            try {
                const body = await request.clone().json();
                bodyKey = body.key || "";
            } catch (e) {}
        }
        const isAuth = authKey === panelConfig.masterKey || bodyKey === panelConfig.masterKey;
        if (!isAuth) {
            return new Response(
                JSON.stringify({ success: false, error: "Unauthorized" }),
                { status: 401, headers: { "Content-Type": "application/json" } }
            );
        }

        if (method === "POST") {
            try {
                const body = await request.json();
                if (!body.name) {
                    return new Response(
                        JSON.stringify({ success: false, error: "Name is required" }),
                        { status: 400, headers: { "Content-Type": "application/json" } }
                    );
                }
                const newId = generateId();
                const newUser = {
                    id: newId,
                    name: body.name,
                    limitTotalReq: body.trafficLimit ? Math.floor(parseFloat(body.trafficLimit) * 6000) : null,
                    limitDailyReq: body.dailyLimit ? Math.floor(parseFloat(body.dailyLimit) * 6000) : null,
                    expiryMs: body.expiryDays ? Date.now() + parseInt(body.expiryDays) * 86400000 : null,
                    notes: body.notes || "",
                    maxConfigs: body.maxConfigs ? parseInt(body.maxConfigs) : null,
                    proxyIp: body.proxyIp || null,
                    cleanIp: body.cleanIp || null,
                    userMode: body.userMode || null,
                    userPorts: body.userPorts || null,
                    userNodes: body.userNodes || null,
                    nat64: body.nat64 || null,
                    connLimit: body.connLimit ? parseInt(body.connLimit) : null,
                    userPanelUrl: body.userPanelUrl || null,
                    createdAt: Date.now(),
                    isPaused: false,
                };
                panelConfig.users.push(newUser);
                await saveToDB(env, "panel_config", JSON.stringify(panelConfig));
                ctx?.waitUntil(logActivity(env, "User Created", `User "${body.name}" (${newId}) created`).catch(() => {}));
                return new Response(
                    JSON.stringify({ success: true, user: newUser }),
                    { status: 201, headers: { "Content-Type": "application/json" } }
                );
            } catch (e) {
                return new Response(
                    JSON.stringify({ success: false, error: e.message }),
                    { status: 500, headers: { "Content-Type": "application/json" } }
                );
            }
        }

        if (method === "PUT" && userId) {
            try {
                const body = await request.json();
                const u = panelConfig.users.find(usr => usr.id === userId);
                if (!u) {
                    return new Response(
                        JSON.stringify({ success: false, error: "User not found" }),
                        { status: 404, headers: { "Content-Type": "application/json" } }
                    );
                }
                if (body.name !== undefined) u.name = body.name;
                if (body.trafficLimit !== undefined) u.limitTotalReq = body.trafficLimit ? Math.floor(parseFloat(body.trafficLimit) * 6000) : null;
                if (body.dailyLimit !== undefined) u.limitDailyReq = body.dailyLimit ? Math.floor(parseFloat(body.dailyLimit) * 6000) : null;
                if (body.expiryDays !== undefined) {
                    if (u.expiryMs) u.expiryMs += parseInt(body.expiryDays) * 86400000;
                    else u.expiryMs = Date.now() + parseInt(body.expiryDays) * 86400000;
                }
                if (body.notes !== undefined) u.notes = body.notes;
                if (body.maxConfigs !== undefined) u.maxConfigs = body.maxConfigs ? parseInt(body.maxConfigs) : null;
                if (body.proxyIp !== undefined) u.proxyIp = body.proxyIp;
                if (body.cleanIp !== undefined) u.cleanIp = body.cleanIp;
                if (body.userMode !== undefined) u.userMode = body.userMode;
                if (body.userPorts !== undefined) u.userPorts = body.userPorts;
                if (body.userNodes !== undefined) u.userNodes = body.userNodes;
                if (body.nat64 !== undefined) u.nat64 = body.nat64;
                if (body.connLimit !== undefined) u.connLimit = body.connLimit ? parseInt(body.connLimit) : null;
                if (body.userPanelUrl !== undefined) u.userPanelUrl = body.userPanelUrl || null;
                await saveToDB(env, "panel_config", JSON.stringify(panelConfig));
                ctx?.waitUntil(logActivity(env, "User Updated", `User "${u.name}" (${userId}) updated`).catch(() => {}));
                return new Response(
                    JSON.stringify({ success: true, user: u }),
                    { headers: { "Content-Type": "application/json" } }
                );
            } catch (e) {
                return new Response(
                    JSON.stringify({ success: false, error: e.message }),
                    { status: 500, headers: { "Content-Type": "application/json" } }
                );
            }
        }

        if (method === "DELETE" && userId) {
            try {
                const idx = panelConfig.users.findIndex(usr => usr.id === userId);
                if (idx === -1) {
                    return new Response(
                        JSON.stringify({ success: false, error: "User not found" }),
                        { status: 404, headers: { "Content-Type": "application/json" } }
                    );
                }
                const deleted = panelConfig.users.splice(idx, 1)[0];
                await saveToDB(env, "panel_config", JSON.stringify(panelConfig));
                ctx?.waitUntil(logActivity(env, "User Deleted", `User "${deleted.name}" (${userId}) deleted`).catch(() => {}));
                return new Response(
                    JSON.stringify({ success: true, deleted: deleted.id }),
                    { headers: { "Content-Type": "application/json" } }
                );
            } catch (e) {
                return new Response(
                    JSON.stringify({ success: false, error: e.message }),
                    { status: 500, headers: { "Content-Type": "application/json" } }
                );
            }
        }

        if (method === "POST" && userId && action === "toggle") {
            try {
                const u = panelConfig.users.find(usr => usr.id === userId);
                if (!u) {
                    return new Response(
                        JSON.stringify({ success: false, error: "User not found" }),
                        { status: 404, headers: { "Content-Type": "application/json" } }
                    );
                }
                u.isPaused = !u.isPaused;
                if (!u.isPaused) {
                    u.disabledReason = null;
                    u.disabledAt = null;
                }
                await saveToDB(env, "panel_config", JSON.stringify(panelConfig));
                ctx?.waitUntil(logActivity(env, "User Toggled", `User "${u.name}" (${userId}) ${u.isPaused ? "paused" : "resumed"}`).catch(() => {}));
                return new Response(
                    JSON.stringify({ success: true, user: u }),
                    { headers: { "Content-Type": "application/json" } }
                );
            } catch (e) {
                return new Response(
                    JSON.stringify({ success: false, error: e.message }),
                    { status: 500, headers: { "Content-Type": "application/json" } }
                );
            }
        }

        return new Response(
            JSON.stringify({ success: false, error: "Invalid request" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
        );
    } catch (e) {
        return new Response(
            JSON.stringify({ success: false, error: e.message }),
            { status: 500, headers: { "Content-Type": "application/json" } }
        );
    }
}

async function handleStatsApi(request, env) {
    try {
        const url = new URL(request.url);
        const authKey = url.searchParams.get("key") || "";
        if (authKey !== panelConfig.masterKey) {
            return new Response(
                JSON.stringify({ success: false, error: "Unauthorized" }),
                { status: 401, headers: { "Content-Type": "application/json" } }
            );
        }
        const users = panelConfig.users || [];
        const totalUsers = users.length;
        const activeUsers = users.filter((u) => !u.isPaused && (!u.expiryMs || Date.now() <= u.expiryMs)).length;
        const autoDisabledUsers = users.filter((u) => u.isPaused && u.disabledReason).length;
        const pausedUsers = users.filter((u) => u.isPaused && !u.disabledReason).length;
        const expiredUsers = users.filter((u) => u.expiryMs && Date.now() > u.expiryMs && !u.isPaused).length;
        let totalTrafficReqs = 0;
        let dailyTrafficReqs = 0;
        const todayDate = new Date().toISOString().split("T")[0];
        users.forEach((u) => {
            const idClean = u.id.replace(/-/g, "").toLowerCase();
            const storeU = usageStore?.users?.[idClean] || { reqs: 0, dReqs: 0, lastDay: "" };
            totalTrafficReqs += storeU.reqs || 0;
            if (storeU.lastDay === todayDate) dailyTrafficReqs += storeU.dReqs || 0;
        });
        let usageData = {};
        for (let [k, v] of uuidUsage.entries()) {
            usageData[k] = { ...v, connects: activeConns.get(k) || 0 };
        }
        const upSeconds = Math.floor((Date.now() - startTime) / 1000);
        return new Response(
            JSON.stringify({
                success: true,
                stats: {
                    users: {
                        total: totalUsers,
                        active: activeUsers,
                        paused: pausedUsers,
                        expired: expiredUsers,
                        autoDisabled: autoDisabledUsers,
                    },
                    traffic: {
                        totalRequests: totalTrafficReqs,
                        totalGB: (totalTrafficReqs / 6000).toFixed(2),
                        dailyRequests: dailyTrafficReqs,
                        dailyGB: (dailyTrafficReqs / 6000).toFixed(2),
                    },
                    usage: usageData,
                    system: {
                        uptimeSeconds: upSeconds,
                        activeConnections,
                        version: APP_VERSION,
                        isPaused: panelConfig.isPaused || false,
                    },
                },
            }),
            { headers: { "Content-Type": "application/json" } }
        );
    } catch (e) {
        return new Response(
            JSON.stringify({ success: false, error: e.message }),
            { status: 500, headers: { "Content-Type": "application/json" } }
        );
    }
}

async function handleAuth(request, hostName, ctx, env) {
    try {
        const data = await request.json();
        const ip = request.headers.get("cf-connecting-ip") || "Unknown";
        const oldKey = data.oldKey || "";
        const newKey = data.newKey || "";
        if (oldKey === panelConfig.masterKey && newKey && newKey.length >= 3) {
            panelConfig.masterKey = newKey;
            await saveToDB(env, "panel_config", JSON.stringify(panelConfig));
            ctx?.waitUntil(logActivity(env, "Password Changed", `Password changed from ${ip}`).catch(() => {}));
            return new Response(
                JSON.stringify({ success: true, message: "Password updated successfully" }),
                { headers: { "Content-Type": "application/json" } }
            );
        }
        const loginKey = data.key || "";
        if (loginKey === panelConfig.masterKey || isPanelApiKey(loginKey)) {
            if (isPanelApiKey(loginKey)) {
                const apiKeyEntry = (panelConfig.panelApiKeys || []).find((k) => k.key === loginKey);
                if (apiKeyEntry) apiKeyEntry.lastUsed = Date.now();
            }
            ctx?.waitUntil(logActivity(env, "Auth Success", `Successful login from ${ip}`).catch(() => {}));
            return new Response(
                JSON.stringify({
                    success: true,
                    config: {
                        ...panelConfig,
                        masterKey: "[PROTECTED]",
                        panelApiKeys: "[PROTECTED]",
                        cfApiToken: "[PROTECTED]",
                        cfAccountId: "[PROTECTED]",
                        cfWorkerName: "[PROTECTED]",
                        tgToken: "[PROTECTED]",
                        tgChatId: "[PROTECTED]",
                        tgAdminId: "[PROTECTED]",
                        syncApiKey: "[PROTECTED]",
                    },
                    deviceId: deviceUuid,
                    version: APP_VERSION,
                }),
                { status: 200 }
            );
        }
        ctx?.waitUntil(logActivity(env, "Auth Failed", `Failed login attempt from ${ip}`).catch(() => {}));
        return new Response(JSON.stringify({ success: false }), { status: 401 });
    } catch (e) {
        return new Response(JSON.stringify({ success: false }), { status: 400 });
    }
}

async function handleSubscription(request, url, env, ctx) {
    try {
        const ua = (request.headers.get("User-Agent") || "").toLowerCase();
        const clientHost = request.headers.get("Host") || url.hostname;
        let targetSub = url.searchParams.get("user");
        let hasMultiUser = panelConfig.users && panelConfig.users.length > 0;
        let targetUser = null;
        let isValidUser = false;
        if (hasMultiUser) {
            if (targetSub) {
                targetUser = panelConfig.users.find((u) => u.name.toLowerCase() === targetSub.toLowerCase() || u.id === targetSub);
                if (targetUser) isValidUser = true;
            }
        } else {
            isValidUser = true;
            targetUser = { id: deviceUuid, name: "Default" };
        }
        if (hasMultiUser && !isValidUser) {
            return new Response("Error: User not found. Use ?user=NAME", { status: 404 });
        }
        const allowInsecure = url.searchParams.get("insecure") === "true" || url.searchParams.get("allowInsecure") === "true" || url.searchParams.get("allow_insecure") === "1" || url.searchParams.get("allowInsecure") === "1";
        const resHeaders = new Headers();
        resHeaders.set("Cache-Control", "no-store");
        resHeaders.set("Access-Control-Allow-Origin", "*");
        let flag = (url.searchParams.get("flag") || url.searchParams.get("format") || url.searchParams.get("type") || url.searchParams.get("output") || "").toLowerCase();
        if (isValidUser && targetUser) {
            let idClean = targetUser.id.replace(/-/g, "").toLowerCase();
            let storeU = usageStore?.users?.[idClean] || { reqs: 0, dReqs: 0 };
            let totalReqs = storeU.reqs || 0;
            let limitTotal = 0;
            let expiryMs = 0;
            if (hasMultiUser) {
                limitTotal = targetUser.limitTotalReq || 0;
                expiryMs = targetUser.expiryMs || 0;
            } else {
                limitTotal = panelConfig.limitTotalReq || 0;
                expiryMs = panelConfig.expiryMs || 0;
            }
            let usedBytes = Math.floor(totalReqs * (1073741824 / 6000));
            let limitBytes = Math.floor(limitTotal * (1073741824 / 6000));
            let expireSec = expiryMs ? Math.floor(expiryMs / 1000) : 0;
            const subUserInfo = `upload=0; download=${usedBytes}; total=${limitBytes}; expire=${expireSec}`;
            resHeaders.set("Subscription-UserInfo", subUserInfo);
            resHeaders.set("subscription-userinfo", subUserInfo);
            resHeaders.set("Profile-Update-Interval", "12");
            resHeaders.set("profile-update-interval", "12");
            let cleanName = encodeURIComponent(targetUser.name);
            resHeaders.set("Content-Disposition", `attachment; filename="${cleanName}"; filename*=UTF-8''${cleanName}`);
        }
        let isClashYaml = false;
        let isSingboxJson = false;
        let isClashJson = false;
        let isVJson = false;
        if (flag === "clash" || flag === "yaml" || flag === "meta" || flag === "stash" || flag === "clash-meta" || flag === "y") {
            isClashYaml = true;
        } else if (flag === "b" || flag === "c_legacy") {
            isClashJson = true;
        } else if (flag === "sing" || flag === "singbox" || flag === "sing-box" || flag === "sb" || flag === "s" || flag === "c" || flag === "g") {
            isSingboxJson = true;
        } else if (flag === "vjson" || flag === "v") {
            isVJson = true;
        } else if (flag === "a" || flag === "raw" || flag === "") {
            if (ua.includes(clashTag()) || ua.includes("meta") || ua.includes("sta" + "sh") || ua.includes("verge") || ua.includes("mihomo") || ua.includes("cfw") || ua.includes("stash") || ua.includes("clash")) {
                isClashYaml = true;
            } else if (ua.includes("sing-box") || ua.includes("singbox") || ua.includes("hiddify") || ua.includes("nekobox") || ua.includes("sfa") || ua.includes("karing")) {
                isSingboxJson = true;
            }
        }
        if (isClashYaml) {
            resHeaders.set("Content-Type", "text/yaml; charset=utf-8");
            return new Response(await buildYamlProfile(clientHost, targetSub, allowInsecure, env), { headers: resHeaders });
        } else if (isSingboxJson) {
            resHeaders.set("Content-Type", "application/json; charset=utf-8");
            return new Response(JSON.stringify(await buildSingBoxJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers: resHeaders });
        } else if (isClashJson) {
            resHeaders.set("Content-Type", "application/json; charset=utf-8");
            return new Response(JSON.stringify(await buildClashJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers: resHeaders });
        } else if (isVJson) {
            resHeaders.set("Content-Type", "application/json; charset=utf-8");
            return new Response(JSON.stringify(await buildVJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers: resHeaders });
        } else {
            resHeaders.set("Content-Type", "text/plain; charset=utf-8");
            const raw = await buildUriProfile(clientHost, targetSub, allowInsecure);
            return new Response(encodeBase64(raw), { headers: resHeaders });
        }
    } catch (e) {
        return new Response(JSON.stringify({ success: false, error: e.message }), {
            status: 500,
            headers: { "Content-Type": "application/json" },
        });
    }
}

export default {
    async fetch(request, env, ctx) {
        try {
            if (!startTime) startTime = Date.now();
            if (configRegistry.size > 10000) { configRegistry.clear(); trojanHashCache.clear(); }
            await initPanel(env);
            deviceUuid = panelConfig.deviceId || createDeviceId("TopConfigIR");
            const url = new URL(request.url);
            const upgradeHeader = request.headers.get("Upgrade");
            const isTelemetryStream = upgradeHeader && upgradeHeader.toLowerCase() === "websocket";
            let reqPath = url.pathname;
            if (reqPath.endsWith("/") && reqPath.length > 1) reqPath = reqPath.slice(0, -1);
            if (!isTelemetryStream) {
                if (reqPath === "/") {
                    try {
                        const loginUrl = 'https://raw.githubusercontent.com/TopConfigIR/TopConfigIR/main/login.html';
                        const resp = await fetch(loginUrl);
                        const html = await resp.text();
                        return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8" } });
                    } catch (e) {
                        return new Response('Failed to load login page', { status: 502 });
                    }
                }
                if (reqPath === "/dashboard") {
                    try {
                        const dashboardUrl = 'https://raw.githubusercontent.com/TopConfigIR/TopConfigIR/main/dashboard.html';
                        const resp = await fetch(dashboardUrl);
                        let html = await resp.text();
                        if (env && env.TopConfigIR) {
                            html = html.replace('__HAS_DB_WARNING__', '');
                        } else {
                            html = html.replace('__HAS_DB_WARNING__', '<div class="mb-5 p-4 rounded-2xl flex items-start gap-3" style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);"><span style="color:#f87171;">&#9888;&#65039;</span><span class="text-sm" style="color:#fca5a5;">Database not connected. Settings won\'t be saved.</span></div>');
                        }
                        return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8" } });
                    } catch (e) {
                        return new Response('Failed to load dashboard', { status: 502 });
                    }
                }
                if (reqPath === "/sub") {
                    try {
                        const subUrl = 'https://raw.githubusercontent.com/TopConfigIR/TopConfigIR/main/subscription.html';
                        const resp = await fetch(subUrl);
                        const html = await resp.text();
                        return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8" } });
                    } catch (e) {
                        return new Response('Failed to load subscription page', { status: 502 });
                    }
                }
                if (reqPath === "/api/users") {
                    return await handleUsersApi(request, env, ctx);
                }
                if (reqPath === "/api/stats") {
                    return await handleStatsApi(request, env);
                }
                if (reqPath === "/api/auth") {
                    if (request.method !== "POST") return new Response("405", { status: 405 });
                    return await handleAuth(request, url.hostname, ctx, env);
                }
                if (reqPath === "/subscription") {
                    return await handleSubscription(request, url, env, ctx);
                }
            }
            if (isTelemetryStream) {
                if (panelConfig.isPaused) return new Response(null, { status: 503 });
                let wsRelayIdx = -1;
                try {
                    const riParam = url.searchParams.get("ri");
                    if (riParam !== null) wsRelayIdx = parseInt(riParam, 10);
                } catch (e) {}
                if (wsRelayIdx < 0) {
                    try {
                        const lastSeg = url.pathname.split("/").pop();
                        if (lastSeg) {
                            const num = parseInt(lastSeg, 10);
                            if (!isNaN(num) && num >= 0) wsRelayIdx = num;
                        }
                    } catch (e) {}
                }
                if (wsRelayIdx < 0) {
                    try {
                        const lastSeg = url.pathname.split("/").pop();
                        if (lastSeg) {
                            const decoded = JSON.parse(atob(lastSeg));
                            if (typeof decoded.relayIdx === "number") wsRelayIdx = decoded.relayIdx;
                        }
                    } catch (e) {}
                }
                return await processTelemetryStream(env, ctx, wsRelayIdx);
            }
            return new Response(null, { status: 404 });
        } catch (err) {
            return new Response(null, { status: 404 });
        }
    },
    async scheduled(event, env, ctx) {
        try {
            await initPanel(env);
        } catch (e) {}
    }
};
