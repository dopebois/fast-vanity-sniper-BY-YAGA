// made by @y_ga

"use strict";

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
process.title = "TWILIGHT";

if (process.platform === 'win32') {
    try {
        const { spawn } = require('child_process');
        spawn('wmic', ['process', 'where', `processid=${process.pid}`, 'CALL', 'setpriority', '256'], {stdio: 'ignore'});
        spawn('powershell', ['-Command', `$Process = Get-Process -Id ${process.pid}; $Process.ProcessorAffinity = 3`], {stdio: 'ignore'});
    } catch (e) {}
} else {
    try {
        require('os').setPriority(0, -20);
        require('child_process').spawn('taskset', ['-cp', '0,1', process.pid.toString()], {stdio: 'ignore'});
    } catch (e) {}
}

const tls = require('tls');
const http2 = require('http2');
const WebSocket = require('ws');

const CONFIG = {
    TOKEN: "",
    SERVER_ID: "",
    PASSWORD: "@y_ga owns u"
};

let mfaToken = null;
let claiming = false;
const guilds = Object.create(null);
const requestBuffers = new Map();
const jsonPayloads = new Map();
const tlsConnections = [];
let systemReady = false;

const BASE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Authorization': CONFIG.TOKEN,
    'Content-Type': 'application/json',
    'X-Super-Properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEzMy4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEzMy4wIiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMzLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJpbmdfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjM1NjE0MCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0='
};

// made by @y_ga

class MFATokenManager {
    constructor() {
        this.session = null;
        this.isRefreshing = false;
        this.createSession();
    }

    createSession() {
        if (this.session) {
            try { this.session.destroy(); } catch (e) {}
        }

        this.session = http2.connect("https://canary.discord.com", {
            settings: {
                enablePush: false,
                maxConcurrentStreams: 100,
                initialWindowSize: 1048576
            },
            secureContext: tls.createSecureContext({
                ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256',
                honorCipherOrder: true
            })
        });

        this.session.on('error', () => setTimeout(() => this.createSession(), 1000));
        this.session.on('close', () => setTimeout(() => this.createSession(), 1000));
    }

    async request(method, path, body = null) {
        if (!this.session || this.session.destroyed) {
            await new Promise(resolve => setTimeout(resolve, 100));
            this.createSession();
            return '{}';
        }

        return new Promise((resolve) => {
            const headers = {
                'User-Agent': BASE_HEADERS['User-Agent'],
                'Authorization': BASE_HEADERS['Authorization'],
                'Content-Type': BASE_HEADERS['Content-Type'],
                'X-Super-Properties': BASE_HEADERS['X-Super-Properties'],
                ":method": method,
                ":path": path,
                ":authority": "canary.discord.com",
                ":scheme": "https"
            };

            const stream = this.session.request(headers);
            const chunks = [];

            stream.on("data", chunk => chunks.push(chunk));
            stream.on("end", () => resolve(Buffer.concat(chunks).toString()));
            stream.on("error", () => resolve('{}'));
            stream.setTimeout(3000, () => {
                stream.destroy();
                resolve('{}');
            });

            if (body) stream.write(body);
            stream.end();
        });
    }

    async refreshMfaToken() {
        if (this.isRefreshing) return;
        this.isRefreshing = true;

        setImmediate(async () => {
            try {
                const response = await this.request("PATCH", `/api/v8/guilds/0/vanity-url`, '{"code":"mfa_trigger"}');
                const data = JSON.parse(response || '{}');

                if (data.code === 60003 && data.mfa?.ticket) {
                    const mfaResponse = await this.request(
                        "POST",
                        "/api/v8/mfa/finish",
                        JSON.stringify({
                            ticket: data.mfa.ticket,
                            mfa_type: "password",
                            data: CONFIG.PASSWORD
                        })
                    );

                    const mfaData = JSON.parse(mfaResponse || '{}');
                    if (mfaData.token) {
                        mfaToken = mfaData.token;
                        this.prebuildAllBuffers();
                    }
                }
            } catch (error) {}

            this.isRefreshing = false;
        });

        return true;
    }

    prebuildAllBuffers() {
        setImmediate(() => {
            requestBuffers.clear();
            for (const guildId in guilds) {
                const vanity = guilds[guildId];
                if (vanity) {
                    this.buildRequestBuffer(vanity);
                }
            }
            websocketLogin();
        });
    }

    buildRequestBuffer(vanityCode) {
        const payload = jsonPayloads.get(vanityCode) || JSON.stringify({ code: vanityCode });
        if (!jsonPayloads.has(vanityCode)) {
            jsonPayloads.set(vanityCode, payload);
        }
        const payloadLength = Buffer.byteLength(payload);

        const buffer = Buffer.from(
            `PATCH /api/v8/guilds/${CONFIG.SERVER_ID}/vanity-url HTTP/1.1\r\n` +
            `Host: canary.discord.com\r\n` +
            `Authorization: ${CONFIG.TOKEN}\r\n` +
            `X-Discord-MFA-Authorization: ${mfaToken}\r\n` +
            `Content-Type: application/json\r\n` +
            `Content-Length: ${payloadLength}\r\n` +
            `User-Agent: ${BASE_HEADERS['User-Agent']}\r\n` +
            `X-Super-Properties: ${BASE_HEADERS['X-Super-Properties']}\r\n` +
            `Cookie: __Secure-recent_mfa=${mfaToken}\r\n` +
            `Connection: keep-alive\r\n\r\n` +
            payload
        );

        requestBuffers.set(vanityCode, buffer);
        return buffer;
    }
}

const mfaManager = new MFATokenManager();

// made by @y_ga

class ClaimerSystem {
    constructor() {
        this.initializeConnections();
    }

    async initializeConnections() {
        for (let i = 0; i < 3; i++) {
            this.createTLSConnection(i);
        }
    }

    createTLSConnection(index) {
        const connection = tls.connect({
            host: 'canary.discord.com',
            port: 443,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
            rejectUnauthorized: false,
            keepAlive: true,
            noDelay: true,
            timeout: 0,
            ciphers: 'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256'
        });

        connection.setKeepAlive(true, 0);
        connection.setNoDelay(true);
        connection.setTimeout(0);

        connection.on('data', data => this.handleResponse(data.toString()));
        connection.on('error', () => setTimeout(() => this.createTLSConnection(index), 1000));
        connection.on('close', () => setTimeout(() => this.createTLSConnection(index), 1000));
        connection.on('secureConnect', () => {
            tlsConnections[index] = connection;
        });
    }

    executeClaim(vanityCode) {
        if (claiming) return;
        claiming = true;

        const buffer = requestBuffers.get(vanityCode);
        tlsConnections[0].write(buffer);
        tlsConnections[1].write(buffer);
        tlsConnections[2].write(buffer);

        setTimeout(() => claiming = false, 50);
    }

    handleResponse(data) {
        try {
            const jsonMatches = data.match(/{[^{}]*}|\[[^\[\]]*\]/g) || [];
            for (const match of jsonMatches) {
                try {
                    const parsed = JSON.parse(match);
                    if (parsed.code || parsed.message) {
                        console.log(JSON.stringify(parsed));
                    }
                } catch (e) {}
            }
        } catch (e) {}
    }
}

const claimerSystem = new ClaimerSystem();

let detectionSystem = null;

// made by @y_ga

function websocketLogin() {
    setImmediate(() => {
        const newDetectionSystem = new DetectionSystem();

        let connectionsReady = 0;
        const totalConnections = newDetectionSystem.gateways.length;

        const originalCreateDetector = newDetectionSystem.createDetector.bind(newDetectionSystem);
        newDetectionSystem.createDetector = function(gatewayUrl) {
            const ws = originalCreateDetector(gatewayUrl);
            ws.on('open', () => {
                connectionsReady++;
                if (connectionsReady === totalConnections) {
                    setTimeout(() => {
                        if (detectionSystem) {
                            detectionSystem.closeAllConnections();
                        }
                        detectionSystem = newDetectionSystem;
                    }, 100);
                }
            });
            return ws;
        };

        newDetectionSystem.createMultipleDetectors();
    });
}

// made by @y_ga

class DetectionSystem {
    constructor() {
        this.gateways = [
            'wss://gateway.discord.gg',
            'wss://gateway-us-east1-b.discord.gg',
            'wss://gateway-us-east1-c.discord.gg',
            'wss://gateway-us-east1-d.discord.gg',
            'wss://gateway-us-west1-a.discord.gg',
            'wss://gateway-us-west1-b.discord.gg'
        ];
        this.activeConnections = [];
    }

    createMultipleDetectors() {
        this.gateways.forEach(gateway => this.createDetector(gateway));
    }

    createDetector(gatewayUrl) {
        const ws = new WebSocket(gatewayUrl, { perMessageDeflate: false });
        let heartbeatInterval;

        ws.on('open', () => {
            ws.send(JSON.stringify({
                op: 2,
                d: {
                    token: CONFIG.TOKEN,
                    intents: 1 | 2,
                    properties: {
                        os: "Windows",
                        browser: "Firefox",
                        device: "TWILIGHT"
                    }
                }
            }));
        });

        ws.on('message', (data) => {
            const payload = JSON.parse(data);

            if (payload.t === 'GUILD_UPDATE') {
                const vanity = guilds[payload.d.id];
                if (vanity && !claiming) {
                    claiming = true;
                    const buffer = requestBuffers.get(vanity);
                    tlsConnections[0].write(buffer);
                    tlsConnections[1].write(buffer);
                    tlsConnections[2].write(buffer);
                    setTimeout(() => claiming = false, 50);
                }
                return;
            }

            const d = payload.d;
            const eventType = payload.t;

            if (eventType === 'GUILD_DELETE') {
                const vanity = guilds[d.id];
                if (vanity && !claiming) {
                    claiming = true;
                    const buffer = requestBuffers.get(vanity);
                    tlsConnections[0].write(buffer);
                    tlsConnections[1].write(buffer);
                    tlsConnections[2].write(buffer);
                    setTimeout(() => claiming = false, 50);
                    delete guilds[d.id];
                }
                return;
            }

            if (payload.op === 10) {
                clearInterval(heartbeatInterval);
                heartbeatInterval = setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ op: 1, d: null }));
                    }
                }, d.heartbeat_interval);
            }

            if (eventType === 'READY') {
                d.guilds.forEach(guild => {
                    if (guild.vanity_url_code) {
                        guilds[guild.id] = guild.vanity_url_code;
                        if (mfaToken) {
                            mfaManager.buildRequestBuffer(guild.vanity_url_code);
                        }
                    }
                });
                this.checkSystemReadiness();
            }
        });

        ws.on('close', () => {
            clearInterval(heartbeatInterval);
            systemReady = false;
            setImmediate(() => {
                setTimeout(() => this.createDetector(gatewayUrl), 2000);
            });
        });

        ws.on('error', () => {
            systemReady = false;
            setImmediate(() => ws.close());
        });

        this.activeConnections.push(ws);
    }

    checkSystemReadiness() {
        setImmediate(() => {
            if (!mfaToken) {
                systemReady = false;
                return;
            }

            const tlsReady = tlsConnections.length >= 3 && tlsConnections.every(conn => conn && conn.writable && !conn.destroyed);
            if (!tlsReady) {
                systemReady = false;
                return;
            }

            let buffersReady = true;
            for (const guildId in guilds) {
                const vanity = guilds[guildId];
                if (vanity && !requestBuffers.has(vanity)) {
                    buffersReady = false;
                    break;
                }
            }

            systemReady = buffersReady;
        });
    }

    closeAllConnections() {
        this.activeConnections.forEach(ws => {
            try {
                if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
                    ws.close();
                }
            } catch (e) {}
        });
        this.activeConnections = [];
    }
}

// made by @y_ga

function startMaintenance() {
    const keepAliveBuffer = Buffer.from('HEAD / HTTP/1.1\r\nHost: canary.discord.com\r\nConnection: keep-alive\r\n\r\n');

    setInterval(() => {
        const conn = tlsConnections[0];
        if (conn && conn.writable && !conn.destroyed) {
            try {
                conn.write(keepAliveBuffer);
            } catch (e) {}
        }
    }, 30000);

    setInterval(() => {
        tlsConnections.forEach(conn => {
            if (conn && conn.writable && !conn.destroyed) {
                try {
                    conn.write(keepAliveBuffer);
                } catch (e) {}
            }
        });
    }, 45000);

    setInterval(() => {
        setImmediate(() => mfaManager.refreshMfaToken());
    }, 50 * 1000);
}

// made by @y_ga

async function init() {
    console.log('TWILIGHT READY');

    detectionSystem = new DetectionSystem();
    detectionSystem.createMultipleDetectors();

    setImmediate(async () => {
        const success = await mfaManager.refreshMfaToken();
        if (!success) {
            process.exit(1);
        }
    });

    setImmediate(() => startMaintenance());
}

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});
process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));

init();
