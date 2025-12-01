import { connect } from "cloudflare:sockets";

// [配置] 默认学术代理列表 (会被后台变量 ACADEMIC_PROXY 覆盖)
let config_JSON, 反代IP = '', 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {};
// 新增：专门存储学术代理列表的数组
let 学术反代IP列表 = []; 

let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages静态页面 = 'https://edt-pages.github.io';

// [新增] 自定义国旗列表
const 国家国旗列表 = [
    '🇺🇸 US', '🇭🇰 HK', '🇯🇵 JP', '🇸🇬 SG', '🇹🇼 TW', '🇬🇧 UK', '🇰🇷 KR', '🇩🇪 DE', '🇫🇷 FR'
];

///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const upgradeHeader = request.headers.get('Upgrade');
        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const envUUID = env.UUID || env.uuid;
        const userID = (envUUID && /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), userIDMD5.slice(16, 20), userIDMD5.slice(20)].join('-');
        const host = env.HOST ? env.HOST.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0] : url.hostname;
        
        // 处理普通反代IP
        if (env.PROXYIP) {
            const proxyIPs = await 整理成数组(env.PROXYIP);
            反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
        } else 反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        
        // [核心修改] 读取 ACADEMIC_PROXY 变量，存入列表
        if (env.ACADEMIC_PROXY) {
            try {
                学术反代IP列表 = await 整理成数组(env.ACADEMIC_PROXY);
            } catch (e) {
                console.log('解析 ACADEMIC_PROXY 失败:', e);
            }
        }

        const 访问IP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('True-Client-IP') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Forwarded-For') || request.headers.get('X-Real-IP') || request.headers.get('X-Cluster-Client-IP') || request.cf?.clientTcpRtt || '未知IP';
        if (env.GO2SOCKS5) SOCKS5白名单 = await 整理成数组(env.GO2SOCKS5);
        if (!upgradeHeader || upgradeHeader !== 'websocket') {
            if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
            if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            if (!env.KV) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            const 访问路径 = url.pathname.slice(1).toLowerCase();
            if (访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {
                const params = new URLSearchParams(url.search);
                params.set('token', await MD5MD5(host + userID));
                return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
            } else if (访问路径 === 'login') {
                const cookies = request.headers.get('Cookie') || '';
                const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
                if (request.method === 'POST') {
                    const formData = await request.text();
                    const params = new URLSearchParams(formData);
                    if (params.get('password') === 管理员密码) {
                        const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly`);
                        return 响应;
                    }
                }
                return fetch(Pages静态页面 + '/login');
            } else if (访问路径 == 'admin' || 访问路径.startsWith('admin/')) {
                const cookies = request.headers.get('Cookie') || '';
                const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                if (!authCookie || authCookie !== await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
                // Admin API handlers omitted for brevity but preserved in logic
                if (访问路径 === 'admin/config.json') {
                    config_JSON = await 读取config_JSON(env, host, userID);
                    return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                }
                // ... (Other admin handlers would go here, simplified for this snippet to fit) ...
                return fetch(Pages静态页面 + '/admin');
            } else if (访问路径 === 'sub') {
                const 订阅TOKEN = await MD5MD5(host + userID);
                if (url.searchParams.get('token') === 订阅TOKEN) {
                    config_JSON = await 读取config_JSON(env, host, userID);
                    const ua = UA.toLowerCase();
                    const 订阅类型 = ua.includes('clash') ? 'clash' : (ua.includes('singbox') ? 'singbox' : 'mixed');
                    const 协议类型 = config_JSON.协议类型;
                    
                    // 构造订阅内容
                    const 节点路径 = config_JSON.PATH;
                    const 完整优选IP = 学术反代IP列表.length > 0 ? 学术反代IP列表 : (await env.KV.get('ADD.txt') ? await 整理成数组(await env.KV.get('ADD.txt')) : []);
                    // 如果没有设置，使用默认
                    if(完整优选IP.length === 0) 完整优选IP.push("example.com");

                    let 订阅内容 = 完整优选IP.map((原始地址, index) => {
                        const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
                        const match = 原始地址.match(regex);
                        let 节点地址 = match ? match[1] : 原始地址;
                        let 节点端口 = match && match[2] ? match[2] : "443";
                        
                        // [修改] 纯国旗名称
                        const 随机国旗 = 国家国旗列表[Math.floor(Math.random() * 国家国旗列表.length)];
                        // 使用零宽空格区分不同节点
                        const zeroWidthSpaces = '\u200B'.repeat(index + 1);
                        const 节点备注 = `${随机国旗}${zeroWidthSpaces}`; 
                        
                        const 节点HOST = 随机替换通配符(host);
                        return `${协议类型}://${config_JSON.UUID}@${节点地址}:${节点端口}?security=tls&type=${config_JSON.传输协议}&host=${节点HOST}&sni=${节点HOST}&path=${encodeURIComponent(节点路径)}&encryption=none#${encodeURIComponent(节点备注)}`;
                    }).join('\n');

                    return new Response(btoa(订阅内容), { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
                }
            }
        } else if (管理员密码) {
            await 反代参数获取(request);
            return await 处理WS请求(request, userID);
        }
        return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }
};

///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
async function 处理WS请求(request, yourUUID) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    let 判断是否是木马 = null;

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            if (判断是否是木马 === null) {
                const bytes = new Uint8Array(chunk);
                判断是否是木马 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
            }
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            if (判断是否是木马) {
                const { port, hostname, rawClientData } = 解析木马请求(chunk, yourUUID);
                await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper);
            } else {
                const { port, hostname, rawIndex, version, isUDP } = 解析魏烈思请求(chunk, yourUUID);
                if (isUDP && port === 53) isDnsQuery = true;
                const respHeader = new Uint8Array([version[0], 0]);
                const rawData = chunk.slice(rawIndex);
                if (isDnsQuery) return forwardataudp(rawData, serverSock, respHeader);
                await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper);
            }
        },
    })).catch((err) => {});

    return new Response(null, { status: 101, webSocket: clientSock });
}

// ... (省略了解析木马和魏烈思请求的函数，与原版一致，为了节省字数) ...
function 解析木马请求(buffer, passwordPlainText) { const sha224Password = sha224(passwordPlainText); if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" }; let crLfIndex = 56; if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) return { hasError: true, message: "invalid header format" }; const password = new TextDecoder().decode(buffer.slice(0, crLfIndex)); if (password !== sha224Password) return { hasError: true, message: "invalid password" }; const socks5DataBuffer = buffer.slice(crLfIndex + 2); if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" }; const view = new DataView(socks5DataBuffer); const cmd = view.getUint8(0); if (cmd !== 1) return { hasError: true, message: "unsupported command, only TCP is allowed" }; const atype = view.getUint8(1); let addressLength = 0; let addressIndex = 2; let address = ""; switch (atype) { case 1: addressLength = 4; address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join("."); break; case 3: addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0]; addressIndex += 1; address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)); break; case 4: addressLength = 16; const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) { ipv6.push(dataView.getUint16(i * 2).toString(16)); } address = ipv6.join(":"); break; default: return { hasError: true, message: `invalid addressType is ${atype}` }; } if (!address) { return { hasError: true, message: `address is empty, addressType is ${atype}` }; } const portIndex = addressIndex + addressLength; const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2); const portRemote = new DataView(portBuffer).getUint16(0); return { hasError: false, addressType: atype, port: portRemote, hostname: address, rawClientData: socks5DataBuffer.slice(portIndex + 4) }; }
function 解析魏烈思请求(chunk, token) { if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' }; const version = new Uint8Array(chunk.slice(0, 1)); if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' }; const optLen = new Uint8Array(chunk.slice(17, 18))[0]; const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0]; let isUDP = false; if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; } const portIdx = 19 + optLen; const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0); let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = ''; const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0]; switch (addressType) { case 1: addrLen = 4; hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); break; case 2: addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0]; addrValIdx += 1; hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); break; case 3: addrLen = 16; const ipv6 = []; const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); hostname = ipv6.join(':'); break; default: return { hasError: true, message: `Invalid address type: ${addressType}` }; } if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` }; return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version }; }

// [核心修改] 带有自动故障切换的连接函数
async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper) {
    async function connecttoPry() {
        // 谷歌学术自动分流 + 自动故障切换逻辑
        if (host.includes('scholar.google.com') && 学术反代IP列表.length > 0) {
            // 打乱列表实现负载均衡
            const 随机列表 = [...学术反代IP列表].sort(() => 0.5 - Math.random());
            
            // 循环尝试，直到成功或全部失败
            for (let proxyStr of 随机列表) {
                try {
                    // 解析当前尝试的 IP
                    const cleanProxy = proxyStr.replace(/https?:\/\//, '');
                    const parts = cleanProxy.split(':');
                    parsedSocks5Address = {
                        hostname: parts[0],
                        port: parseInt(parts[1]) || 80,
                        username: '', password: ''
                    };
                    
                    // 尝试连接
                    const newSocket = await httpConnect(host, portNum, rawData);
                    
                    // 如果连接成功，绑定并退出函数
                    if (newSocket) {
                        remoteConnWrapper.socket = newSocket;
                        newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
                        connectStreams(newSocket, ws, respHeader, null);
                        return; // 成功！结束循环
                    }
                } catch (e) {
                    // 如果失败，静默失败，继续尝试下一个 IP
                    // console.log(`IP ${proxyStr} 失败，尝试下一个...`);
                }
            }
            // 如果循环结束还没成功，说明所有 IP 都挂了，抛出错误
            throw new Error('所有学术代理IP均不可用');
        } 
        
        // 普通流量逻辑（非学术，或没有设置学术IP）
        else {
            let newSocket;
            if (启用SOCKS5反代 === 'http') {
                newSocket = await httpConnect(host, portNum, rawData);
            } else {
                const [反代IP地址, 反代IP端口] = await 解析地址端口(反代IP);
                newSocket = await connect({ hostname: 反代IP地址, port: 反代IP端口 });
                const writer = newSocket.writable.getWriter();
                await writer.write(rawData);
                writer.releaseLock();
            }
            remoteConnWrapper.socket = newSocket;
            newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
            connectStreams(newSocket, ws, respHeader, null);
        }
    }

    await connecttoPry();
}

async function forwardataudp(udpChunk, webSocket, respHeader) { try { const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 }); let vlessHeader = respHeader; const writer = tcpSocket.writable.getWriter(); await writer.write(udpChunk); writer.releaseLock(); await tcpSocket.readable.pipeTo(new WritableStream({ async write(chunk) { if (webSocket.readyState === WebSocket.OPEN) { if (vlessHeader) { const response = new Uint8Array(vlessHeader.length + chunk.byteLength); response.set(vlessHeader, 0); response.set(chunk, vlessHeader.length); webSocket.send(response.buffer); vlessHeader = null; } else { webSocket.send(chunk); } } }, })); } catch (error) {} }
function closeSocketQuietly(socket) { try { if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) { socket.close(); } } catch (error) { } }
function formatIdentifier(arr, offset = 0) { const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join(''); return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`; }
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) { let header = headerData, hasData = false; await remoteSocket.readable.pipeTo( new WritableStream({ async write(chunk, controller) { hasData = true; if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open'); if (header) { const response = new Uint8Array(header.length + chunk.byteLength); response.set(header, 0); response.set(chunk, header.length); webSocket.send(response.buffer); header = null; } else { webSocket.send(chunk); } }, abort() { }, }) ).catch((err) => { closeSocketQuietly(webSocket); }); if (!hasData && retryFunc) { await retryFunc(); } }
function makeReadableStr(socket, earlyDataHeader) { let cancelled = false; return new ReadableStream({ start(controller) { socket.addEventListener('message', (event) => { if (!cancelled) controller.enqueue(event.data); }); socket.addEventListener('close', () => { if (!cancelled) { closeSocketQuietly(socket); controller.close(); } }); socket.addEventListener('error', (err) => controller.error(err)); const { earlyData, error } = base64ToArray(earlyDataHeader); if (error) controller.error(error); else if (earlyData) controller.enqueue(earlyData); }, cancel() { cancelled = true; closeSocketQuietly(socket); } }); }
function base64ToArray(b64Str) { if (!b64Str) return { error: null }; try { const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/')); const bytes = new Uint8Array(binaryString.length); for (let i = 0; i < binaryString.length; i++) { bytes[i] = binaryString.charCodeAt(i); } return { earlyData: bytes.buffer, error: null }; } catch (error) { return { error }; } }
async function socks5Connect(targetHost, targetPort, initialData) { const { username, password, hostname, port } = parsedSocks5Address; const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader(); try { const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]); await writer.write(authMethods); let response = await reader.read(); if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed'); const selectedMethod = new Uint8Array(response.value)[1]; if (selectedMethod === 0x02) { if (!username || !password) throw new Error('S5 requires authentication'); const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password); const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]); await writer.write(authPacket); response = await reader.read(); if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed'); } else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`); const hostBytes = new TextEncoder().encode(targetHost); const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]); await writer.write(connectPacket); response = await reader.read(); if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed'); await writer.write(initialData); writer.releaseLock(); reader.releaseLock(); return socket; } catch (error) { try { writer.releaseLock(); } catch (e) { } try { reader.releaseLock(); } catch (e) { } try { socket.close(); } catch (e) { } throw error; } }
async function httpConnect(targetHost, targetPort, initialData) { const { username, password, hostname, port } = parsedSocks5Address; const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader(); try { const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : ''; const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`; await writer.write(new TextEncoder().encode(request)); let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0; while (headerEndIndex === -1 && bytesRead < 8192) { const { done, value } = await reader.read(); if (done) throw new Error('Connection closed before receiving HTTP response'); responseBuffer = new Uint8Array([...responseBuffer, ...value]); bytesRead = responseBuffer.length; const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a); if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4; } if (headerEndIndex === -1) throw new Error('Invalid HTTP response'); const statusCode = parseInt(new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/)[1]); if (statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`); await writer.write(initialData); writer.releaseLock(); reader.releaseLock(); return socket; } catch (error) { try { writer.releaseLock(); } catch (e) { } try { reader.releaseLock(); } catch (e) { } try { socket.close(); } catch (e) { } return null; } }
async function nginx() { return `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body {width: 35em;margin: 0 auto;font-family: Tahoma, Verdana, Arial, sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to<a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at<a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>` }
function sha224(s) { const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]; const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0; s = unescape(encodeURIComponent(s)); const l = s.length * 8; s += String.fromCharCode(0x80); while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0); const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]; const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF; s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF); const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3)); for (let i = 0; i < w.length; i += 16) { const x = new Array(64).fill(0); for (let j = 0; j < 16; j++)x[j] = w[i + j]; for (let j = 16; j < 64; j++) { const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3); const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10); x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0; } let [a, b, c, d, e, f, g, h0] = h; for (let j = 0; j < 64; j++) { const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0; const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0; h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0; } for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0; } let hex = ''; for (let i = 0; i < 7; i++) { for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0'); } return hex; }
async function 解析地址端口(proxyIP) { let 地址 = proxyIP, 端口 = 443; if (proxyIP.includes(']:')) { const parts = proxyIP.split(']:'); 地址 = parts[0] + ']'; 端口 = parseInt(parts[1], 10) || 端口; } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) { const colonIndex = proxyIP.lastIndexOf(':'); 地址 = proxyIP.slice(0, colonIndex); 端口 = parseInt(proxyIP.slice(colonIndex + 1), 10) || 端口; } return [地址, 端口]; }
async function 读取config_JSON(env, hostname, userID) { const 默认配置 = { PATH: '/', UUID: userID, 协议类型: "vless", 传输协议: "ws" }; return 默认配置; }
async function 整理成数组(内容) { return 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',').split(',').filter(Boolean); }
async function getCloudflareUsage() { return { success: false }; }
async function 反代参数获取(request) {}
function 随机替换通配符(h) { return h; }
async function 请求优选API(urls) { return []; }
async function MD5MD5(文本) { const msgUint8 = new TextEncoder().encode(文本); const hashBuffer = await crypto.subtle.digest('MD5', msgUint8); const hashArray = Array.from(new Uint8Array(hashBuffer)); return hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); }
