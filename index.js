const fs = require("fs");
const net = require("net");
const path = require("path");
const child_process = require("child_process");
const { EventEmitter } = require("events");
const crypto = require("crypto");
const http = require("http");
const url = require("url");
const stream = require("stream");

function parseConf(content) {
    const out = {};
    let section = null;
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const sectionMatch = trimmed.match(/^\[([a-zA-Z0-9]+)\]$/);
        if (sectionMatch) {
            section = sectionMatch[1];
            if (!out[section]) out[section] = {};
            continue;
        }
        const eq = trimmed.indexOf("=");
        if (eq === -1) continue;
        const key = trimmed.slice(0, eq).trim();
        let value = trimmed.slice(eq + 1).trim();
        if ((key === "key" && (value === "" || value === "null")) || value === "null") value = null;
        else if (value === "") value = "";
        else if (/^\d+$/.test(value)) value = parseInt(value, 10);
        else if (value === "true") value = true;
        else if (value === "false") value = false;
        if (section) out[section][key] = value;
        else out[key] = value;
    }
    return out;
}

const configPath = path.join(__dirname, "config.conf");
const defaults = {
    mappingFile: "mapping.txt",
    host: { directIp: "10.0.200.50", accessIp: "" },
    api: { port: 3000, key: null, pingTimeoutMs: 5000, scanTimeoutMs: 2000 },
    log: { level: "INFO", format: "text" },
    server: { bindAddress: "0.0.0.0", upstreamTimeoutMs: 10000 },
    metrics: { intervalMs: 60000 },
    iptables: { chainName: "NATASHAA_PRE", nflogGroup: "1", multiportChunkSize: 15 },
    ulog: { logPath: "/var/log/ulog/syslogemu.log", watchIntervalMs: 1000 },
    ports: { availableMin: 1024, availableMax: 65535, availableListMax: 100, availableResponseLimit: 50 },
    version: "2.0.0"
};

let config;
try {
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = parseConf(raw);
    config = { ...defaults };
    if (parsed.host) config.host = { ...defaults.host, ...parsed.host };
    if (parsed.api) config.api = { ...defaults.api, ...parsed.api };
    if (parsed.log) config.log = { ...defaults.log, ...parsed.log };
    if (parsed.server) config.server = { ...defaults.server, ...parsed.server };
    if (parsed.metrics) config.metrics = { ...defaults.metrics, ...parsed.metrics };
    if (parsed.iptables) config.iptables = { ...defaults.iptables, ...parsed.iptables };
    if (parsed.ulog) config.ulog = { ...defaults.ulog, ...parsed.ulog };
    if (parsed.ports) config.ports = { ...defaults.ports, ...parsed.ports };
    if (parsed.mappingFile !== undefined) config.mappingFile = parsed.mappingFile;
} catch (e) {
    config = JSON.parse(JSON.stringify(defaults));
}

config.api.key = process.env.API_KEY || config.api.key || crypto.randomBytes(32).toString("hex");
config.api.port = parseInt(process.env.API_PORT, 10) || config.api.port;
config.log.level = process.env.LOG_LEVEL || config.log.level;
config.log.format = process.env.LOG_FORMAT || config.log.format;
config.host.directIp = process.env.HOST_DIRECT_IP || config.host.directIp;
config.host.accessIp = process.env.HOST_ACCESS_IP || config.host.accessIp;

const mappingFilePath = path.isAbsolute(config.mappingFile)
    ? config.mappingFile
    : path.join(__dirname, config.mappingFile);

const logLevels = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

let currentMapping = new Map();
let activeServers = new Map();
let connectionStats = new Map();
let apiServer = null;
const streamMonitor = new EventEmitter();

if (!process.env.API_KEY) {
    console.log(`\x1b[33m[SECURITY] Current API key: ${config.api.key}\x1b[0m`);
    console.log("\x1b[33m[SECURITY] Set API_KEY env or api.key in config.conf for production!\x1b[0m");
}

function formatTimestamp() {
    return new Date().toISOString();
}

function shouldLog(level) {
    return logLevels[level] >= logLevels[config.log.level];
}

const logger = {
    formatLog(level, module, operation, message, metadata = {}) {
        const timestamp = formatTimestamp();
        const logEntry = {
            timestamp,
            level,
            module,
            operation,
            message,
            metadata,
            pid: process.pid,
            version: config.version
        };
        if (config.log.format === "json") {
            console.log(JSON.stringify(logEntry));
            return;
        }
        const colorCodes = {
            DEBUG: "\x1b[36m",
            INFO: "\x1b[32m",
            WARN: "\x1b[33m",
            ERROR: "\x1b[31m",
            FATAL: "\x1b[35m"
        };
        const resetCode = "\x1b[0m";
        const color = colorCodes[level] || "";
        const moduleFormatted = `[${module.padEnd(12)}]`;
        const operationFormatted = operation ? `::${operation.padEnd(15)}` : "";
        const prefix = `${color}${timestamp} ${level.padEnd(5)} ${moduleFormatted}${operationFormatted}${resetCode}`;
        if (Object.keys(metadata).length > 0) {
            console.log(`${prefix} ${message}`, metadata);
        } else {
            console.log(`${prefix} ${message}`);
        }
    },
    debug(module, operation, message, metadata) {
        if (shouldLog("DEBUG")) this.formatLog("DEBUG", module, operation, message, metadata);
    },
    info(module, operation, message, metadata) {
        if (shouldLog("INFO")) this.formatLog("INFO", module, operation, message, metadata);
    },
    warn(module, operation, message, metadata) {
        if (shouldLog("WARN")) this.formatLog("WARN", module, operation, message, metadata);
    },
    error(module, operation, message, metadata) {
        if (shouldLog("ERROR")) this.formatLog("ERROR", module, operation, message, metadata);
    },
    fatal(module, operation, message, metadata) {
        this.formatLog("FATAL", module, operation, message, metadata);
    }
};

function createConnectionId() {
    return crypto.randomBytes(8).toString("hex");
}

function getConnectionStats(port) {
    if (!connectionStats.has(port)) {
        connectionStats.set(port, {
            activeConnections: 0,
            totalConnections: 0,
            bytesTransferred: 0,
            errors: 0,
            lastActivity: null
        });
    }
    return connectionStats.get(port);
}

function updateStats(port, action, bytes = 0) {
    const stats = getConnectionStats(port);
    stats.lastActivity = new Date();
    switch (action) {
        case "connect":
            stats.activeConnections++;
            stats.totalConnections++;
            break;
        case "disconnect":
            stats.activeConnections = Math.max(0, stats.activeConnections - 1);
            break;
        case "data":
            stats.bytesTransferred += bytes;
            break;
        case "error":
            stats.errors++;
            break;
    }
}

function parseMappingFileContent(content) {
    const newMapping = new Map();
    const lines = content.split(/\r?\n/);
    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        if (line.startsWith("#")) continue;
        const match = line.match(/^(\d{1,5})\s*->\s*([A-Za-z0-9.\-]+):(\d{1,5})$/);
        if (!match) {
            logger.warn("CONFIG", "parse_mapping", "Invalid mapping line ignored", { line });
            continue;
        }
        const sourcePort = parseInt(match[1], 10);
        const destinationHost = match[2];
        const destinationPort = parseInt(match[3], 10);
        if (sourcePort < 1 || sourcePort > 65535) continue;
        if (destinationPort < 1 || destinationPort > 65535) continue;
        newMapping.set(sourcePort, { destinationHost, destinationPort });
    }
    currentMapping = newMapping;
    logger.info("CONFIG", "load_mapping", "Port mapping configuration loaded successfully", {
        mappings_count: currentMapping.size,
        mappings: Array.from(currentMapping.entries()).map(([port, dest]) => `${port}->${dest.destinationHost}:${dest.destinationPort}`)
    });
}

function loadMappingFileOnce() {
    try {
        const content = fs.readFileSync(mappingFilePath, "utf8");
        parseMappingFileContent(content);
    } catch (e) {
        logger.error("CONFIG", "load_mapping", "Failed to read mapping configuration file", {
            file: mappingFilePath,
            error: String(e)
        });
        currentMapping = new Map();
    }
}

function watchMappingFile() {
    fs.watchFile(mappingFilePath, { interval: config.ulog.watchIntervalMs }, () => {
        try {
            const content = fs.readFileSync(mappingFilePath, "utf8");
            parseMappingFileContent(content);
            rebuildServers();
            rebuildIptablesRules();
        } catch (e) {
            logger.error("CONFIG", "reload_mapping", "Failed to reload mapping configuration", {
                error: String(e)
            });
        }
    });
}

function detectSSHTraffic(data, connectionId) {
    if (data.length < 4) return false;
    const sshSignatures = [Buffer.from("SSH-"), Buffer.from("\x00\x00\x00")];
    for (const signature of sshSignatures) {
        if (data.indexOf(signature) === 0) {
            logger.info("PROTOCOL", "ssh_detect", "SSH traffic detected", {
                connection_id: connectionId,
                signature: signature.toString("hex"),
                data_preview: data.slice(0, 32).toString("hex")
            });
            return true;
        }
    }
    return false;
}

function analyzeSSHHandshake(data, connectionId, direction) {
    if (data.length < 10) return;
    try {
        if (data.toString().startsWith("SSH-")) {
            const version = data.toString().split("\r\n")[0];
            logger.info("PROTOCOL", "ssh_handshake", "SSH handshake detected", {
                connection_id: connectionId,
                direction,
                version,
                timestamp: new Date().toISOString()
            });
        }
        if (data[0] === 0x00 && data.length > 8) {
            const packetLength = data.readUInt32BE(0);
            logger.debug("PROTOCOL", "ssh_packet", "Encrypted SSH packet", {
                connection_id: connectionId,
                direction,
                packet_length: packetLength,
                data_size: data.length
            });
        }
    } catch (e) {
        logger.debug("PROTOCOL", "ssh_analysis_error", "SSH analysis failed", {
            connection_id: connectionId,
            error: String(e)
        });
    }
}

function createMonitoredStream(source, destination, connectionId, direction) {
    let totalBytes = 0;
    let isSSHConnection = false;
    let packetCount = 0;
    const port = connectionId.split("-")[0];

    const transform = new stream.Transform({
        transform(chunk, encoding, callback) {
            totalBytes += chunk.length;
            packetCount++;
            updateStats(port, "data", chunk.length);

            if (!isSSHConnection && packetCount <= 5) {
                isSSHConnection = detectSSHTraffic(chunk, connectionId);
            }
            if (isSSHConnection) {
                analyzeSSHHandshake(chunk, connectionId, direction);
            }

            logger.debug("STREAM", "data_transfer", "Data packet transferred", {
                connection_id: connectionId,
                direction,
                packet_bytes: chunk.length,
                total_bytes: totalBytes,
                packet_count: packetCount,
                is_ssh: isSSHConnection
            });

            streamMonitor.emit("data", {
                connectionId,
                direction,
                bytes: chunk.length,
                timestamp: new Date(),
                isSSH: isSSHConnection,
                packetCount
            });

            callback(null, chunk);
        }
    });

    source.pipe(transform).pipe(destination);

    source.on("end", () => {
        logger.debug("STREAM", "stream_closed", "Data stream closed", {
            connection_id: connectionId,
            direction,
            total_bytes: totalBytes,
            packet_count: packetCount,
            was_ssh: isSSHConnection
        });
    });

    return { transform, totalBytes: () => totalBytes, isSSH: () => isSSHConnection };
}

function createServerForPort(port, destinationHost, destinationPort) {
    if (activeServers.has(port)) return;
    const server = net.createServer((clientSocket) => {
        const clientAddress = clientSocket.remoteAddress;
        const clientPort = clientSocket.remotePort;
        const connectionId = `${port}-${createConnectionId()}`;

        updateStats(port, "connect");

        logger.info("CONNECTION", "client_connected", "Incoming connection established", {
            connection_id: connectionId,
            client_address: clientAddress,
            client_port: clientPort,
            source_port: port,
            connection_stats: getConnectionStats(port)
        });

        let targetHost = destinationHost;
        let targetPort = destinationPort;
        if (config.host.accessIp && destinationHost === config.host.directIp) targetHost = config.host.accessIp;

        const upstream = net.createConnection({ host: targetHost, port: targetPort });
        upstream.setTimeout(config.server.upstreamTimeoutMs);

        upstream.on("connect", () => {
            logger.info("CONNECTION", "tunnel_established", "Tunnel connection established successfully", {
                connection_id: connectionId,
                client_endpoint: `${clientAddress}:${clientPort}`,
                source_port: port,
                target_endpoint: `${targetHost}:${targetPort}`,
                tunnel_ready: true
            });
            createMonitoredStream(clientSocket, upstream, connectionId, "client->server");
            createMonitoredStream(upstream, clientSocket, connectionId, "server->client");
        });

        upstream.on("timeout", () => {
            updateStats(port, "error");
            logger.warn("CONNECTION", "upstream_timeout", "Connection timeout to upstream server", {
                connection_id: connectionId,
                source_port: port,
                target_endpoint: `${targetHost}:${targetPort}`,
                timeout_duration: config.server.upstreamTimeoutMs
            });
            try {
                upstream.destroy();
            } catch {}
            try {
                clientSocket.destroy();
            } catch {}
        });

        upstream.on("error", (error) => {
            updateStats(port, "error");
            logger.error("CONNECTION", "upstream_error", "Upstream connection failed", {
                connection_id: connectionId,
                source_port: port,
                target_endpoint: `${targetHost}:${targetPort}`,
                error: String(error)
            });
            try {
                clientSocket.destroy();
            } catch {}
        });

        clientSocket.on("error", (error) => {
            updateStats(port, "error");
            logger.error("CONNECTION", "client_error", "Client connection error", {
                connection_id: connectionId,
                error: String(error)
            });
            try {
                upstream.destroy();
            } catch {}
        });

        clientSocket.on("close", () => {
            updateStats(port, "disconnect");
            logger.debug("CONNECTION", "client_disconnected", "Client connection closed", {
                connection_id: connectionId,
                final_stats: getConnectionStats(port)
            });
            try {
                upstream.destroy();
            } catch {}
        });

        upstream.on("close", () => {
            logger.debug("CONNECTION", "upstream_disconnected", "Upstream connection closed", {
                connection_id: connectionId
            });
            try {
                clientSocket.destroy();
            } catch {}
        });
    });

    server.on("error", (error) => {
        logger.error("SERVER", "listen_error", "Server listen error", {
            source_port: port,
            error: String(error)
        });
    });

    server.listen(port, config.server.bindAddress, () => {
        logger.info("SERVER", "listening", "Server listening on port", {
            source_port: port,
            target_endpoint: `${destinationHost}:${destinationPort}`,
            bind_address: config.server.bindAddress
        });
    });

    activeServers.set(port, server);
}

function closeServerForPort(port) {
    const server = activeServers.get(port);
    if (!server) return;
    const stats = getConnectionStats(port);
    try {
        server.close(() => {
            logger.info("SERVER", "stopped", "Server stopped listening", {
                source_port: port,
                final_stats: stats
            });
        });
    } catch (e) {
        logger.error("SERVER", "stop_error", "Error stopping server", {
            source_port: port,
            error: String(e)
        });
    }
    connectionStats.delete(port);
    activeServers.delete(port);
}

function rebuildServers() {
    const desiredPorts = new Set(currentMapping.keys());
    for (const [port] of activeServers) {
        if (!desiredPorts.has(port)) closeServerForPort(port);
    }
    for (const [port, dest] of currentMapping) {
        createServerForPort(port, dest.destinationHost, dest.destinationPort);
    }
}

function executeCommand(command) {
    try {
        child_process.execSync(command, { stdio: "pipe" });
        logger.debug("SYSTEM", "command_executed", "System command executed successfully", { command });
    } catch (e) {
        logger.error("SYSTEM", "command_failed", "System command execution failed", {
            command,
            error: String(e.stderr || e)
        });
        throw e;
    }
}

function ensureIptablesChainExists() {
    executeCommand(`iptables -N ${config.iptables.chainName} || true`);
    executeCommand(`iptables -F ${config.iptables.chainName} || true`);
    executeCommand(`iptables -C INPUT -p tcp --syn -j ${config.iptables.chainName} || iptables -I INPUT 1 -p tcp --syn -j ${config.iptables.chainName}`);
}

function chunkArray(array, size) {
    const output = [];
    for (let i = 0; i < array.length; i += size) {
        output.push(array.slice(i, i + size));
    }
    return output;
}

function rebuildIptablesRules() {
    ensureIptablesChainExists();
    executeCommand(`iptables -F ${config.iptables.chainName}`);
    const mappedPorts = Array.from(currentMapping.keys()).sort((a, b) => a - b);
    if (mappedPorts.length > 0) {
        const chunks = chunkArray(mappedPorts, config.iptables.multiportChunkSize);
        for (const chunk of chunks) {
            const list = chunk.join(",");
            executeCommand(`iptables -A ${config.iptables.chainName} -p tcp --syn -m multiport --dports ${list} -j RETURN`);
        }
    }
    executeCommand(`iptables -A ${config.iptables.chainName} -p tcp --syn -j NFLOG --nflog-group ${config.iptables.nflogGroup} --nflog-prefix "NATASHAA_NOMAP "`);
    logger.info("IPTABLES", "rules_rebuilt", "Iptables rules rebuilt successfully", {
        mapped_ports_count: mappedPorts.length,
        mapped_ports: mappedPorts
    });
}

function authenticateRequest(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return { valid: false, error: "Missing authorization header" };
    }
    const [scheme, token] = authHeader.split(" ");
    if (scheme !== "Bearer" || token !== config.api.key) {
        return { valid: false, error: "Invalid API key" };
    }
    return { valid: true };
}

function sendJSON(res, statusCode, data) {
    res.writeHead(statusCode, {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    });
    res.end(JSON.stringify(data, null, 2));
}

function parseRequestBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";
        req.on("data", (chunk) => {
            body += chunk.toString();
        });
        req.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (e) {
                reject(new Error("Invalid JSON"));
            }
        });
        req.on("error", reject);
    });
}

async function pingHost(host, timeout = config.api.pingTimeoutMs) {
    return new Promise((resolve) => {
        const start = Date.now();
        const socket = new net.Socket();
        socket.setTimeout(timeout);
        socket.on("connect", () => {
            const duration = Date.now() - start;
            socket.destroy();
            resolve({ available: true, response_time: duration });
        });
        socket.on("timeout", () => {
            socket.destroy();
            resolve({ available: false, error: "timeout" });
        });
        socket.on("error", (err) => {
            resolve({ available: false, error: err.message });
        });
        socket.connect(22, host);
    });
}

function getPortStatistics() {
    const stats = {};
    for (const [port, data] of connectionStats) {
        stats[port] = {
            ...data,
            uptimeMs: data.lastActivity ? new Date() - data.lastActivity : 0
        };
    }
    return stats;
}

function logPerformanceMetrics() {
    const stats = getPortStatistics();
    const totalStats = {
        total_ports: Object.keys(stats).length,
        total_active_connections: Object.values(stats).reduce((sum, s) => sum + s.activeConnections, 0),
        total_connections: Object.values(stats).reduce((sum, s) => sum + s.totalConnections, 0),
        total_bytes_transferred: Object.values(stats).reduce((sum, s) => sum + s.bytesTransferred, 0),
        total_errors: Object.values(stats).reduce((sum, s) => sum + s.errors, 0)
    };
    logger.info("METRICS", "performance_report", "System performance metrics", {
        timestamp: new Date().toISOString(),
        ...totalStats,
        port_details: stats
    });
}

const apiHandlers = {
    "/api/status": {
        GET: (req, res) => {
            const stats = getPortStatistics();
            const response = {
                status: "running",
                version: config.version,
                uptime: process.uptime(),
                mappings: Array.from(currentMapping.entries()).map(([port, dest]) => ({
                    source_port: port,
                    destination_host: dest.destinationHost,
                    destination_port: dest.destinationPort,
                    stats: stats[port] || null
                })),
                global_stats: {
                    total_ports: Object.keys(stats).length,
                    total_active_connections: Object.values(stats).reduce((sum, s) => sum + s.activeConnections, 0),
                    total_connections: Object.values(stats).reduce((sum, s) => sum + s.totalConnections, 0),
                    total_bytes_transferred: Object.values(stats).reduce((sum, s) => sum + s.bytesTransferred, 0),
                    total_errors: Object.values(stats).reduce((sum, s) => sum + s.errors, 0)
                }
            };
            sendJSON(res, 200, response);
        }
    },

    "/api/mappings": {
        GET: (req, res) => {
            const mappings = Array.from(currentMapping.entries()).map(([port, dest]) => {
                const stats = getConnectionStats(port);
                return {
                    source_port: port,
                    destination_host: dest.destinationHost,
                    destination_port: dest.destinationPort,
                    active: activeServers.has(port),
                    statistics: {
                        active_connections: stats.activeConnections,
                        total_connections: stats.totalConnections,
                        bytes_transferred: stats.bytesTransferred,
                        errors: stats.errors,
                        last_activity: stats.lastActivity
                    }
                };
            });
            sendJSON(res, 200, { mappings });
        },

        POST: async (req, res) => {
            try {
                const body = await parseRequestBody(req);
                const { source_port, destination_host, destination_port } = body;
                if (!source_port || !destination_host || !destination_port) {
                    return sendJSON(res, 400, {
                        error: "Missing required fields: source_port, destination_host, destination_port"
                    });
                }
                if (currentMapping.has(source_port)) {
                    return sendJSON(res, 409, { error: `Port ${source_port} already mapped` });
                }
                currentMapping.set(source_port, {
                    destinationHost: destination_host,
                    destinationPort: destination_port
                });
                createServerForPort(source_port, destination_host, destination_port);
                rebuildIptablesRules();
                logger.info("API", "mapping_created", "New port mapping created", {
                    source_port,
                    destination: `${destination_host}:${destination_port}`
                });
                sendJSON(res, 201, {
                    message: "Mapping created successfully",
                    mapping: { source_port, destination_host, destination_port }
                });
            } catch (e) {
                logger.error("API", "mapping_create_error", "Failed to create mapping", { error: e.message });
                sendJSON(res, 500, { error: "Internal server error" });
            }
        },

        DELETE: async (req, res) => {
            try {
                const urlParts = url.parse(req.url, true);
                const port = parseInt(urlParts.query.port);
                if (!port || !currentMapping.has(port)) {
                    return sendJSON(res, 404, { error: "Port mapping not found" });
                }
                const mapping = currentMapping.get(port);
                currentMapping.delete(port);
                closeServerForPort(port);
                rebuildIptablesRules();
                logger.info("API", "mapping_deleted", "Port mapping removed", {
                    source_port: port,
                    destination: `${mapping.destinationHost}:${mapping.destinationPort}`
                });
                sendJSON(res, 200, { message: "Mapping deleted successfully" });
            } catch (e) {
                logger.error("API", "mapping_delete_error", "Failed to delete mapping", { error: e.message });
                sendJSON(res, 500, { error: "Internal server error" });
            }
        }
    },

    "/api/network/ping": {
        POST: async (req, res) => {
            try {
                const body = await parseRequestBody(req);
                const { host, timeout = config.api.pingTimeoutMs } = body;
                if (!host) {
                    return sendJSON(res, 400, { error: "Host parameter required" });
                }
                const result = await pingHost(host, timeout);
                logger.debug("API", "network_ping", "Host connectivity check", { host, result });
                sendJSON(res, 200, {
                    host,
                    ...result,
                    timestamp: new Date().toISOString()
                });
            } catch (e) {
                logger.error("API", "ping_error", "Network ping failed", { error: e.message });
                sendJSON(res, 500, { error: "Internal server error" });
            }
        }
    },

    "/api/network/scan": {
        POST: async (req, res) => {
            try {
                const body = await parseRequestBody(req);
                const { network } = body;
                if (!network) {
                    return sendJSON(res, 400, { error: "Network parameter required (e.g., 192.168.1)" });
                }
                const promises = [];
                for (let i = 1; i <= 254; i++) {
                    const host = `${network}.${i}`;
                    promises.push(
                        pingHost(host, config.api.scanTimeoutMs).then((result) => ({ host, ...result }))
                    );
                }
                const pingResults = await Promise.all(promises);
                const availableHosts = pingResults.filter((r) => r.available);
                logger.info("API", "network_scan", "Network scan completed", {
                    network,
                    available_hosts: availableHosts.length,
                    total_scanned: 254
                });
                sendJSON(res, 200, {
                    network,
                    available_hosts: availableHosts,
                    scan_summary: {
                        total_scanned: 254,
                        available: availableHosts.length,
                        unavailable: 254 - availableHosts.length
                    },
                    timestamp: new Date().toISOString()
                });
            } catch (e) {
                logger.error("API", "scan_error", "Network scan failed", { error: e.message });
                sendJSON(res, 500, { error: "Internal server error" });
            }
        }
    },

    "/api/ports": {
        GET: (req, res) => {
            const urlParts = url.parse(req.url, true);
            const port = urlParts.query.port;
            if (port) {
                const portNum = parseInt(port);
                const mapping = currentMapping.get(portNum);
                const stats = getConnectionStats(portNum);
                if (!mapping) {
                    return sendJSON(res, 404, { error: "Port not found" });
                }
                sendJSON(res, 200, {
                    port: portNum,
                    destination_host: mapping.destinationHost,
                    destination_port: mapping.destinationPort,
                    active: activeServers.has(portNum),
                    statistics: stats
                });
            } else {
                const usedPorts = Array.from(currentMapping.keys());
                const availablePorts = [];
                const { availableMin, availableMax, availableListMax, availableResponseLimit } = config.ports;
                for (let p = availableMin; p <= availableMax; p++) {
                    if (!usedPorts.includes(p) && availablePorts.length < availableListMax) {
                        availablePorts.push(p);
                    }
                }
                sendJSON(res, 200, {
                    used_ports: usedPorts.sort((a, b) => a - b),
                    available_ports: availablePorts.slice(0, availableResponseLimit),
                    total_used: usedPorts.length,
                    suggested_next: availablePorts[0] || null
                });
            }
        }
    }
};

function createAPIServer() {
    apiServer = http.createServer(async (req, res) => {
        const startTime = Date.now();
        const method = req.method;
        const pathname = url.parse(req.url).pathname;

        logger.debug("API", "request", "API request received", {
            method,
            path: pathname,
            user_agent: req.headers["user-agent"],
            remote_ip: req.headers["x-forwarded-for"] || req.connection.remoteAddress
        });

        if (method === "OPTIONS") {
            return sendJSON(res, 200, {});
        }

        const auth = authenticateRequest(req);
        if (!auth.valid) {
            logger.warn("API", "auth_failed", "Authentication failed", {
                path: pathname,
                error: auth.error,
                remote_ip: req.headers["x-forwarded-for"] || req.connection.remoteAddress
            });
            return sendJSON(res, 401, { error: auth.error });
        }

        const handler = apiHandlers[pathname];
        if (!handler || !handler[method]) {
            return sendJSON(res, 404, {
                error: "Endpoint not found",
                available_endpoints: Object.keys(apiHandlers)
            });
        }

        try {
            await handler[method](req, res);
            const duration = Date.now() - startTime;
            logger.debug("API", "request_completed", "API request completed", {
                method,
                path: pathname,
                duration_ms: duration
            });
        } catch (error) {
            logger.error("API", "request_error", "API request failed", {
                method,
                path: pathname,
                error: error.message
            });
            sendJSON(res, 500, { error: "Internal server error" });
        }
    });

    apiServer.listen(config.api.port, () => {
        logger.info("API", "startup", "REST API server started", {
            port: config.api.port,
            endpoints: Object.keys(apiHandlers)
        });
    });

    apiServer.on("error", (error) => {
        logger.error("API", "server_error", "API server error", { error: error.message });
    });
}

function startUlogTail() {
    const logPath = config.ulog.logPath;
    const logDir = path.dirname(logPath);
    try {
        fs.mkdirSync(logDir, { recursive: true });
    } catch {}
    try {
        const tail = child_process.spawn("bash", ["-lc", `touch ${logPath} && tail -F ${logPath}`], {
            stdio: ["ignore", "pipe", "pipe"]
        });
        tail.stdout.on("data", (d) => {
            logger.warn("FIREWALL", "unmapped_connection", "Unmapped connection attempt detected", {
                raw_log: String(d).trim(),
                timestamp: formatTimestamp()
            });
        });
        tail.stderr.on("data", (d) => {
            logger.error("FIREWALL", "ulog_error", "ULOG tail process error", {
                error: String(d).trim()
            });
        });
    } catch (e) {
        logger.error("FIREWALL", "ulog_startup_failed", "Failed to start ULOG tail process", {
            error: String(e)
        });
    }
}

function startUlogd() {
    try {
        const proc = child_process.spawn("bash", ["-lc", "ulogd -d"], {
            stdio: ["ignore", "pipe", "pipe"]
        });
        proc.stdout.on("data", (d) => {
            logger.debug("FIREWALL", "ulogd_output", "ULOGD daemon output", {
                output: String(d).trim()
            });
        });
        proc.stderr.on("data", (d) => {
            logger.error("FIREWALL", "ulogd_error", "ULOGD daemon error", {
                error: String(d).trim()
            });
        });
    } catch (e) {
        logger.error("FIREWALL", "ulogd_startup_failed", "Failed to start ULOGD daemon", {
            error: String(e)
        });
    }
}

function main() {
    logger.info("SYSTEM", "startup", "NATashaa initialization started", {
        version: config.version,
        log_level: config.log.level,
        host_direct_ip: config.host.directIp,
        host_access_ip: config.host.accessIp || "not_defined",
        api_port: config.api.port,
        pid: process.pid,
        node_version: process.version,
        platform: process.platform
    });

    if (process.platform !== "linux") {
        logger.warn("SYSTEM", "limited_mode", "Not Linux: iptables and ULOG are disabled. TCP forwarding and API work; firewall/unmapped-connection logs are unavailable.", {
            platform: process.platform
        });
    }

    if (process.platform === "linux") {
        startUlogd();
        startUlogTail();
    }
    loadMappingFileOnce();
    rebuildServers();
    if (process.platform === "linux") {
        rebuildIptablesRules();
    }
    watchMappingFile();
    createAPIServer();

    setInterval(() => {
        logPerformanceMetrics();
    }, config.metrics.intervalMs);

    process.on("SIGINT", () => {
        logger.info("SYSTEM", "shutdown", "Graceful shutdown requested", {
            final_stats: getPortStatistics(),
            uptime: process.uptime()
        });
        if (apiServer) {
            apiServer.close(() => {
                logger.info("API", "shutdown", "API server stopped");
                process.exit(0);
            });
        } else {
            process.exit(0);
        }
    });

    process.on("uncaughtException", (error) => {
        logger.fatal("SYSTEM", "uncaught_exception", "Uncaught exception occurred", {
            error: error.message,
            stack: error.stack
        });
        process.exit(1);
    });

    process.on("unhandledRejection", (reason, promise) => {
        logger.fatal("SYSTEM", "unhandled_rejection", "Unhandled promise rejection", {
            reason: String(reason),
            promise: String(promise)
        });
        process.exit(1);
    });

    logger.info("SYSTEM", "startup_complete", "NATashaa started successfully", {
        active_ports: Array.from(activeServers.keys()),
        total_mappings: currentMapping.size,
        api_endpoints: Object.keys(apiHandlers),
        ready: true
    });
}

main();
