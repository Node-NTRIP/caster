/*
 * This file is part of the @ntrip/caster distribution (https://github.com/node-ntrip/caster).
 * Copyright (c) 2020 Nebojsa Cvetkovic.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

import {NtripHTTPParser} from '../..';
NtripHTTPParser.verify();

import {Caster, CasterTransportDefinition, CasterTransportInterface} from '../../caster';
import {Transport} from '../transport'
import {AuthCredentials, AuthRequest, AuthResponse} from '../../auth';
import {NtripRtpMessageType, NtripRtpSession, RtpPacket} from '../../util/rtp';
import {Client, Connection, Server} from '../../connection';
import {Sourcetable} from "../../sourcetable";

import dgram = require('dgram');
import http = require('http');
import https = require('https');
import stream = require('stream');
import tls = require('tls');
import url = require('url');

import {IncomingMessage, OutgoingHttpHeaders, ServerResponse} from 'http';
import {ParsedUrlQuery} from 'querystring';
import {TLSSocket} from 'tls';
import {UrlWithParsedQuery} from 'url';
import VError from 'verror';

export enum NtripVersion {
    V1 = 1,
    V2 = 2
}

const STATUS_CODES: {[code: number]: string | undefined} = {
    454: "Session Not Found",
    455: "Method Not Valid in This State",
    459: "Aggregate Operation Not Allowed",
    461: "Unsupported Transport"
};

/** @see c10410.1 NTRIP v2.0 - 2.6.2, 2.6.3 */
const NTRIP_HEADERS = ['ntrip-gga', 'ntrip-version', 'ntrip-str', 'ntrip-flags', 'str', 'source-agent'];
const NTRIP_FLAGS = ['st_auth', 'st_strict', 'st_match', 'st_filter', 'rtsp', 'plain_rtp'];

const NTRIP_RTP_PACKET_TIMESTAMP_PERIOD_NS = 125000;

export interface NtripTransportOptions {
    port: number;
    tls?: tls.SecureContextOptions & tls.TlsOptions;

    protocols?: {
        http?: boolean;
        rtsp?: boolean;
        rtp?: boolean;
    },

    versions?: {
        [NtripVersion.V1]?: boolean;
        [NtripVersion.V2]?: boolean;
    }

    browserFavicon?: () => Buffer;
    browserStreamAccess?: boolean;
}

export interface NtripTransportConnectionProperties {
    protocol: 'http' | 'https' | 'rtsp' | 'rtsps' | 'rtp';

    remote: {
        host: string;
        port: number;
        family: string;
    };

    agent?: string;

    version: NtripVersion;

    toString: () => string;
}

interface RtpSessionInfo {
    session: NtripRtpSession,
    type: 'server' | 'client',
    mountpoint: string,
    connection?: Connection
}

function newClientError(info: object, cause: Error | undefined, message: string, ...params: any[]): Error {
    return new VError({
        name: 'ClientError',
        info: info,
        cause: cause
    }, message, ...params);
}

/**
 * NTRIP caster server for HTTP/RTSP/Plain-RTP
 */
export class NtripTransport extends Transport {
    /** HTTP(S) server for accepting HTTP and RTSP connections, as well as injected plain RTP connections */
    private server!: http.Server | https.Server;

    /** UDP server for plain RTP connections (array to accept socket for IPv4 and IPv6) */
    private plainRtpSocket?: dgram.Socket;

    /** Map of remote addresses to UDP sockets if plainRtpSocket intercepts (happens on Windows) TODO: remove */
    private plainRtpClientSockets?: Map<string, dgram.Socket> = new Map();

    /** Map of session numbers to RTP sessions */
    private readonly rtpSessions: Map<number, RtpSessionInfo> = new Map();

    /** Transport options */
    private readonly options: NtripTransportOptions = {
        port: -1,
        protocols: {
            http: true,
            rtsp: true,
            rtp: true
        },
        versions: {
            [NtripVersion.V1]: true,
            [NtripVersion.V2]: true
        },
        browserStreamAccess: false
    }

    get description(): string {
        let tls = this.options.tls !== undefined;
        let protocols = [];
        if (this.options.protocols?.http) protocols.push('http' + (tls ? 's' : ''));
        if (this.options.protocols?.rtsp) protocols.push('rtsp' + (tls ? 's' : ''));
        if (this.options.protocols?.rtp) protocols.push('rtp');
        return `ntrip[${protocols.join(',')},port=${this.options.port}]`;
    }

    connectionDescription(source: any): string {
        return `${source.protocol}://${source.remote.host}:${source.remote.port}`;
    }

    protected constructor(manager: CasterTransportInterface, options: NtripTransportOptions) {
        super(manager, options);
        Object.assign(this.options, options);

        // Ensure at least one protocol is enabled
        if (!this.options.protocols?.http && !this.options.protocols?.rtsp && !this.options.protocols?.rtp)
            throw new Error("No protocols enabled");

        // Plain RTP does not work with TLS TODO: Node.js DTLS?
        if (this.options.protocols?.rtp && this.options.tls !== undefined)
            throw new Error("Plain RTP protocol is not supported when using TLS (HTTPS/RTSPS)");
    }

    static new(options: NtripTransportOptions): CasterTransportDefinition {
        return (caster: CasterTransportInterface) => new NtripTransport(caster, options);
    }

    open(): void {
        let openServer: Promise<void> | null = null;
        let openPlainRtpSocket: Promise<void> | null = null;

        // HTTP(S) server (used in all protocols)
        this.server = (this.options.tls !== undefined ? https : http).createServer({
            IncomingMessage: NtripCasterRequest,
            ServerResponse: NtripCasterResponse,
            ...this.options.tls
        });
        this.server.on('request', (req, res) => this.accept(req, res));
        this.server.keepAliveTimeout = 10000;
        this.server.timeout = 10000;

        // Client error handling
        this.server.on('clientError', (err, socket) => {
            this.emit('clientError', newClientError({
                remote: {
                    host: socket.remoteAddress,
                    port: socket.remotePort,
                    family: socket.remoteFamily
                }
            }, err, "HTTP server client error"));

            if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        });

        // Bind to port only if HTTP or RTSP are being used (RTP connections are injected manually)
        if (this.options.protocols?.http || this.options.protocols?.rtsp) {
            openServer = new Promise((resolve, reject) => {
                this.server.once('listening', resolve);
                this.server.once('error', reject);
            });

            this.server.listen(this.options.port);
        }

        // Plain RTP socket
        if (this.options.protocols?.rtp) {
            this.plainRtpClientSockets = new Map();
            this.plainRtpSocket = dgram.createSocket({
                type: 'udp6',
                reuseAddr: true
            });
            this.plainRtpSocket.on('message', (message, remote) => this.message(message, remote));

            openPlainRtpSocket = new Promise((resolve, reject) => {
                this.plainRtpSocket!.once('listening', resolve);
                this.plainRtpSocket!.once('error', reject);
            });

            this.plainRtpSocket.bind(this.options.port);
        }

        // Wait for server and socket to open
        Promise.all([openServer, openPlainRtpSocket])
            .then(() => this.emit('open'));
    }

    close(): void {
        const closeServer = this.server === undefined ? null
            : new Promise(resolve => this.server?.close(resolve));
        const closePlainRtpSocket = this.plainRtpSocket === undefined ? null
            : new Promise(resolve => this.plainRtpSocket?.close(resolve));

        // Wait for server and socket to close
        Promise.all([closeServer, closePlainRtpSocket])
            .then(() => this.emit('close'))
            .catch(err => this.emit('error', err)); // TODO
    }

    private async accept(req: NtripCasterRequest, res: NtripCasterResponse): Promise<void> {
        // Detect HTTP/RTSP/RTP
        req.protocol = (req.headers['@protocol'] as string ?? 'HTTP').toLowerCase();

        // Parse URL
        if (req.url != undefined) req.query = url.parse(req.url, true, false);
        req.mountpoint = req.query!.pathname!.slice(1);
        if (req.mountpoint.length === 0) req.mountpoint = null;

        // Remote host
        req.remote = {
            host: req.socket.remoteAddress!,
            port: req.socket.remotePort!,
            family: req.socket.remoteFamily!
        };

        // Detect NTRIP version
        const headerVersion = singularHeader(req.headers['ntrip-version'])?.toLowerCase();
        if (headerVersion === 'ntrip/1.0') req.ntripVersion = NtripVersion.V1;
        else if (headerVersion === 'ntrip/2.0') req.ntripVersion = NtripVersion.V2;

        // Detect user agent
        req.agent = req.headers['user-agent'];
        if (req.agent === undefined && req.method === 'SOURCE')
            req.agent = singularHeader(req.headers['source-agent']);

        // Begin forming auth request
        req.authRequest = {
            mountpoint: req.mountpoint,

            host: req.headers.host ?? null,
            source: req.remote,

            credentials: NtripTransport.parseCredentials(req)
        };

        if (!this.options.protocols?.[req.protocol as 'http' | 'rtsp' | 'rtp']) {
            res.error(501);
            this.emit('clientError', newClientError({remote: req.remote}, undefined, "Protocol requested by client is disabled"));
        } else if (req.protocol === 'http') {
            await new NtripTransport.HttpRequestProcessor(this, req, res).accept();
        } else if (req.protocol === 'rtsp') {
            await new NtripTransport.RtspRequestProcessor(this, req, res).accept();
        } else if (req.protocol === 'rtp') {
            await new NtripTransport.RtpRequestProcessor(this, req, res).accept();
        } else {
            res.error(400);
        }
    }

    private message(message: Buffer, remote: {address: string, port: number, family: string}): void {
        // If a client is already listening on this remote, inject the message to its own socket
        const client = this.plainRtpClientSockets!.get(remote.address + ':' + remote.port);
        if (client !== undefined) {
            client.emit('message', message, remote);
            return;
        }

        const emitClientError = (message: string, error?: Error) => {
            this.emit('clientError', newClientError({
                remote: remote
            }, error, message));
        }

        let packet: RtpPacket;
        try {
            packet = RtpPacket.fromBuffer(message);
        } catch (error) {
            return emitClientError("RTP: Invalid packet received on plain RTP socket", error);
        }

        if (packet.payloadType != NtripRtpMessageType.HTTP || packet.payload == null)
            return emitClientError("RTP: Unknown packet type or empty payload received on plain RTP socket");

        // Replace protocol (HTTP) with RTP
        let request: string = packet.payload.toString();
        const requestStatusEnd = request.indexOf('\r\n');
        request = request.slice(0, request.lastIndexOf(' ', requestStatusEnd) + 1)
                + 'RTP/1.1' + request.slice(requestStatusEnd);

        const socket = this.plainRtpSocket!;
        const time = process.hrtime.bigint();
        const connection = new stream.Duplex({
            read(): void {},
            write(chunk: any, encoding: string, callback: (error?: (Error | null)) => void): void {
                if (typeof chunk === 'string')
                    chunk = Buffer.from(chunk as string, encoding as BufferEncoding);

                // Since SSRC of response is tied to sequence/timestamp, return appropriately incremented values
                const sequenceNumber = (packet.sequenceNumber + 1) % 0xffff;
                const timestamp = (packet.timestamp + (Number(process.hrtime.bigint() - time)
                        / NTRIP_RTP_PACKET_TIMESTAMP_PERIOD_NS)) % 0xffffffff;

                const response = new RtpPacket({
                    payloadType: NtripRtpMessageType.HTTP,
                    sequenceNumber: sequenceNumber,
                    timestamp: timestamp,
                    ssrc: packet.ssrc,
                    payload: chunk
                });

                // Send response and destroy stream
                socket.send(RtpPacket.toBuffer(response), remote.port, remote.address, (error: Error | null) => {
                    callback(error);

                    // Stream is no longer needed, and RTP session may have been made
                    this.destroy();
                });
            }
        });
        connection.push(request);
        (connection as any).remoteAddress = remote.address;
        (connection as any).remotePort = remote.port;
        (connection as any).remoteFamily = remote.family;

        // Inject connection to server to parse HTTP request
        this.server.emit('connection', connection);
    }

    /**
     * Abstract request instance processor
     *
     * Mainly used to improve organization of code and avoid complex function names for various combinations of
     * protocols and versions. Request processors are initially created by {@link NtripTransport#accept}.
     *
     * Contains properties for reference to the parent transport, overall caster manager, and request/response objects.
     */
    private static RequestProcessor = class RequestProcessor {
        protected transport: NtripTransport;
        protected manager: CasterTransportInterface;

        protected req: NtripCasterRequest;
        protected res: NtripCasterResponse;

        constructor(parent: NtripTransport | RequestProcessor, req?: NtripCasterRequest, res?: NtripCasterResponse) {
            if (parent instanceof RequestProcessor) {
                this.transport = parent.transport;
                this.manager = parent.manager;
                this.req = parent.req;
                this.res = parent.res;
            } else {
                this.transport = parent;
                this.manager = parent.caster;
                this.req = req!;
                this.res = res!;
            }
        };

        protected async authenticate() {
            this.req.authResponse = await this.manager.authenticate(this.req.authRequest!);
            return this.req.authResponse.authenticated;
        }

        protected connect(params: {
            type: 'server' | 'client'

            input?: stream.Readable,
            output?: stream.Writable,
            stream?: stream.Duplex
        }): Connection {
            let protocol = this.req.protocol.toLowerCase();
            if (this.transport.options.tls !== undefined && (protocol === 'http' || protocol === 'rtsp')) protocol += 's';

            const source: NtripTransportConnectionProperties = {
                protocol: protocol as 'http' | 'https' | 'rtsp' | 'rtsps' | 'rtp',
                version: this.req.ntripVersion!,
                remote: this.req.remote!,
                agent: this.req.agent,
                toString: () => this.transport.connectionDescription(source)
            };

            return this.transport.connect({
                ...params,
                source: source,
                mountpoint: this.req.mountpoint as string,

                gga: this.req.ntripGga,
                str: this.req.ntripStr
            });
        }
    };

    /** HTTP request instance processor */
    private static HttpRequestProcessor = class HttpRequestProcessor extends NtripTransport.RequestProcessor {
        async accept() {
            // Determine whether the connection is from an NTRIP agent or a browser
            this.req.ntripAgent = true;
            const headerAgent = this.req.headers['user-agent']?.toUpperCase();
            // If User-Agent is provided but doesn't start with NTRIP, and no NTRIP
            // specific headers are present, assume connection is from browser
            if (!NTRIP_HEADERS.some(h => h in this.req.headers) && !(headerAgent?.startsWith('NTRIP') ?? true)) {
                this.req.ntripAgent = false;
                // Browsers default to V2
                this.req.ntripVersion = NtripVersion.V2;

                // Special case for favicon.ico
                if (this.req.mountpoint === 'favicon.ico') {
                    const favicon = this.transport.options.browserFavicon;
                    if (favicon !== undefined) return this.res.end(favicon());
                    else return this.res.error(404);
                }

                // Redirect to sourcetable unless browser stream access is requested
                if (this.transport.options.browserStreamAccess) this.req.mountpoint = null;
            }

            // Default to V1 if not defined
            if (this.req.ntripVersion === null) this.req.ntripVersion = NtripVersion.V1;

            // Do not allow disabled versions
            if (this.transport.options.versions?.[this.req.ntripVersion] === false)
                return this.res.error(501);

            if (this.req.ntripVersion === NtripVersion.V1) {
                await new HttpRequestProcessor.V1Processor(this).accept();
            } else if (this.req.ntripVersion === NtripVersion.V2) {
                await new HttpRequestProcessor.V2Processor(this).accept();
            } else {
                this.res.error(501);
            }
        }

        /** HTTP NTRIP v1.0 request instance processor */
        private static V1Processor = class V1Processor extends NtripTransport.RequestProcessor {
            async accept() {
                this.res.statusVersion = 'ICY';
                this.res.removeHeader('Content-Length');
                this.res.removeHeader('Transfer-Encoding');
                this.res.removeHeader('Connection');
                this.res.sendDate = false;

                if (this.req.method === 'SOURCE') {
                    await this.acceptServer();
                } else if (this.req.method === 'GET') {
                    await this.acceptClient();
                } else {
                    this.res.error(405);
                }
            }

            private async acceptServer() {
                this.req.authRequest!.type = 'server';

                // Can't push to /
                if (this.req.mountpoint === null) return this.res.error(400);

                // Secret moved to header by NtripHTTPParser
                this.req.authRequest!.credentials.secret = singularHeader(this.req.headers['ntrip-source-secret'])!;
                this.req.authRequest!.credentials.anonymous = false;

                // Optional sourcetable entry
                this.req.ntripStr = singularHeader(this.req.headers['str']);

                if (!(await this.authenticate())) return this.res.error(401);

                // Remove listeners set by HTTP server (would return 400 Bad Request on data)
                this.req.socket.removeAllListeners('data');

                try {
                    this.connect({
                        type: 'server',
                        input: this.req.socket,
                        output: this.res.socket
                    });
                } catch (err) {
                    return this.res.error(500); // TODO
                }

                // Remove listeners set by HTTP server (would return 400 Bad Request on data)
                this.req.socket.removeAllListeners('data');

                // Flush headers to confirm connection
                this.res.flushHeaders();
            }

            private async acceptClient() {
                this.req.authRequest!.type = 'client';

                // Respond with sourcetable
                if (this.req.mountpoint === null) return this.printSourcetable();

                if (!(await this.authenticate())) return this.res.error(401);

                try {
                    this.connect({
                        type: 'client',
                        input: this.req.socket,
                        output: this.res.socket
                    });
                } catch (err) {
                    return this.res.error(500);
                }

                // Remove listeners set by HTTP server (would return 400 Bad Request on data)
                this.req.socket.removeAllListeners('data');

                // Flush headers to confirm connection
                this.res.flushHeaders();
            }

            private printSourcetable() {
                this.res.statusVersion = 'SOURCETABLE';
                this.res.setHeader('Connection', 'close');
                this.res.setHeader('Server', 'NTRIP ' + Caster.NAME + '/1.0');
                this.res.setHeader('Content-Type', 'text/plain');
                this.res.sendDate = true;
                this.res.end(this.transport.getSourcetable(this.req.query?.query));
            }
        };

        /** HTTP NTRIP v2.0 request instance processor */
        private static V2Processor = class V2Processor extends NtripTransport.RequestProcessor {
            async accept(): Promise<void> {
                this.res.setHeader('Connection', 'close');
                this.res.setHeader('Ntrip-Version', 'Ntrip/2.0');
                this.res.setHeader('Ntrip-Flags', NTRIP_FLAGS.join(','));
                this.res.setHeader('Server', 'NTRIP ' + Caster.NAME);

                if (this.req.method === 'POST') {
                    await this.acceptServer();
                } else if (this.req.method === 'GET') {
                    await this.acceptClient();
                } else {
                    this.res.error(405);
                }
            }

            private async acceptServer(): Promise<void> {
                this.req.authRequest!.type = 'server';

                // Can't push to /
                if (this.req.mountpoint === null) return this.res.error(400);

                // Optional sourcetable entry
                this.req.ntripStr = singularHeader(this.req.headers['ntrip-str']);

                // Authenticate
                if (!(await this.authenticate())) {
                    this.res.setHeader('WWW-Authenticate', `Basic realm="/${this.req.mountpoint}"`);
                    return this.res.error(401, `Mountpoint ${this.req.mountpoint} requires authentication, or provided credentials were invalid`);
                }

                try {
                    this.connect({
                        type: 'server',
                        input: this.req,
                        output: this.res
                    });
                } catch (err) {
                    return this.res.error(500);
                }

                // Flush headers to confirm connection
                this.res.flushHeaders();
            }

            private async acceptClient(): Promise<void> {
                this.req.authRequest!.type = 'client';

                // Respond with sourcetable
                if (this.req.mountpoint === null) return this.printSourcetable();

                // Client position for NMEA-requesting mountpoints
                this.req.ntripGga = singularHeader(this.req.headers['ntrip-gga']);

                // Authenticate
                if (!(await this.authenticate())) {
                    this.res.setHeader('WWW-Authenticate', `Basic realm="/${this.req.mountpoint}"`);
                    return this.res.error(401, `Mountpoint ${this.req.mountpoint} requires authentication, or provided credentials were invalid`);
                }

                try {
                    this.connect({
                        type: 'client',
                        input: this.req.socket, // Output is chunked but input is raw
                        output: this.res
                    });
                } catch (err) {
                    return this.res.error(500);
                }

                // Remove listeners set by HTTP server (would return 400 Bad Request on data)
                this.req.socket.removeAllListeners('data');

                // Flush headers to confirm connection
                this.res.setHeader('Cache-Control', 'no-store, no-cache, max-age=0');
                this.res.setHeader('Content-Type', this.req.ntripAgent ? 'gnss/data' : 'text/plain');
                if (!this.req.ntripAgent) this.res.setHeader('X-Content-Type-Options', 'nosniff');
                this.res.flushHeaders();
            }

            private async printSourcetable(): Promise<void> {
                let sourcetable;
                try {
                    sourcetable = await this.transport.getSourcetable(this.req.query?.query);
                } catch (error) {
                    return this.res.error(400, `Error filtering sourcetable: ${error.message}`);
                }

                this.res.setHeader('Content-Type', this.req.ntripAgent ? 'gnss/sourcetable' : 'text/plain');
                this.res.end(sourcetable);
            }
        };
    };

    /** RTSP request instance processor */
    private static RtspRequestProcessor = class RtspRequestProcessor extends NtripTransport.RequestProcessor {
        async accept() {
            this.res.statusVersion = 'RTSP/1.0';

            this.res.setHeader('CSeq', this.req.headers['cseq'] ?? 0);
            this.res.removeHeader('Content-Length');
            this.res.removeHeader('Transfer-Encoding');
            this.res.removeHeader('Connection');

            // Always set timeout to 60 seconds after request ends
            this.res.on('finish', () => {
                // Use process to next tick to set timeout after internal set timeout call
                process.nextTick(() => this.req.socket.setTimeout(20000));
            });

            // Default to V2 if not defined
            if (this.req.ntripVersion === null) this.req.ntripVersion = NtripVersion.V2;

            // Do not allow disabled versions
            if (this.transport.options.versions?.[this.req.ntripVersion] === false)
                return this.res.error(501);

            if (this.req.ntripVersion === NtripVersion.V2) {
                await new RtspRequestProcessor.V2Processor(this).accept();
            } else {
                this.res.error(501);
            }
        }

        /** RTSP NTRIP v2.0 request instance processor */
        private static V2Processor = class V2Processor extends NtripTransport.RequestProcessor  {
            async accept(): Promise<void> {
                const session = Number(this.req.headers['session']);
                if (!isNaN(session)) this.req.rtpSession = this.transport.rtpSessions.get(session);

                if (this.req.method === 'SETUP') {
                    await this.setup();
                } else if (['RECORD', 'PLAY', 'TEARDOWN', 'GET_PARAMETER'].includes(this.req.method!)) {
                    this.command();
                } else {
                    this.res.error(405);
                }
            }

            private async setup() {
                // Can't setup new connection if already set up
                if (this.req.rtpSession !== undefined) return this.res.error(459);

                this.res.setHeader('Ntrip-Version', 'Ntrip/2.0');
                this.res.setHeader('Ntrip-Flags', NTRIP_FLAGS.join(','));
                this.res.setHeader('Server', 'NTRIP ' + Caster.NAME);

                const component = singularHeader(this.req.headers['ntrip-component'])?.toLowerCase();
                if (component === undefined)
                    return this.res.error(400, "Ntrip-Component header not included in request"); // TODO

                // Parse transport header, verify RTP/GNSS and client port are present
                this.req.rtspTransportParams = singularHeader(this.req.headers['transport'])
                        ?.toLowerCase()
                        .split(';');
                this.req.rtpRemotePort = Number(this.req.rtspTransportParams
                        ?.find(p => /^client_port=\d+$/.test(p))
                        ?.slice('client_port='.length));
                if (!this.req.rtspTransportParams?.includes('rtp/gnss') || isNaN(this.req.rtpRemotePort))
                    return this.res.error(461);

                if (!['ntripclient', 'ntripserver'].includes(component))
                    return this.res.error(400, "Invalid Ntrip-Component header sent");

                this.req.authRequest!.type = component === 'ntripclient' ? 'client' : 'server';

                // Authenticate
                if (!(await this.authenticate())) return this.res.error(401);

                this.req.rtpSocket = dgram.createSocket({
                    type: 'udp6',
                    reuseAddr: true
                });

                try {
                    await new Promise((resolve, reject) => {
                        this.req.rtpSocket!.once('connect', resolve);
                        this.req.rtpSocket!.once('error', reject);

                        this.req.rtpSocket!.connect(this.req.rtpRemotePort!, this.req.remote!.host);
                    });
                } catch (err) {
                    this.setupError(err);
                }

                await this.setupSocket();
            }

            private setupSocket() {
                const session = new NtripRtpSession(this.req.rtpSocket!);

                // Keep regenerating SSRC until unused
                while (this.transport.rtpSessions.has(session.ssrc)) session.regenerateSsrc();
                this.req.rtpSession = {
                    session: session,
                    type: this.req.authRequest!.type!,
                    mountpoint: this.req.mountpoint!
                };
                this.transport.rtpSessions.set(session.ssrc, this.req.rtpSession);
                session.on('close', () => {
                    this.transport.rtpSessions.delete(session.ssrc);
                    this.res.socket.destroy();
                });

                this.res.setHeader('Transport', this.req.rtspTransportParams!
                        .filter(p => !/^server_port=.*$/.test(p))
                        .concat('server_port=' + this.req.rtpSocket!.address().port)
                        .join(';'));

                this.res.setHeader('Session', session.ssrc);
                this.res.setHeader('Connection', 'keep-alive');
                this.res.end();
            }

            private setupError(err: Error) {
                this.req.rtpSocket!.close();
                this.res.error(500);

                this.transport.emit('clientError', newClientError({
                    remote: {
                        ...this.req.remote,
                        port: this.req.rtpRemotePort
                    }
                }, err,"RTP: Could not connect to client RTP port"));
            }

            private command() {
                // Active connection must be available
                if (this.req.rtpSession === undefined) return this.res.error(454);

                this.res.setHeader('Session', this.req.rtpSession.session.ssrc);
                this.res.setHeader('Connection', 'keep-alive');
                this.res.sendDate = false;

                if (this.req.method === 'RECORD' || this.req.method === 'PLAY')
                    return this.start();

                if (this.req.method === 'TEARDOWN') {
                    this.req.rtpSession.session.end();
                    this.transport.rtpSessions.delete(this.req.rtpSession.session.ssrc);

                    this.res.setHeader('Connection', 'close');
                } else if (this.req.method === 'GET_PARAMETER') {
                    // Allow clients to update their location with Ntrip-GGA
                    if (this.req.rtpSession.type === 'client') {
                        const gga = singularHeader(this.req.headers['ntrip-gga']);
                        const connection = this.req.rtpSession.connection as Client;
                        if (gga !== undefined && connection !== undefined) connection.gga = gga;
                    }
                }

                // Flush headers to confirm connection
                this.res.end();
            }

            private start() {
                let type: 'server' | 'client';
                if (this.req.method === 'RECORD') {
                    type = 'server';

                    // Optional sourcetable entry
                    this.req.ntripStr = singularHeader(this.req.headers['ntrip-str']);
                } else if (this.req.method === 'PLAY') {
                    type = 'client';

                    // Client position for NMEA-requesting mountpoints
                    this.req.ntripGga = singularHeader(this.req.headers['ntrip-gga']);
                } else {
                    return this.res.error(405);
                }

                if (this.req.rtpSession?.type != type) return this.res.error(455);

                try {
                    this.req.rtpSession.connection = this.connect({
                        type: type,
                        stream: this.req.rtpSession!.session.dataStream
                    });
                } catch (err) {
                    return this.res.error(500);
                }

                // Flush headers to confirm connection
                this.res.end();
            }
        };
    };

    /** RTP request instance processor */
    private static RtpRequestProcessor = class RtpRequestProcessor extends NtripTransport.RequestProcessor {
        async accept() {
            // Default to V2 if not defined
            if (this.req.ntripVersion === null) this.req.ntripVersion = NtripVersion.V2;

            // Do not allow disabled versions
            if (this.transport.options.versions?.[this.req.ntripVersion] === false)
                return this.res.error(501);

            if (this.req.ntripVersion === NtripVersion.V2) {
                await new RtpRequestProcessor.V2Processor(this).accept();
            } else {
                this.res.error(501);
            }
        }

        /** RTP NTRIP v2.0 request instance processor */
        private static V2Processor = class V2Processor extends NtripTransport.RequestProcessor {
            async accept(): Promise<void> {
                this.res.removeHeader('Connection');
                this.res.setHeader('Ntrip-Version', 'Ntrip/2.0');
                this.res.setHeader('Ntrip-Flags', NTRIP_FLAGS.join(','));
                this.res.setHeader('Server', 'NTRIP ' + Caster.NAME);

                if (this.req.method === 'POST') {
                    this.req.authRequest!.type = 'server';

                    // Optional sourcetable entry
                    this.req.ntripStr = singularHeader(this.req.headers['ntrip-str']);
                } else if (this.req.method === 'GET') {
                    this.req.authRequest!.type = 'client';

                    // Client position for NMEA-requesting mountpoints
                    this.req.ntripGga = singularHeader(this.req.headers['ntrip-gga']);
                } else {
                    return this.res.error(405);
                }

                // Authenticate
                if (!(await this.authenticate())) return this.res.error(401);

                this.req.rtpSocket = dgram.createSocket({
                    type: 'udp6',
                    reuseAddr: true
                });

                try {
                    await new Promise((resolve, reject) => {
                        this.req.rtpSocket!.once('connect', resolve);
                        this.req.rtpSocket!.once('error', reject);

                        // Bind to chosen port and then connect to client
                        this.req.rtpSocket!.bind(this.transport.options.port, undefined, () => {
                            this.req.rtpSocket!.connect(this.req.remote!.port, this.req.remote!.host);
                        });
                    });
                } catch (err) {
                    this.setupError(err);
                }

                await this.setupSocket();
            }

            private setupSocket() {
                const remote = this.req.remote!.host + ':' + this.req.remote!.port;
                this.transport.plainRtpClientSockets!.set(remote, this.req.rtpSocket!);
                this.req.rtpSocket!.on('close', () => this.transport.plainRtpClientSockets!.delete(remote));

                const session = new NtripRtpSession(this.req.rtpSocket!);

                // Keep regenerating SSRC until unused
                while (this.transport.rtpSessions.has(session.ssrc)) session.regenerateSsrc();
                this.req.rtpSession = {
                    session: session,
                    type: this.req.authRequest!.type!,
                    mountpoint: this.req.mountpoint!
                };
                this.transport.rtpSessions.set(session.ssrc, this.req.rtpSession);
                session.on('close', () => this.transport.rtpSessions.delete(session.ssrc));

                this.res.setHeader('Session', session.ssrc);

                try {
                    this.connect({
                        type: this.req.authRequest!.type!,
                        stream: this.req.rtpSession!.session.dataStream
                    });
                } catch (err) {
                    return this.res.error(500);
                }

                if (this.req.authRequest!.type === 'client') this.res.setHeader('Content-Type', 'gnss/data');

                // Flush headers to confirm connection
                this.res.end();

                // Send keep-alive message every 20 seconds to avoid disconnection
                setInterval(() => this.req.rtpSession?.session.dataStream.write(''), 20000);
            }

            private setupError(err: Error) {
                this.req.rtpSocket!.close();
                this.res.error(500);

                this.transport.emit('clientError', newClientError({
                    remote: {
                        ...this.req.remote,
                        port: this.req.rtpRemotePort
                    }
                }, err,"RTSP: Could not connect to client RTP port"));
            }
        };
    };

    private getSourcetable(query?: ParsedUrlQuery): Promise<string> {
        // Parse filters if provided
        let filters: Sourcetable.Filters | undefined;
        if (query !== undefined) {
            let {auth, strict, match, filter}: any = query;
            if (auth !== undefined) auth = !!auth;
            if (strict !== undefined) strict = !!strict;
            if (match !== undefined) match = ((match instanceof Array) ? match : [match])
                .map(filters => filters.split(';'));

            if (filter !== undefined) filter = ((filter instanceof Array) ? filter : [filter])
                .map(filters => filters.split(';'))
                .map(Sourcetable.parseAdvancedFilters);

            filters = {
                auth: auth,
                strict: strict,
                simple: match,
                advanced: filter
            };
        }

        return this.caster.generateSourcetable(filters);
    }

    private static parseCredentials(req: NtripCasterRequest): AuthCredentials {
        const credentials: AuthCredentials = {};

        credentials.anonymous = true;

        // Basic authentication
        if (req.headers['authorization']?.startsWith('Basic ')) {
            credentials.anonymous = false;

            let basic = req.headers['authorization'].slice('Basic '.length);
            basic = Buffer.from(basic, 'base64').toString();
            let separator = basic.indexOf(':');
            if (separator >= 0) {
                credentials.basic = {
                    username: basic.slice(0, separator),
                    password: basic.slice(separator + 1)
                }
            }
        } else if (req.headers['authorization']?.startsWith('Bearer ')) {
            credentials.anonymous = false;

            credentials.bearer = req.headers['authorization'].slice('Bearer '.length);
        }

        // TLS client certificate
        if (req.socket instanceof TLSSocket) {
            credentials.anonymous = false;

            credentials.certificate = req.socket.getPeerCertificate().fingerprint;
        }

        return credentials;
    }
}

class NtripCasterRequest extends IncomingMessage {
    protocol!: string;
    remote?: {
        host: string;
        port: number;
        family: string;
    };

    mountpoint: string | null = null;

    ntripVersion: NtripVersion | null = null;
    ntripAgent: boolean = false;

    ntripGga?: string;
    ntripStr?: string;

    agent?: string;

    authRequest?: AuthRequest;
    authResponse?: AuthResponse;

    query?: UrlWithParsedQuery;

    rtspTransportParams?: string[];
    rtpRemotePort?: number;
    rtpSocket?: dgram.Socket;
    rtpSession?: RtpSessionInfo;
}

class NtripCasterResponse extends ServerResponse {
    statusVersion = 'HTTP/1.1';

    // noinspection JSUnusedGlobalSymbols
    /**
     * Internal method that stores the response header.
     * Override to include NTRIP V1 responses such as ICY 200 OK and SOURCETABLE 200 OK.
     *
     * @param firstLine HTTP response status line
     * @param headers HTTP headers
     * @private
     */
    _storeHeader(firstLine: string, headers: OutgoingHttpHeaders) {
        firstLine = this.statusVersion + firstLine.slice(firstLine.indexOf(' '));
        // @ts-ignore Call private _storeHeader
        super._storeHeader(firstLine, headers);

        //console.log(chalk.green(firstLine));
        for (let header in headers) {
            // @ts-ignore
            //console.log(chalk.green(headers[header][0] + ": " + headers[header][1]));
        }
    }

    error(code: number, response?: string) {
        this.statusCode = code;
        this.statusMessage = STATUS_CODES[code] as string;
        this.removeHeader('Connection');
        if (response === undefined) {
            this.removeHeader('Content-Length');
            this.removeHeader('Transfer-Encoding');
        }
        this.end(response);
    }
}

function singularHeader(value: string | string[] | undefined): string | undefined {
    if (value instanceof Array) return value[0];
    return value;
}