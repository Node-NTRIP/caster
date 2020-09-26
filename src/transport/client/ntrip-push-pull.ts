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

import {SingleConnectionTransport} from '../transport';
import {NtripVersion} from '../';
import {Caster, CasterTransportDefinition, CasterTransportInterface} from '../../caster';
import {NtripRtpSession} from '../../util/rtp';
import {Connection} from '../../connection';

import dgram = require('dgram');
import dns = require('dns');
import http = require('http');
import https = require('https');
import net = require('net');
import stream = require('stream');
import tls = require('tls');

import {ClientRequest, ClientRequestArgs, IncomingMessage, OutgoingHttpHeaders} from 'http';
import VError from 'verror';

export interface NtripPushPullTransportOptions {
    mode: 'push' | 'pull';

    remote: {
        host: string;
        port: number;
        family?: string;
    }
    tls?: tls.SecureContextOptions & tls.CommonConnectionOptions;

    protocol: 'http' | 'rtsp' | 'rtp';

    localMountpoint: string;
    remoteMountpoint: string;

    ntripVersion: NtripVersion;

    localStr?: string;
    localGga?: string;

    remoteStr?: string;
    remoteGga?: string;

    credentials?: {
        basic?: {username: string, password: string};
        bearer?: string;
        secret?: string;
    }
}

export interface NtripPushPullTransportConnectionProperties {
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

export class NtripPushPullTransport extends SingleConnectionTransport {
    private agent?: http.Agent | https.Agent;

    private rtpSocket?: dgram.Socket;
    private rtpSession?: NtripRtpSession;

    get description(): string {
        return `ntrip[${this.options.mode}]`;
    }

    connectionDescription(source: any): string {
        return `${source.protocol}://${source.remote.host}:${source.remote.port}`;
    }

    protected constructor(manager: CasterTransportInterface, private readonly options: NtripPushPullTransportOptions) {
        super(manager, options);

        // Plain RTP does not work with TLS TODO: Node.js DTLS?
        if (options.protocol === 'rtp' && options.tls !== undefined)
            throw new Error("Plain RTP protocol is not supported when using TLS");
    }

    static new(options: NtripPushPullTransportOptions): CasterTransportDefinition {
        return (caster: CasterTransportInterface) => new NtripPushPullTransport(caster, options);
    }

    open(): void {
        if (this.options.protocol !== 'rtp') {
            const options = {
                maxSockets: 1,
                keepAlive: true,
                timeout: 60000,
                keepAliveMsecs: 60000
            };
            this.agent = (this.options.tls === undefined
                    ? new http.Agent(options)
                    : new https.Agent({...options, ...this.options.tls}));
        }

        const params: NtripClientRequestOptions = {
            protocol: this.options.tls === undefined ? 'http:' : 'https:',
            host: this.options.remote.host,
            port: this.options.remote.port,
            agent: this.agent,
            headers: {},
            rejectUnauthorized: false
        };

        if (this.options.credentials?.basic !== undefined) {
            params.auth = this.options.credentials.basic.username + ':' + this.options.credentials.basic.password;
        } else if (this.options.credentials?.bearer !== undefined) {
            params.headers!['Authorization'] = 'Bearer ' + this.options.credentials.bearer;
        }

        if (this.options.protocol === 'http') {
            new NtripPushPullTransport.HttpRequestFormer(this, params).form();
        } else if (this.options.protocol === 'rtsp') {
            new NtripPushPullTransport.RtspRequestFormer(this, params).form();
        } else if (this.options.protocol === 'rtp') {
            new NtripPushPullTransport.RtpRequestFormer(this, params).form();
        } else {
            this.error(new Error(`Unknown protocol ${this.options.protocol}`));
        }
    }

    close(): void {
        super.close();

        this.agent?.destroy();
        this.rtpSession?.destroy();
        try { this.rtpSocket?.close(); } catch (err) {}
    }

    /**
     * Abstract request instance processor
     *
     * Mainly used to improve organization of code and avoid complex function names for various combinations of
     * protocols and versions. Request processors are initially created by {@link NtripTransport#accept}.
     *
     * Contains properties for reference to the parent transport, overall caster manager, and request/response objects.
     */
    private static RequestFormer = class RequestFormer {
        protected transport: NtripPushPullTransport;
        protected manager: CasterTransportInterface;
        protected options: NtripPushPullTransportOptions;

        protected params: NtripClientRequestOptions;
        protected req?: NtripClientRequest;
        protected res?: NtripClientResponse;

        protected type: 'server' | 'client';

        constructor(parent: NtripPushPullTransport | RequestFormer, params?: NtripClientRequestOptions) {
            if (parent instanceof RequestFormer) {
                this.transport = parent.transport;
                this.manager = parent.manager;
                this.options = parent.transport.options;
                this.params = parent.params;
                this.req = parent.req;
                this.res = parent.res;
            } else {
                this.transport = parent;
                this.manager = parent.caster;
                this.options = parent.options;
                this.params = params!;
            }
            this.type = this.options.mode == 'pull' ? 'server' : 'client';
        };

        protected send(flushOnly: boolean = false): void {
            this.req = new NtripClientRequest(this.params, response => {
                this.res = response;
                this.response();
            });

            if (flushOnly) {
                this.req.flushHeaders();
            } else {
                this.req.end('');
            }
        }

        protected response() {
            if (this.res!.statusCode != 200)
                return this.transport.error(new Error(`Could not connect to caster, response was ${this.res!.statusCode} ${this.res!.statusMessage}`));

            if (this.options.mode == 'push') {
                return this.responseServer();
            } else { // if (this.options.mode == 'pull') {
                return this.responseClient();
            }
        }

        protected responseServer() {
            this.connect({
                type: 'client',
                input: this.res,
                output: this.req,
            });
        }

        protected responseClient() {
            this.connect({
                type: 'server',
                input: this.res,
                output: this.req
            });
        }

        protected connect(params: {
            type: 'server' | 'client'

            input?: stream.Readable,
            output?: stream.Writable,
            stream?: stream.Duplex
        }): Connection {
            let protocol = this.options.protocol;
            if (this.options.tls !== undefined && (protocol === 'http' || protocol === 'rtsp')) protocol += 's';

            const source: NtripPushPullTransportConnectionProperties = {
                protocol: protocol as 'http' | 'https' | 'rtsp' | 'rtsps' | 'rtp',
                version: this.options.ntripVersion,
                remote: {
                    host: this.options.remote.host,
                    port: this.options.remote.port,
                    family: this.res!.socket.remoteFamily!
                },
                toString: () => this.transport.connectionDescription(source)
            };

            return this.transport.connect({
                ...params,
                source: source,
                mountpoint: this.options.localMountpoint,

                gga: this.options.localGga,
                str: this.options.localStr
            });
        }

        protected setNtripStrHeader(header: string = 'Ntrip-STR') {
            if (this.options.remoteStr === undefined) return;
            this.params.headers![header] = this.options.remoteStr;
        }

        protected setNtripGgaHeader(header: string = 'Ntrip-GGA') {
            if (this.options.remoteGga === undefined) return;
            this.params.headers![header] = this.options.remoteGga;
        }
    };

    /** HTTP request instance processor */
    private static HttpRequestFormer = class HttpRequestFormer extends NtripPushPullTransport.RequestFormer {
        form() {
            this.params.statusVersion = 'HTTP/1.1';
            this.params.path = '/' + this.options.remoteMountpoint;

            if (this.options.ntripVersion == NtripVersion.V1) {
                return new HttpRequestFormer.V1Processor(this).form();
            } else if (this.options.ntripVersion == NtripVersion.V2) {
                return new HttpRequestFormer.V2Processor(this).form();
            } else {
                return this.transport.error(new Error(`Unknown NTRIP version ${this.options.ntripVersion}`));
            }
        }

        /** HTTP NTRIP v1.0 request instance former */
        private static V1Processor = class V1Processor extends NtripPushPullTransport.RequestFormer {
            form() {
                if (this.options.mode == 'push') {
                    return this.formServer();
                } else { // if (this.options.mode == 'pull') {
                    return this.formClient();
                }
            }

            private formServer() {
                this.params.method = 'SOURCE';

                this.params.headers!['Source-Agent'] = 'NTRIP ' + Caster.NAME;

                if (this.options.credentials?.secret === undefined)
                    return this.transport.error(new Error("NTRIP v1 SOURCE request secret not provided"));
                this.params.sourceSecret = this.options.credentials?.secret!;

                this.setNtripStrHeader('STR');

                this.send(true);
            }

            private formClient() {
                this.params.method = 'GET';

                this.params.headers!['User-Agent'] = 'NTRIP ' + Caster.NAME;

                this.setNtripGgaHeader();

                this.send(true);
            }

            protected responseServer() {
                this.connect({
                    type: 'client',
                    stream: this.res!.socket
                });
            }

            protected responseClient() {
                this.res!.socket.removeAllListeners('data');
                this.connect({
                    type: 'server',
                    stream: this.res!.socket
                });
            }
        };

        /** HTTP NTRIP v2.0 request instance former */
        private static V2Processor = class V2Processor extends NtripPushPullTransport.RequestFormer {
            form() {
                this.params.headers!['Ntrip-Version'] = 'Ntrip/2.0';
                this.params.headers!['User-Agent'] = 'NTRIP ' + Caster.NAME;
                this.params.headers!['Connection'] = 'close';

                if (this.options.mode == 'push') {
                    this.params.method = 'POST';
                    this.setNtripStrHeader();
                } else { // if (this.options.mode == 'pull') {
                    this.params.method = 'GET';
                    this.setNtripGgaHeader();
                }

                this.send(true);
            }
        }
    };

    /** RTSP request instance processor */
    private static RtspRequestFormer = class RtspRequestFormer extends NtripPushPullTransport.RequestFormer {
        form() {
            this.params.statusVersion = 'RTSP/1.0';
            this.params.path = 'rtsp://' + this.options.remote.host + ':' + this.options.remote.port + '/' + this.options.remoteMountpoint;
            this.params.headers!['CSeq'] = 1;

            if (this.options.ntripVersion == NtripVersion.V2) {
                return new RtspRequestFormer.V2Processor(this).form();
            } else {
                this.transport.error(new Error('RTSP only supports NTRIP V2 requests'));
            }
        }

        /** RTSP NTRIP v2.0 request instance former */
        private static V2Processor = class V2Processor extends NtripPushPullTransport.RequestFormer {
            private socket?: dgram.Socket;
            private session?: NtripRtpSession;
            private active: boolean = false;

            form() {
                this.params.method = 'SETUP';

                this.params.headers!['Ntrip-Version'] = 'Ntrip/2.0';
                this.params.headers!['User-Agent'] = 'NTRIP ' + Caster.NAME;
                this.params.headers!['Connection'] = 'keep-alive';
                this.params.timeout = 60000;

                this.socket = this.transport.rtpSocket = dgram.createSocket({
                    type: 'udp6',
                    reuseAddr: true,
                    // TODO: https://github.com/nodejs/node/issues/33331
                    lookup: (hostname, options, callback) =>
                        dns.lookup(hostname, 0, (err, address, family) =>
                            callback(err, family === 4 ? '::ffff:' + address : address, family))
                });

                new Promise((resolve, reject) => {
                    this.socket!.once('listening', resolve);
                    this.socket!.once('error', reject);
                }).then(() => {
                    const address = this.socket!.address();
                    this.params.headers!['Transport'] = 'RTP/GNSS;unicast;client_port=' + address.port;

                    if (this.options.mode == 'push') {
                        this.params.headers!['Ntrip-Component'] = 'Ntripserver';
                        this.setNtripStrHeader();
                    } else { // if (this.options.mode == 'pull') {
                        this.params.headers!['Ntrip-Component'] = 'Ntripclient';
                        this.setNtripGgaHeader();
                    }

                    this.send();
                }).catch(err => {
                    this.socket!.close();
                    this.transport.error(new Error(`Could not open RTP socket: ${err.message}`));
                });

                // Bind to random port and then connect to client
                this.socket.bind();
            }

            protected response() {
                if (this.res!.statusCode != 200)
                    return this.transport.error(new Error(`Could not connect to caster, response was ${this.res!.statusCode} ${this.res!.statusMessage}`));

                if (this.session === undefined) {
                    let ssrc = parseInt(this.res!.headers['session'] as string);
                    if (isNaN(ssrc))
                        return this.transport.error(new Error("Caster did not respond with (valid) RTP session code"));

                    // Parse transport header, verify RTP/GNSS and client port are present
                    const transport = singularHeader(this.res!.headers['transport']);
                    const rtspTransportParams = transport?.toLowerCase().split(';');
                    const serverPort = Number(rtspTransportParams
                            ?.find(p => /^server_port=\d+$/.test(p))
                            ?.slice('server_port='.length));
                    if (isNaN(serverPort))
                        return this.transport.error(new Error("Caster did not respond with target RTP port"));

                    new Promise((resolve, reject) => {
                        this.socket!.once('connect', resolve);
                        this.socket!.once('error', reject);
                    }).then(() => {
                        this.session = this.transport.rtpSession = new NtripRtpSession(this.socket!);
                        this.session.on('close', () => this.transport.close());

                        // If expecting data from caster, send initial empty packet to allow connection through firewall
                        if (this.options.mode === 'pull') this.session.dataStream.write('');

                        this.params.headers = {};
                        this.params.headers!['Connection'] = 'keep-alive';
                        this.params.method = this.options.mode === 'push' ? 'RECORD' : 'PLAY';
                        this.params.headers!['CSeq'] = 2;
                        this.params.headers!['Session'] = ssrc;
                        this.send();
                    }).catch(err => {
                        this.socket!.close();
                        this.transport.error(new VError({
                            cause: err,
                            info: {
                                remote: this.transport.options.remote
                            }
                        }, "Could not connect to caster RTP port"));
                    });

                    this.socket!.connect(serverPort, this.options.remote.host);
                } else if (!this.active) {
                    this.active = true;

                    this.connect({
                        type: this.type,
                        stream: this.session.dataStream
                    });

                    // Send keep-alive message every 30 seconds to avoid disconnection
                    this.params.method = 'GET_PARAMETER';
                    setInterval(() => {
                        (this.params.headers!['CSeq'] as number)++;
                        this.send();
                    }, 30000);
                }

                // Required to allow next request to be sent
                this.res!.emit('end');
            }
        }
    };

    /** RTP request instance processor */
    private static RtpRequestFormer = class RtpRequestFormer extends NtripPushPullTransport.RequestFormer {
        form() {
            this.params.statusVersion = 'HTTP/1.1';
            this.params.path = '/' + this.options.remoteMountpoint;

            if (this.options.ntripVersion == NtripVersion.V2) {
                return new RtpRequestFormer.V2Processor(this).form();
            } else {
                this.transport.error(new Error('RTP only supports NTRIP V2 requests'));
            }
        }

        /** RTP NTRIP v2.0 request instance former */
        private static V2Processor = class V2Processor extends NtripPushPullTransport.RequestFormer {
            private socket?: dgram.Socket;
            private session?: NtripRtpSession;

            form() {
                this.params.headers!['Ntrip-Version'] = 'Ntrip/2.0';
                this.params.headers!['User-Agent'] = 'NTRIP ' + Caster.NAME;
                this.params.headers!['Connection'] = 'keep-alive';

                this.params.createConnection = ((options: ClientRequestArgs, onCreate: (e: Error | undefined, s?: net.Socket) => void) => {
                    this.socket = this.transport.rtpSocket = dgram.createSocket({
                        type: 'udp6',
                        // TODO: https://github.com/nodejs/node/issues/33331
                        lookup: (hostname, options, callback) =>
                            dns.lookup(hostname, 0, (err, address, family) =>
                                callback(err, family === 4 ? '::ffff:' + address : address, family))
                    });

                    this.socket.once('connect', () => onCreate(undefined, this.createInjectionSocket()));
                    this.socket.once('error', (err) => onCreate(err));

                    this.socket.connect(this.options.remote.port, this.options.remote.host);
                }) as any; // Signature of createConnection is incorrect

                if (this.options.mode == 'push') {
                    this.params.method = 'POST';
                    this.setNtripStrHeader();
                } else { // if (this.options.mode == 'pull') {
                    this.params.method = 'GET';
                    this.setNtripGgaHeader();
                }
                this.send();
            }

            private createInjectionSocket(): net.Socket {
                this.session = this.transport.rtpSession = new NtripRtpSession(this.socket!);
                const connection = this.session.httpStream;
                (connection as any).remoteAddress = this.socket?.remoteAddress().address;
                (connection as any).remotePort = this.socket?.remoteAddress().port;
                (connection as any).remoteFamily = this.socket?.remoteAddress().family;

                // Inject as a socket, only remote* properties of net.Socket will be accessed
                return connection as unknown as net.Socket;
            }

            protected response() {
                if (this.res!.statusCode != 200)
                    return this.transport.error(new Error(`Could not connect to caster, response was ${this.res!.statusCode} ${this.res!.statusMessage}`));

                let ssrc = parseInt(this.res!.headers['session'] as string);
                if (isNaN(ssrc)) return this.transport.error(new Error("Caster did not respond with (valid) RTP session code"));

                this.session!.ssrc = ssrc;

                this.connect({
                    type: this.type,
                    stream: this.session!.dataStream
                });

                // Send keep-alive message every 20 seconds to avoid disconnection
                setInterval(() => this.session?.dataStream.write(''), 20000);
            }
        }
    };
}

interface NtripClientRequestOptions extends https.RequestOptions {
    statusVersion?: string;
    sourceSecret?: string;
}

class NtripClientRequest extends ClientRequest {
    statusVersion?: string;
    sourceSecret?: string;

    constructor(options: NtripClientRequestOptions, cb?: (res: IncomingMessage) => void) {
        super(options, cb);

        this.statusVersion = options.statusVersion;
        this.sourceSecret = options.sourceSecret;
    }

    // noinspection JSUnusedGlobalSymbols
    /**
     * Internal method that stores the request header.
     * Override to include RTSP in status line.
     *
     * @param firstLine HTTP request status line
     * @param headers HTTP headers
     * @private
     */
    _storeHeader(firstLine: string, headers: OutgoingHttpHeaders) {
        if (this.statusVersion !== undefined)
            firstLine = firstLine.slice(0, firstLine.lastIndexOf(' ') + 1) + this.statusVersion + '\r\n';

        if (this.sourceSecret !== undefined)
            firstLine = firstLine.slice(0, firstLine.indexOf(' ') + 1) +
                    this.sourceSecret + firstLine.slice(firstLine.indexOf(' '));

        // @ts-ignore Call private _storeHeader
        super._storeHeader(firstLine, headers);
    }
}

type NtripClientResponse = IncomingMessage;

function singularHeader(value: string | string[] | undefined): string | undefined {
    if (value instanceof Array) return value[0];
    return value;
}