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

import net = require('net');
import tls = require('tls');

import {AuthRequest, AuthResponse} from '../../auth';
import {CasterTransportDefinition, CasterTransportInterface} from '../../caster';
import {Transport} from '../transport';
import {TLSSocket} from 'tls';
import VError from 'verror';

export interface SourceHost {
    hostMask: string;
    port?: number;

    authenticate?: boolean;

    type: 'server' | 'client';

    mountpoint: string;

    gga?: string;
    str?: string;
}

export interface SocketTransportOptions {
    port: number;
    tls?: tls.SecureContextOptions & tls.TlsOptions;

    sourceHosts: SourceHost[];
}

export interface SocketTransportConnectionProperties {
    protocol: 'tcp' | 'tls';

    remote: {
        host: string;
        port: number;
        family: string;
    }

    toString: () => string;
}

export class SocketTransport extends Transport {
    private server!: net.Server;

    protected constructor(manager: CasterTransportInterface, private readonly options: SocketTransportOptions) {
        super(manager, options);
    }

    static new(options: SocketTransportOptions): CasterTransportDefinition {
        return (caster: CasterTransportInterface) => new SocketTransport(caster, options);
    }

    open(): void {
        this.server = (this.options.tls === undefined ? net.createServer() : tls.createServer(this.options.tls));
        this.server.on('connection', (socket) => this.accept(socket));

        new Promise((resolve, reject) => {
            this.server.once('listening', resolve);
            this.server.once('error', reject);
        }).then(() => this.emit('open'))
            .catch((err?: Error) => this.emit('error', err));

        this.server.listen(this.options.port);
    }

    close(): void {
        this.server.close(() => this.emit('close'));
    }

    private static matchHost(host: string, mask: string): boolean {
        const sections = mask.split('*');
        let text = host;
        for (let section of sections) {
            const index = text.indexOf(section);
            if (index < 0) return false;
            text = text.slice(index + section.length);
        }
        return true;
    }

    private findMatchingSourceHost(socket: net.Socket): SourceHost | undefined {
        return this.options.sourceHosts.find(sourceHost =>
            SocketTransport.matchHost(socket.remoteAddress!, sourceHost.hostMask)
            && (sourceHost.port === undefined || sourceHost.port === socket.remotePort));
    }

    private async accept(socket: net.Socket) {
        socket.on('error', err => {
            this.emit('clientError', new VError({
                name: 'ClientError',
                cause: err,
                info: {
                    remote: {
                        address: socket.remoteAddress,
                        port: socket.remotePort,
                        family: socket.remoteFamily
                    }
                }
            }, "Socket server client error"));
        });

        let sourceHost = this.findMatchingSourceHost(socket);
        if (sourceHost === undefined) return socket.destroy();

        let authResponse: AuthResponse | undefined;
        if (sourceHost.authenticate) {
            const authRequest: AuthRequest = {
                type: sourceHost.type,
                mountpoint: sourceHost.mountpoint,

                host: socket.localAddress,
                source: {
                    host: socket.remoteAddress!,
                    port: socket.remotePort!,
                    family: socket.remoteFamily!
                },

                credentials: {
                    anonymous: !(socket instanceof TLSSocket),
                    certificate: socket instanceof TLSSocket ? socket.getPeerCertificate().fingerprint : undefined
                }
            };

            authResponse = await this.caster.authenticate(authRequest);
        }

        const source: SocketTransportConnectionProperties = {
            protocol: socket instanceof TLSSocket ? 'tls' : 'tcp',

            remote: {
                host: socket.remoteAddress!,
                port: socket.remotePort!,
                family: socket.remoteFamily!
            },

            toString: () => this.connectionDescription(source)
        };

        try {
            this.connect({
                type: sourceHost.type,

                source: source,

                mountpoint: sourceHost.mountpoint,

                gga: sourceHost.gga,
                str: sourceHost.str,

                stream: socket,

                auth: authResponse
            });
        } catch (err) {
            socket.destroy(err);
        }
    }

    get description(): string {
        return `${this.options.tls === undefined ? 'tcp' : 'tls'}[port=${this.options.port}]`;
    }

    connectionDescription(source: any): string {
        return `${source.protocol}://${source.remote.host}:${source.remote.port}`;
    }
}