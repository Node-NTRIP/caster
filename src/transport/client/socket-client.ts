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

import {SingleConnectionTransport} from '../transport';
import {CasterTransportDefinition, CasterTransportInterface} from '../../caster';

export interface SocketClientTransportOptions {
    type: 'server' | 'client';
    mountpoint: string;

    remote: {
        host: string;
        port: number;
        family?: string;
    }
    tls?: tls.SecureContextOptions & tls.CommonConnectionOptions;

    str?: string;
    gga?: string,
}

export class SocketClientTransport extends SingleConnectionTransport {
    private socket!: net.Socket;

    protected constructor(manager: CasterTransportInterface, private readonly options: SocketClientTransportOptions) {
        super(manager, options);
    }

    static new(options: SocketClientTransportOptions): CasterTransportDefinition {
        return (caster: CasterTransportInterface) => new SocketClientTransport(caster, options);
    }

    open(): void {
        this.socket = new net.Socket();
        if (this.options.tls !== undefined)
            this.socket = new tls.TLSSocket(this.socket, this.options.tls);

        new Promise((resolve, reject) => {
            this.socket.once(this.socket instanceof tls.TLSSocket ? 'secureConnect' : 'connect', resolve);
            this.socket.once('error', reject);
        }).then(() => {
            try {
                this.connect({
                    type: this.options.type,
                    mountpoint: this.options.mountpoint,

                    source: this.options.remote.host + ':' + this.options.remote.port,
                    stream: this.socket,

                    str: this.options.str,
                    gga: this.options.gga
                });
                this.emit('open');
            } catch (err) {
                this.emit('error', err);
            }
        }).catch(err => this.emit('error', err));

        this.socket.connect({
            host: this.options.remote.host,
            port: this.options.remote.port
        });
    }

    close(): void {
        super.close();

        this.socket?.destroy();
    }

    get description(): string {
        return `${this.options.tls === undefined ? 'tcp' : 'tls'}[${this.options.type}]`;
    }
}