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

import stream = require('stream');

import {SingleConnectionTransport} from '../transport';
import {CasterTransportDefinition, CasterTransportInterface} from '../../caster';

export interface StreamTransportOptions {
    type: 'server' | 'client';
    source: string;

    mountpoint: string;

    stream?: stream.Duplex;
    input?: stream.Readable;
    output?: stream.Writable;

    str?: string;
    gga?: string;
}

export class StreamTransport extends SingleConnectionTransport {
    protected constructor(manager: CasterTransportInterface, private readonly options: StreamTransportOptions) {
        super(manager, options);
    }

    static new(options: StreamTransportOptions): CasterTransportDefinition {
        return (caster: CasterTransportInterface) => new StreamTransport(caster, options);
    }

    open(): void {
        try {
            this.connect(this.options);
            this.emit('open')
        } catch (err) {
            this.emit('error', err)
        }
    }

    get description(): string {
        return 'stream';
    }
}