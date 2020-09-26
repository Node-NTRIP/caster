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

import fs = require('fs');

import {SingleConnectionTransport} from '../transport';
import {CasterTransportDefinition, CasterTransportInterface} from '../../caster';

export interface FileTransportOptions {
    type: 'server' | 'client';
    source: string;

    mountpoint: string;

    input?: string;
    output?: string;

    str?: string;
    gga?: string;
}

export class FileTransport extends SingleConnectionTransport {
    protected constructor(manager: CasterTransportInterface, private readonly options: FileTransportOptions) {
        super(manager, options);
    }

    static new(options: FileTransportOptions): CasterTransportDefinition {
        return (caster: CasterTransportInterface) => new FileTransport(caster, options);
    }

    open(): void {
        const input = this.options.input !== undefined ?
            fs.createReadStream(this.options.input, {
                emitClose: true
            }) : undefined;
        const output = this.options.output !== undefined ?
            fs.createWriteStream(this.options.output, {
                emitClose: true
            }) : undefined;

        try {
            this.connect({
                ...this.options,
                input: input,
                output: output
            });
            this.emit('open')
        } catch (err) {
            this.emit('error', err)
        }
    }

    get description(): string {
        return 'file';
    }
}