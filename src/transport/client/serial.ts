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

import SerialPort from 'serialport';

import {CasterTransportDefinition, CasterTransportInterface} from '../../caster';
import {SingleConnectionTransport} from '../transport';

export interface SerialTransportOptions {
    type: 'server' | 'client';
    mountpoint: string;

    port: string;
    portOptions: {
        baudRate?: 921600|460800|230400|115200|57600|38400|19200|9600|4800|2400|1800|1200|600|300|200|150|134|110|75|50|number;
        dataBits?: 8|7|6|5;
        stopBits?: 1|2;
        parity?: 'none'|'even'|'mark'|'odd'|'space';
        rtscts?: boolean;
        disableRtsCts?: boolean
        xon?: boolean;
        xoff?: boolean;
    };

    str?: string;
    gga?: string;
}

export class SerialTransport extends SingleConnectionTransport {
    private serial!: SerialPort;

    protected constructor(manager: CasterTransportInterface, private readonly options: SerialTransportOptions) {
        super(manager, options);
    }

    static new(options: SerialTransportOptions): CasterTransportDefinition {
        return (caster: CasterTransportInterface) => new SerialTransport(caster, options);
    }

    open(): void {
        this.serial = new SerialPort(this.options.port, {...this.options.portOptions, autoOpen: false});

        new Promise((resolve, reject) => {
            this.serial.once('open', resolve);
            this.serial.once('error', reject);
        }).then(() => {
            if (this.options.portOptions.disableRtsCts) this.serial!.set({dtr: false, rts: false});

            try {
                this.connect({
                    type: this.options.type,
                    mountpoint: this.options.mountpoint,

                    source: this.options.port,
                    stream: this.serial
                });
                this.emit('open');
            } catch (err) {
                this.emit('error', err);
            }
        }).catch((err?: Error) => {
            this.emit('error', err);
        });

        this.serial.open();
    }

    close(): void {
        super.close();

        this.serial?.close(() => this.emit('close'));
    }

    static list(): Promise<SerialPort.PortInfo[]> {
        return SerialPort.list();
    }

    get description(): string {
        return `serial[baud=${this.options.portOptions.baudRate ?? 115200}]`;
    }
}