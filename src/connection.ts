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

import {Mountpoint} from './mountpoint';
import {Transport} from './transport';

import stream = require('stream');
import events = require('events');
import {RtcmDecodeTransformStream} from '@gnss/rtcm';
import {NmeaDecodeTransformStream, NmeaTransport} from '@gnss/nmea';

export interface ConnectionParameters {
    transport: Transport,
    source: string | object,

    token?: any,

    mountpoint: Mountpoint,

    input?: stream.Readable,
    output?: stream.Writable,
    stream?: stream.Duplex,
}

/**
 * Connection of a server/client to a single mountpoint
 */
export abstract class Connection extends events.EventEmitter {
    protected closed: boolean = false;

    readonly transport: Transport;
    readonly source: string | object;

    readonly mountpoint: Mountpoint;

    readonly input?: stream.Readable;
    readonly output?: stream.Writable;

    readonly token?: any;

    private _connectionTime: Date = new Date();
    private _disconnectionTime?: Date;
    get connectionTime(): Date { return this._connectionTime; }
    get disconnectionTime(): Date | undefined { return this._disconnectionTime; }
    /** Connection duration, in ms */
    get duration(): number { return (this._disconnectionTime?.getTime() ?? Date.now()) - this._connectionTime.getTime(); }

    abstract get type(): 'server' | 'client';

    protected constructor(parameters: ConnectionParameters) {
        super();
        this.transport = parameters.transport;
        this.source = parameters.source;
        this.token = parameters.token;
        this.mountpoint = parameters.mountpoint;
        this.input = parameters.input ?? parameters.stream;
        this.output = parameters.output ?? parameters.stream;

        // Disconnect if streams close
        this.input?.on('close', () => this.close());
        this.input?.on('error', (error) => this.error(error));
        if (this.input !== this.output) {
            this.output?.on('close', () => this.close());
            this.output?.on('error', (error) => this.error(error));
        }
    }

    private error(error: Error) {
        //this.emit('error', error);
        this.close(error);
    }

    close(error?: Error): void {
        if (this.closed) return;

        if (!this.input?.destroyed) this.input?.destroy(error);
        if (!this.output?.destroyed) this.output?.destroy(error);
        this.closed = true;

        this._disconnectionTime = new Date();

        this.emit('close');
    }

    pipe(connection: Connection): void {
        this.input!.pipe(connection.output!, {end: false});
    }

    unpipe(connection: Connection): void {
        this.input!.unpipe(connection.output!);
    }
}

/**
 * Server connection to a single mountpoint for pushing data
 *
 * Servers must have an input stream, and can optionally have an output stream e.g. for VRS.
 */
export class Server extends Connection {
    private _str?: string;

    private _rtcm?: RtcmDecodeTransformStream;

    get type(): 'server' { return 'server'; }

    constructor(parameters: ConnectionParameters & {input: stream.Readable}) {
        if (parameters.input === undefined) throw new Error("Server input stream must be provided");
        super(parameters);
    }

    set str(str: string | undefined) {
        this._str = str;
        this.emit('str', str);
    }

    get str(): string | undefined {
        return this._str;
    }

    get rtcm(): RtcmDecodeTransformStream {
        if (this._rtcm === undefined) {
            this._rtcm = new RtcmDecodeTransformStream({
                closeOnError: false,
                synchronizedInitially: false
            });
            this.input?.pipe(this._rtcm);
        }
        return this._rtcm;
    }
}

/**
 * Client connection to a single mountpoint for receiving data
 *
 * Clients must have an output stream, and can optionally have an input stream e.g. for VRS.
 */
export class Client extends Connection {
    private _gga?: string;

    private _nmea?: NmeaDecodeTransformStream;

    get type(): 'client' { return 'client'; }

    constructor(parameters: ConnectionParameters & {output: stream.Writable}) {
        if (parameters.output === undefined) throw new Error("Client output stream must be provided");
        super(parameters);
    }

    set gga(gga: string | undefined) {
        this._gga = gga;
        this.emit('gga', gga);
        this.parseGga();
    }

    get gga(): string | undefined {
        return this._gga;
    }

    get nmea(): NmeaDecodeTransformStream {
        if (this._nmea === undefined) {
            this._nmea = new NmeaDecodeTransformStream({
                closeOnError: false,
                synchronizedInitially: false
            });
            this.input?.pipe(this._nmea);
            this.parseGga();
        }
        return this._nmea;
    }

    private parseGga() {
        if (this._gga === undefined) return;
        if (this._nmea === undefined) return;

        try {
            this._nmea.push(NmeaTransport.decode(this._gga));
        } catch (err) {
            // Ignore invalid GGA
        }
    }
}
