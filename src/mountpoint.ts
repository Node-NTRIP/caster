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

import {Sourcetable} from "./sourcetable";

import events from "events";
import {Client, Server} from './connection';
import {AutoSourceEntry, AutoSourceEntryOptions} from './util/auto-source-entry';

export interface MountpointOptions {
    connectionTimeout?: number;
    silenceTimeout?: number;
    silenceWarningTimeout?: number;

    autoSourceEntry?: boolean;
    serverSourceEntry?: boolean;

    autoSourceEntryOptions?: AutoSourceEntryOptions;

    hidden?: boolean;
}

const MOUNTPOINT_NAME_REGEX = /^[A-Za-z0-9-_.]{1,100}$/;

const STATS_RATE_RUNNING_AVERAGE_ALPHA = 0.90;

const CONNECTION_TIMEOUT_DEFAULT = 10000;
const SILENCE_WARNING_TIMEOUT_DEFAULT = 10000;
const SILENCE_TIMEOUT_DEFAULT = 30000;

const DEFAULT_OPTIONS: MountpointOptions = {
    connectionTimeout: CONNECTION_TIMEOUT_DEFAULT,
    silenceTimeout: SILENCE_TIMEOUT_DEFAULT,
    silenceWarningTimeout: SILENCE_WARNING_TIMEOUT_DEFAULT,

    autoSourceEntry: true,
    serverSourceEntry: false
};

export class Mountpoint extends events.EventEmitter {
    private readonly options: MountpointOptions;

    readonly name: string;
    readonly sourceEntry: Sourcetable.SourceEntry;

    private readonly autoSourceEntry?: AutoSourceEntry;

    hidden: boolean = false;

    private _server: Server | null = null;
    get server(): Server | null { return this._server; }
    private _clients: Set<Client> = new Set<Client>();
    get clients(): ReadonlySet<Client> { return this._clients; }

    private connectionTimeout?: number;
    private silenceTimeout?: number;
    private silenceWarningTimeout?: number;

    readonly stats = {
        in: 0,
        out: 0,
        rate: 0
    };

    private readonly statsStream = new stream.Writable({
        write: (chunk: any, encoding: string, callback: (error?: (Error | null)) => void) => {
            this.stats.in += chunk.length;
            this.stats.out += chunk.length * this._clients.size;
            callback();

            this.resetTimeouts();
        }
    });

    private readonly statsRateCalculator = (old: number) => {
        const current = this.stats.in;
        const rate = current - old;
        this.stats.rate = Math.round(this.stats.rate * STATS_RATE_RUNNING_AVERAGE_ALPHA
                + rate * (1.0 - STATS_RATE_RUNNING_AVERAGE_ALPHA));
        setTimeout(() => this.statsRateCalculator(current), 1000);
    };

    on(event: 'close', listener: () => void): this;
    on(event: 'client', listener: (client: Client) => void): this;
    on(event: 'server', listener: (server: Server) => void): this;
    on(event: 'timeout', listener: () => void): this;
    on(event: 'inactivity', listener: () => void): this;
    on(event: 'silence', listener: () => void): this;
    on(event: string | symbol, listener: (...args: any[]) => void): this {
        return super.on(event, listener);
    }

    constructor(name: string, options?: MountpointOptions) {
        super();

        this.options = options = {...DEFAULT_OPTIONS, ...options};

        if (!MOUNTPOINT_NAME_REGEX.test(name))
            throw new Error(`Mountpoint name (${name}) contains invalid characters: must be 1..100 characters, A-Za-z0-9.-_`);

        this.name = name;
        this.sourceEntry = new Sourcetable.SourceEntry(name);

        if (options?.autoSourceEntry)
            this.autoSourceEntry = new AutoSourceEntry(this, this.options?.autoSourceEntryOptions);

        this.statsRateCalculator(0);

        this.resetTimeouts();
    }

    private resetTimeouts() {
        clearTimeout(this.connectionTimeout);
        clearTimeout(this.silenceTimeout);
        clearTimeout(this.silenceWarningTimeout);

        if (this.active) {
            this.silenceTimeout = setTimeout(() => {
                this.emit('inactivity');
                this.clearServer();
            }, this.options?.silenceTimeout);

            this.silenceWarningTimeout = setTimeout(() => {
                this.emit('silence');
            }, this.options?.silenceWarningTimeout);
        } else {
            this.connectionTimeout = setTimeout(() => {
                this.emit('timeout');
                this.close();
            }, this.options?.connectionTimeout);
        }
    }

    get active(): boolean {
        return this._server != null;
    }

    setServer(server: Server) {
        if (this._server === server) return;
        if (this._server !== null) throw new Error(`Another server is already connected to mountpoint ${this.name}`);
        this._server = server;

        this.emit('server', server);

        server.once('close', () => this.clearServer(server));

        this.resetTimeouts();

        server.input!.pipe(this.statsStream, {end: false});
        this._clients.forEach((client) => server.pipe(client));

        if (this.options?.serverSourceEntry)
            server.on('str', (str) => this.sourceEntry.fromSourcetableLine('STR;;' + str));

        if (this.options?.autoSourceEntry)
            server.rtcm.pipe(this.autoSourceEntry!, { end: false });
    }

    clearServer(server: Server | null = this._server): void {
        if (this._server === null) return;
        if (this._server !== server) return;
        this._server = null;

        this.resetTimeouts();

        server.input!.unpipe(this.statsStream);
        this._clients.forEach((client) => server.unpipe(client));

        if (this.autoSourceEntry !== undefined) server.rtcm.unpipe(this.autoSourceEntry);

        server.close();
    }

    addClient(client: Client): void {
        if (this._clients.has(client)) return;
        this._clients.add(client);

        this.emit('client', client);

        client.on('close', () => this.removeClient(client));

        this._server?.pipe(client);
    }

    removeClient(client: Client): void {
        if (!this._clients.has(client)) return;
        this._clients.delete(client);

        this._server?.unpipe(client);

        client.close();
    }

    close(): void {
        this.clearServer();
        this._clients.forEach((client) => this.removeClient(client));

        this.emit('close');
    }
}