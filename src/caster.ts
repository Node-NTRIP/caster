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
import events = require('events');

import {AuthManager, AuthRequest, AuthResponse} from './auth';
import {Mountpoint, MountpointOptions} from './mountpoint';
import {Client, Connection, ConnectionParameters, Server} from './connection';
import {Transport} from './transport';
import {Sourcetable} from './sourcetable';
import VError from 'verror';

export interface CasterParameters {
    authManager: AuthManager,

    mountpointOptions?: MountpointOptions | ((mountpointName: string) => MountpointOptions)
}

export class Caster extends events.EventEmitter {
    static readonly NAME = 'NodeNtripCaster/0.0.1';

    private readonly authManager: AuthManager;
    private readonly mountpointOptions?: MountpointOptions | ((mountpointName: string) => MountpointOptions);

    readonly _transports: Set<Transport> = new Set();
    get transports(): ReadonlySet<Transport> { return this._transports; };
    readonly _connections: Set<Connection> = new Set();
    get connections(): ReadonlySet<Connection> { return this._connections; }
    readonly _mountpoints: Map<string, Mountpoint> = new Map();
    get mountpoints(): ReadonlyMap<string, Mountpoint> { return this._mountpoints; }

    staticSourcetableEntries: Sourcetable.Entry[] = [];

    constructor(parameters: CasterParameters) {
        super();
        this.authManager = parameters.authManager;
        this.mountpointOptions = parameters.mountpointOptions;
    }

    async authenticate(request: AuthRequest): Promise<AuthResponse> {
        return this.authManager.authenticate(request);
    }

    private createMountpoint(mountpointName: string, options?: MountpointOptions): Mountpoint {
        if (this._mountpoints.has(mountpointName))
            throw new Error("Mountpoint with name \"" + mountpointName + "\" already exists");

        if (options === undefined) {
            if (typeof this.mountpointOptions === "function") {
                options = this.mountpointOptions(mountpointName);
            } else {
                options = this.mountpointOptions;
            }
        }

        const mountpoint = new Mountpoint(mountpointName, options);
        mountpoint.on('close', () => this._mountpoints.delete(mountpointName));
        this._mountpoints.set(mountpointName, mountpoint);

        this.emit('mountpoint', mountpoint);

        return mountpoint;
    }

    private prepareMountpoint(type: 'server' | 'client', mountpointName: string): Mountpoint {
        let mountpoint = this._mountpoints.get(mountpointName);
        if (type === 'server') {
            if (mountpoint === undefined) mountpoint = this.createMountpoint(mountpointName);
            else if (mountpoint.active) throw new VError({
                name: 'ConnectionError',
                info: {
                    mountpoint: mountpointName,
                    server: mountpoint.server
                }
            }, 'Mountpoint %s conflict: A server is already connected');
        } else { // if (type === 'client') {
            if (mountpoint === undefined || !mountpoint.active) throw new VError({
                name: 'ConnectionError',
                info: {
                    mountpoint: mountpointName
                }
            }, 'Mountpoint %s does not exist (or is not currently active)');
        }

        return mountpoint;
    }

    private connect(params: CasterConnectionParameters): Connection {
        const mountpoint = this.prepareMountpoint(params.type, params.mountpoint);

        let connection: Connection;
        const parameters = {
            ...params,
            mountpoint: mountpoint,
            input: params.input ?? params.stream,
            output: params.output ?? params.stream
        }

        if (params.type === 'server') {
            if (parameters.input === undefined) throw new Error("Missing input stream for server");
            connection = new Server(parameters as ConnectionParameters & {input: stream.Readable});
        } else { // if (params.type === 'client') {
            if (parameters.output === undefined) throw new Error("Missing output stream for client");
            connection = new Client(parameters as ConnectionParameters & {output: stream.Writable});
        }

        this._connections.add(connection);
        connection.once('close', () => this._connections.delete(connection));

        // Wait for one tick to allow transport to send successful connection message
        process.nextTick(() => {
            if (params.type === 'server') {
                mountpoint.setServer(connection as Server);
            } else { // if (params.type === 'client') {
                mountpoint.addClient(connection as Client);
            }

            this.emit('connect', connection);
        });

        return connection;
    }

    addTransport(constructor: CasterTransportDefinition): Transport {
        const transport = constructor((this as any) as CasterTransportInterface);
        this._transports.add(transport);
        return transport;
    }

    removeTransport(transport: Transport) {
        this._transports.delete(transport);
    }

    /**
     * Gets a list of sourcetable entries for the caster with an optional set of filters
     *
     * @param filters Optional filters to apply to the sourcetable list
     * @param auth Authentication request for auth filter
     */
    async getSourcetableEntries(filters?: Sourcetable.Filters, auth?: AuthRequest): Promise<Sourcetable.Entry[]> {
        let entries: Sourcetable.Entry[] = Array.from(this._mountpoints.values()).map(m => m.sourceEntry);

        if (filters !== undefined) {
            // Include static entries if not filtering by auth
            if (!filters.auth) entries = this.staticSourcetableEntries.concat(entries);

            // Filter entries
            if (filters.simple !== undefined) entries = entries.filter(e => e.filter(filters.simple!, true, filters.strict!));
            if (filters.advanced !== undefined) entries = entries.filter(e => e.filter(filters.advanced!, false, filters.strict!));

            // Filter authentication
            if (filters?.auth) {
                if (auth === undefined) throw new Error("Attempting to filter sourcetable entries by authentication without providing authentication request");

                const filterResults = await Promise.all(entries.map(async (entry) => {
                    const mountpointAuth: AuthRequest = Object.assign({}, auth);
                    mountpointAuth.mountpoint = (entry as Sourcetable.SourceEntry).mountpoint;
                    return (await this.authenticate(mountpointAuth)).authenticated;
                }))

                entries = entries.filter((e, i) => filterResults[i]);
            }

            // Filter aggregations on all remaining entries
            if (filters?.advanced !== undefined)
                entries = Sourcetable.filterApproximations(filters!.advanced, entries, filters.strict);
        }

        return entries;
    }

    /**
     * Generates the sourcetable for the caster with an optional set of filters
     *
     * @param filters Optional filters to apply to the sourcetable list
     * @param auth Authentication request for auth filter
     */
    async generateSourcetable(filters?: Sourcetable.Filters, auth?: AuthRequest): Promise<string> {
        return (await this.getSourcetableEntries(filters, auth))
            .map(e => e.toSourcetableLine())
            .concat('ENDSOURCETABLE\r\n').join('\r\n');
    }
}

export interface CasterTransportInterface {
    authenticate(request: AuthRequest): Promise<AuthResponse>;
    connect(params: CasterConnectionParameters): Connection;

    generateSourcetable(filters?: Sourcetable.Filters, auth?: AuthRequest): Promise<string>;
}

export type CasterTransportDefinition = (caster: CasterTransportInterface) => Transport;

export interface CasterConnectionParameters {
    type: 'server' | 'client',

    mountpoint: string,

    transport: Transport,
    source: any,

    gga?: string,
    str?: string,

    input?: stream.Readable,
    output?: stream.Writable,
    stream?: stream.Duplex,

    auth?: AuthResponse
}