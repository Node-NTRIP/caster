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

import events = require('events');

import {CasterConnectionParameters, CasterTransportInterface} from '../caster';
import {Connection} from '../connection';

export abstract class Transport extends events.EventEmitter {
    private readonly _connections: Set<Connection> = new Set<Connection>();
    get connections(): ReadonlySet<Connection> { return this._connections; };

    /**
     * Constructs a new NTRIP transport
     *
     * @param caster NTRIP manager that initiated this transport
     * @param options Options for subclasses
     */
    protected constructor(protected readonly caster: CasterTransportInterface, options: any) {
        super();
    }

    /** Opens any servers necessary for this transport */
    abstract open(): void;
    /** Closes any established servers and existing connections */
    close() {
        this._connections.forEach((connection) => connection.close());
    }

    protected error(error: Error) {
        this.emit('error', error);
        this.close();
    }

    /**
     * Makes a connection to the caster
     *
     * @param params Caster connection parameters, excluding transport
     * @throws TODO
     */
    protected connect(params: Omit<CasterConnectionParameters, 'transport'>): Connection {
        const connection = this.caster.connect({...params, transport: this});

        this._connections.add(connection);
        connection.once('close', () => this._connections.delete(connection));

        return connection;
    }

    /** Returns a description of this transport for use in logging */
    abstract get description(): string;

    /** Returns a description of a specific connection from this transport for use in logging */
    connectionDescription(source: string | object): string {
        return source.toString();
    }
}

export abstract class SingleConnectionTransport extends Transport {
    private _connection?: Connection;
    get connection(): Connection | undefined { return this._connection; }

    protected connect(params: Omit<CasterConnectionParameters, 'transport'>): Connection {
        const connection = super.connect(params);

        connection?.once('close', this.closeWrapper);
        this._connection = connection;

        return connection;
    }

    closeWrapper = () => this.close();

    close() {
        this._connection?.off('close', this.closeWrapper);
        this._connection = undefined;

        super.close();
    }
}