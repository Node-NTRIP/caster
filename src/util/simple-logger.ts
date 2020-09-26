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

import {Caster} from "../caster";
import * as events from "events";
import chalk from "chalk";

export class SimpleLogger {
    private registeredListeners: {
        emitter: events.EventEmitter,
        event: string,
        listener: (...args: any[]) => void
    }[] = [];

    constructor(caster: Caster) {
        // Mountpoint created
        this.listen(caster, 'mountpoint', mountpoint => {
            // Mountpoint created
            console.log(chalk`/{red ${mountpoint.name}} ++ Mountpoint created`);

            // Mountpoint closed
            this.listen(mountpoint, 'close', () => {
                console.log(chalk`/{red ${mountpoint.name}} {grey --} Mountpoint closed`);
            })

            // Client connected
            this.listen(mountpoint, 'client', client => {
                console.log(chalk`/{red ${mountpoint.name}} => {italic ${client.transport.description}}://{green ${client.source}} - Client connected to mountpoint`);

                // Client disconnected
                this.listen(client, 'close', () => {
                    console.log(chalk`/{red ${mountpoint.name}} {grey =!} {italic ${client.transport.description}}://{green ${client.source}} - Client disconnected from mountpoint`);
                });
            });

            // Server connected
            this.listen(mountpoint, 'server', server => {
                console.log(chalk`/{red ${mountpoint.name}} <= {italic ${server.transport.description}}://{blue ${server.source}} - Server connected to mountpoint`);

                // Server disconnected
                this.listen(server, 'close', () => {
                    console.log(chalk`/{red ${mountpoint.name}} {grey !=} {italic ${server.transport.description}}://{blue ${server.source}} - Server disconnected from mountpoint`);
                });
            });

            // Server silence
            this.listen(mountpoint, 'silence', () => {
                console.log(chalk`/{red ${mountpoint.name}} {yellow ?=} {italic ${mountpoint.server?.transport.description}}://{blue ${mountpoint.server?.source}} - Server has not sent any data for {bold ${mountpoint.options.silenceWarningTimeout! / 1000} seconds}, may be disconnected due to inactivity`);
            });

            // Server inactivity
            this.listen(mountpoint, 'inactivity', () => {
                console.log(chalk`/{red ${mountpoint.name}} {red !=} {italic ${mountpoint.server?.transport.description}}://{blue ${mountpoint.server?.source}} - Server disconnected due to inactivity for {bold ${mountpoint.options.silenceTimeout! / 1000} seconds}`);
            });

            // Server connection timeout
            this.listen(mountpoint, 'inactivity', () => {
                console.log(chalk`/{red ${mountpoint.name}} - Closed due to no server connection for {bold ${mountpoint.options.connectionTimeout! / 1000} seconds}`);
            });
        });
    }

    private listen(emitter: events.EventEmitter, event: string, listener: (...args: any[]) => void) {
        emitter.on(event, listener);

        this.registeredListeners.push({
            emitter: emitter,
            event: event,
            listener: listener
        });
    }

    disable() {
        for (let listener of this.registeredListeners) {
            listener.emitter.off(listener.event, listener.listener);
        }
    }
}