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

import {HTTPParser} from 'http-parser-ts';

export class NtripHTTPParser extends HTTPParser {
    static readonly REQUEST_EXP = /^(?<method>[A-Z-_]+|SOURCE (?<secret>[^ ]+)) (?<url>[^ ]+)(?: (?<protocol>HTTP|RTSP|RTP)\/(?<versionMajor>\d)\.(?<versionMinor>\d))?$/;

    static readonly RESPONSE_EXP = /^(?<protocol>ICY|SOURCETABLE|HTTP|RTSP)(?:\/(?<versionMajor>\d)\.(?<versionMinor>\d))? (?<code>\d{3}) ?(?<message>.*)$/;
    static readonly ERROR_EXP = /^(?<protocol>ERROR)(?: - (?<message>.*))?$/;

    static readonly methods = HTTPParser.methods.concat(['SOURCE', 'SETUP', 'RECORD', 'PLAY', 'TEARDOWN', 'GET_PARAMETER']).sort();

    socket: any;

    injectedLines: (string | null)[] = [];

    injectLine(line: string | null): void {
        this.injectedLines.push(line);
    }

    consumeLine(): string | undefined {
        return this.injectedLines.pop() ?? super.consumeLine();
    }

    REQUEST_LINE(): void {
        const line = this.consumeLine();
        if (!line) return;
        const match = NtripHTTPParser.REQUEST_EXP.exec(line);
        if (match === null) throw parseError('HPE_INVALID_CONSTANT');

        let method = match!.groups!['method'];
        let protocol = match!.groups!['protocol'] ?? 'HTTP';

        // Process SOURCE request secret
        if (method.startsWith('SOURCE ')) {
            method = 'SOURCE';
            this.info.headers.push('Ntrip-Source-Secret', match!.groups!['secret']);
        }

        this.info.method = NtripHTTPParser.methods.indexOf(method);
        if (this.info.method === -1) throw new Error('invalid request method');

        this.info.url = match!.groups!['url'];
        this.info.headers.push('@protocol', protocol);
        this.socket.protocol = protocol;
        this.info.versionMajor = +(match!.groups!['versionMajor'] ?? 1);
        this.info.versionMinor = +(match!.groups!['versionMinor'] ?? 1);
        // TODO: Discover why keep-alive can't be forced with 1.0
        if (protocol === 'RTSP') {
            this.info.versionMajor = 1;
            this.info.versionMinor = 1;
        }
        this.bodyBytes = 0;
        this.state = 'HEADER';
    }

    RESPONSE_LINE(): void {
        const line = this.consumeLine();
        if (!line) return;
        const match = NtripHTTPParser.RESPONSE_EXP.exec(line) ?? NtripHTTPParser.ERROR_EXP.exec(line);
        if (match === null) throw parseError('HPE_INVALID_CONSTANT');

        let protocol = match!.groups!['protocol'] ?? 'HTTP';

        // Inject newline for casters that don't send second \r\n
        if (['ICY', 'SOURCETABLE', 'ERROR'].includes(protocol)) this.injectLine('');

        let statusCode = +match.groups!['code'];
        let statusMessage = match.groups!['message'];

        // Error message doesn't have status code
        if (isNaN(statusCode)) {
            let statusMessageLower = statusMessage.toLowerCase();
            if (statusMessageLower === 'bad password') {
                statusCode = 401;
            } else if (statusMessageLower === 'already connected') {
                statusCode = 409;
            } else if (statusMessageLower === 'mount point taken or invalid') {
                statusCode = 404;
            } else {
                statusCode = 400;
            }
        }

        this.info.statusCode = statusCode;
        this.info.statusMessage = statusMessage;
        this.info.headers.push('@protocol', protocol);
        this.socket.protocol = protocol;
        this.info.versionMajor = +(match!.groups!['versionMajor'] ?? 1);
        this.info.versionMinor = +(match!.groups!['versionMinor'] ?? 1);
        // TODO: Discover why keep-alive can't be forced with 1.0
        if (protocol === 'RTSP') {
            this.info.versionMajor = 1;
            this.info.versionMinor = 1;
        }

        // Implied zero length
        if ((statusCode / 100 | 0) === 1 || statusCode === 204 || statusCode === 304) {
            this.bodyBytes = 0;
        }
        this.state = 'HEADER';
    }
}

function parseError(code: string) {
    let err = new Error('Parse Error');
    (err as any).code = code;
    return err;
}