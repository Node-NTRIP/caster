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

import {NtripHTTPParser} from '../../util/ntrip-http-parser';
NtripHTTPParser.bind();

import http = require('http');
import net = require('net');
import stream = require('stream');

describe('NtripHTTPParser', () => {
    describe('request parsing', () => {
        jest.setTimeout(10);

        let server: http.Server;
        let socket: stream.Duplex;

        beforeEach(() => {
            server = http.createServer();
            server.on('clientError', err => { throw err; });
            socket = new stream.Duplex({
                read: () => {},
                write: (chunk, encoding, callback) => callback()
            });
        });

        afterEach(() => {
            server.close();
            socket.destroy();
        });

        test.each(['HTTP', 'RTSP', 'RTP'])('%s protocol', (type) => {
            return new Promise<void>(resolve => {
                server.on('request', req => {
                    expect(req.headers['@protocol']).toBe(type);
                    resolve();
                });

                socket.push(`GET / ${type}/1.1\r\n\r\n`);
                server.emit('connection', socket);
            });
        });

        test('empty protocol', done => {
            server.on('request', req => {
                expect(req.headers['@protocol']).toBe('HTTP');
                done();
            });

            socket.push(`GET /\r\n\r\n`);
            server.emit('connection', socket);
        });

        test('protocol version', done => {
            server.on('request', req => {
                expect(req.httpVersionMajor).toBe(0);
                expect(req.httpVersionMinor).toBe(9);
                done();
            });
            socket.push('GET / HTTP/0.9\r\n\r\n');
            server.emit('connection', socket);
        });

        test('SOURCE method', done => {
            server.on('request', req => {
                expect(req.method).toBe('SOURCE');
                expect(req.headers['ntrip-source-secret']).toBe('secret');
                done();
            });
            socket.push('SOURCE secret / HTTP/1.1\r\n\r\n');
            server.emit('connection', socket);
        });
    });

    describe('response parsing', () => {
        jest.setTimeout(10);

        let request: http.ClientRequest;
        let socket: stream.Duplex;

        beforeEach(() => {
            socket = new stream.Duplex({
                read: () => {},
                write: (chunk, encoding, callback) => callback()
            });
            request = http.request({
                createConnection: () => socket as net.Socket
            });
        });

        test.each(['ICY', 'SOURCETABLE', 'RTSP', 'HTTP'])('%s protocol', (type) => {
            return new Promise<void>(resolve => {
                request.on('response', req => {
                    expect(req.headers['@protocol']).toBe(type);
                    resolve();
                });

                request.end();
                socket.push(`${type}/1.1 200 OK\r\n\r\n`);
            });
        });

        test('ERROR message', done => {
            request.on('response', req => {
                expect(req.statusCode).toBe(401);
                expect(req.statusMessage).toBe('bad password');
                done();
            });

            request.end();
            socket.push(`ERROR - bad password\r\n\r\n`);
        });

        test('protocol version', done => {
            request.on('response', req => {
                expect(req.httpVersionMajor).toBe(0);
                expect(req.httpVersionMinor).toBe(9);
                done();
            });

            request.end();
            socket.push(`HTTP/0.9 200 OK\r\n\r\n`);
        });

        test('empty protocol version', done => {
            request.on('response', req => {
                expect(req.httpVersionMajor).toBe(1);
                expect(req.httpVersionMinor).toBe(1);
                done();
            });

            request.end();
            socket.push(`ICY 200 OK\r\n\r\n`);
        });
    });
});