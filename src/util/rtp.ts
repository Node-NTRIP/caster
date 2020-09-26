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

import crypto = require('crypto');
import dgram = require('dgram');
import stream = require('stream');

export interface RtpPacketData {
    padding?: boolean;
    marker?: boolean;
    extension?: {
        header: number,
        length: number,
        content: Buffer
    };
    payloadType: number;
    sequenceNumber: number;
    timestamp: number;
    ssrc: number;
    csrc?: number[];
    payload?: Buffer;
}

/**
 * RTP packet
 *
 * Read only class representing an RTP packet, with helper functions for parsing/serialization.
 */
export class RtpPacket {
    static readonly RTP_VERSION = 2;

    static readonly RTP_PACKET_MIN_HEADER_SIZE = 12;

    readonly padding: boolean;
    readonly marker: boolean;
    readonly payloadType: number;

    readonly sequenceNumber: number;
    readonly timestamp: number;
    readonly ssrc: number;
    readonly csrc: number[];

    readonly extension?: {
        header: number,
        length: number,
        content: Buffer
    };

    readonly payload?: Buffer;

    constructor({
        payloadType,
        padding = false,
        marker = false,
        sequenceNumber,
        timestamp,
        ssrc,
        csrc = [],
        extension,
        payload}: RtpPacketData) {
        this.padding = padding;
        this.marker = marker;
        this.payloadType = payloadType;
        this.sequenceNumber = sequenceNumber;
        this.timestamp = timestamp;
        this.ssrc = ssrc;
        this.csrc = csrc;
        this.extension = extension;
        this.payload = payload;
    }

    get length(): number {
        return 0x0c + (this.csrc.length * 4)
                + (this.extension !== undefined ? this.extension.length + 4 : 0)
                + (this.payload?.length ?? 0);
    }

    /**
     * Reads an RtpPacket from the provided buffer
     *
     * @param buffer Buffer to read packet from
     */
    static fromBuffer(buffer: Buffer): RtpPacket {
        RtpPacket.fromBufferAssertLength(buffer, RtpPacket.RTP_PACKET_MIN_HEADER_SIZE);

        // Version (V)
        const v = (buffer[0] & 0b1100_0000) >>> 6;
        if (v != RtpPacket.RTP_VERSION)
            throw new Error(`Invalid RTP packet provided: Version must be equal to 2, ${v} found`);

        // Padding (P)
        const p = (buffer[0] & 0b0010_0000) != 0;
        // Extension (X)
        const x = (buffer[0] & 0b0001_0000) != 0;
        // CSRC count (CC)
        const cc = (buffer[0] & 0b0000_1111);

        // Marker (M)
        const m = (buffer[1] & 0b1000_0000) != 0;
        // Payload type (PT)
        const pt = (buffer[1] & 0b0111_1111);

        const sequenceNumber = buffer.readUInt16BE(0x02);
        const timestamp = buffer.readUInt32BE(0x04);
        const ssrc = buffer.readUInt32BE(0x08);

        RtpPacket.fromBufferAssertLength(buffer, RtpPacket.RTP_PACKET_MIN_HEADER_SIZE + (cc * 4), "with CSRC");

        const csrc = [];
        for (let c = 0; c < cc; c++) csrc.push(buffer.readUInt32BE(0x0c + (c * 4)));

        let offset = 0x0c + (cc * 4);

        let extension;
        if (x) {
            RtpPacket.fromBufferAssertLength(buffer, RtpPacket.RTP_PACKET_MIN_HEADER_SIZE + (cc * 4) + 4, "with extension header");
            const extensionHeader = buffer.readUInt16BE(offset);
            const extensionLength = buffer.readUInt16BE(offset + 2);
            RtpPacket.fromBufferAssertLength(buffer, RtpPacket.RTP_PACKET_MIN_HEADER_SIZE + (cc * 4) + 4 + extensionLength, "with extension content");
            const extensionContent = buffer.slice(offset + 4, offset + 4 + extensionLength);
            extension = {
                header: extensionHeader,
                length: extensionLength,
                content: extensionContent
            };

            offset += 4 + extensionLength;
        }

        const payload = buffer.slice(offset);

        return new RtpPacket({
            padding: p,
            marker: m,
            payloadType: pt,
            sequenceNumber: sequenceNumber,
            timestamp: timestamp,
            ssrc: ssrc,
            csrc: csrc,
            extension: extension,
            payload: payload
        });
    }

    private static fromBufferAssertLength(buffer: Buffer, length: number, content?: string): void {
        if (buffer.length < length) {
            throw new Error(`Invalid RTP packet: Buffer not large enough to contain ${length} byte header` +
                    (content === undefined ? '' : " " + content));
        }
    }

    /**
     * Writes an RtpPacket to a (provided) buffer
     *
     * @param packet Packet to write to buffer
     * @param buffer Optional buffer to write packet to
     *
     * If a buffer is not provided, a new buffer is allocated with the appropriate length.
     */
    static toBuffer(packet: RtpPacket, buffer?: Buffer): Buffer {
        buffer = buffer ?? Buffer.allocUnsafe(packet.length);
        if (buffer.length < packet.length)
            throw new Error('Provided buffer is not large enough to write packet');

        // Version (V)
        buffer[0] = RtpPacket.RTP_VERSION << 6;
        // Padding (P)
        if (packet.padding) buffer[0] |= 0b0010_0000;
        // Extension (X)
        if (packet.extension != null) buffer[0] |= 0b0001_0000;
        // CSRC count (CC)
        buffer[0] |= packet.csrc.length & 0b0000_1111;

        buffer[1] = 0;
        // Marker (M)
        if (packet.marker) buffer[1] |= 0b1000_0000;
        // Payload type (PT)
        buffer[1] |= packet.payloadType & 0b0111_1111;

        buffer.writeUInt16BE(packet.sequenceNumber, 0x02);
        buffer.writeUInt32BE(packet.timestamp, 0x04);
        buffer.writeUInt32BE(packet.ssrc, 0x08);

        const cc = Math.min(16, packet.csrc.length);
        for (let c = 0; c < cc; c++) buffer.writeUInt32BE(packet.csrc[c], 0x0c + (c * 4));

        let offset = 0x0c + (cc * 4);

        if (packet.extension != null) {
            buffer.writeUInt16BE(packet.extension.header, offset);
            buffer.writeUInt16BE(packet.extension.length, offset + 2);
            packet.extension.content.copy(buffer, offset + 4, 0, packet.extension.length);

            offset += 4 + packet.extension.length;
        }

        packet.payload?.copy(buffer, offset);

        return buffer;
    }
}

/**
 * RTP Session
 *
 * Class representing a unique RTP stream, with a single SSRC. Manages sequence number and timestamp.
 */
export class RtpSession extends stream.Duplex {
    static readonly DEFAULT_TIMESTAMP_PERIOD_NS = 125000;
    static readonly DEFAULT_BUFFER_SIZE = 1446;

    private readonly buffer: Buffer;

    sequenceNumber: number = crypto.randomBytes(2).readUInt16BE(0);
    timestamp: number = crypto.randomBytes(4).readUInt32BE(0);
    ssrc: number = crypto.randomBytes(4).readUInt32BE(0);

    private time: bigint = process.hrtime.bigint();
    private readonly timestampPeriod: number;

    constructor(private readonly socket: dgram.Socket, {
        timestampPeriod = RtpSession.DEFAULT_TIMESTAMP_PERIOD_NS,
        bufferSize = RtpSession.DEFAULT_BUFFER_SIZE
    }: {
        timestampPeriod?: number,
        bufferSize?: number
    }) {
        super({
            readableObjectMode: true,
            writableObjectMode: true
        });

        this.timestampPeriod = timestampPeriod;
        this.buffer = Buffer.allocUnsafe(bufferSize);

        socket.on('message', message => this.receive(message));
        socket.once('error', err => this.destroy(err));
    }

    newSequenceNumber(): number {
        this.sequenceNumber++;
        this.sequenceNumber &= 0xffff;

        return this.sequenceNumber;
    }

    newTimestamp(): number {
        const time = process.hrtime.bigint();
        this.timestamp += Number(time - this.time) / this.timestampPeriod;
        this.timestamp &= 0xffffffff;
        this.timestamp >>>= 0;
        this.time = time;

        return this.timestamp;
    }

    regenerateSsrc() {
        this.ssrc = crypto.randomBytes(4).readUInt32BE(0);
    }

    private receive(message: Buffer) {
        try {
            this.push(RtpPacket.fromBuffer(message));
        } catch (err) {
            this.destroy(err);
        }
    }

    _read(size: number): void { }

    _write(packet: any, encoding: string, callback: (error?: (Error | null)) => void): void {
        if (!(packet instanceof RtpPacket)) return callback(new Error("Can only accept RtpPackets"));

        try {
            RtpPacket.toBuffer(packet, this.buffer);
        } catch (err) {
            return callback(err);
        }

        this.socket.send(this.buffer, 0, packet.length, callback);
    }

    _destroy(error: Error | null, callback: (error: (Error | null)) => void): void {
        this.socket.close(() => callback(null));
    }
}

/**
 * RTP Packet Payload Data Stream
 *
 * Helper stream for reading/writing raw data to/from a specific payload type in an RTP session.
 */
export class RtpPacketPayloadStream extends stream.Duplex {
    // Buffering
    private readonly buffer?: Buffer;
    private bufferOffset?: number;
    private get bufferRemaining(): number { return this.buffer!.length - this.bufferOffset!; }
    private readonly bufferHighWaterMark?: number;
    private readonly bufferTimeoutMs?: number;
    private bufferTimeout?: number = undefined;

    constructor(private session: RtpSession, private readonly payloadType: number,
            bufferOptions?: {
                bufferSize: number,
                bufferHighWaterMark: number,
                bufferTimeout: number
            }) {
        super();

        if (bufferOptions !== undefined) {
            this.buffer = Buffer.allocUnsafe(bufferOptions.bufferSize);
            this.bufferOffset = 0;
            this.bufferHighWaterMark = bufferOptions.bufferHighWaterMark;
            this.bufferTimeoutMs = bufferOptions.bufferTimeout;
        }

        session.once('close', () => this.destroy());
        session.once('error', err => this.destroy(err));

        session.pipe(new stream.Writable({
            objectMode: true,
            write: (packet: RtpPacket, encoding: string, callback: (error?: (Error | null)) => void): void => {
                // Push packet payload contents to stream if correct type
                if (packet.payloadType == this.payloadType) this.push(packet.payload);

                callback();
            }
        }));
    }

    private send(payload: Buffer, callback?: (error?: (Error | null)) => void): void {
        this.session.write(new RtpPacket({
            payloadType: this.payloadType,
            sequenceNumber: this.session.newSequenceNumber(),
            timestamp: this.session.newTimestamp(),
            ssrc: this.session.ssrc,
            payload: payload
        }), callback);
    }

    private async writeBuffer(chunk: Buffer) {
        // Set timeout to flush unless buffer gets filled in meantime
        if (this.bufferTimeout === undefined)
            this.bufferTimeout = setTimeout(() => {
                this.flushBuffer().catch(err => this.destroy(err));
            }, this.bufferTimeoutMs);

        // Always avoid splitting chunk, unless splitting will happen anyway
        if (chunk.length <= this.buffer!.length) {
            // Chunk could fit in single packet, but too long with existing buffer contents, so flush first
            if (chunk.length > this.bufferRemaining) await this.flushBuffer();

            chunk.copy(this.buffer!, this.bufferOffset);
            this.bufferOffset! += chunk.length;
        } else {
            // Write entire chunk as efficiently as possible
            let chunkOffset = 0;
            while (chunkOffset < chunk.length) {
                const write = Math.min(chunk.length - chunkOffset, this.bufferRemaining);
                chunk.copy(this.buffer!, this.bufferOffset, chunkOffset, chunkOffset + write);
                this.bufferOffset! += write;
                chunkOffset += write;

                // Flush along the way if buffer is full
                if (this.bufferRemaining === 0) await this.flushBuffer();
            }
        }

        // Flush if buffer is filled above high water mark
        if (this.bufferOffset! > this.bufferHighWaterMark!) await this.flushBuffer();
    }

    private async flushBuffer(): Promise<void> {
        clearTimeout(this.bufferTimeout);
        this.bufferTimeout = undefined;
        await new Promise((resolve, reject) => {
            this.send(this.buffer!.slice(0, this.bufferOffset), err => {
                if (err instanceof Error) reject(err);
                else resolve();
            });
        });
        this.bufferOffset = 0;
    }

    _read(size: number): void { }

    _write(chunk: any, encoding: string, callback: (error?: (Error | null)) => void): void {
        if (typeof chunk === 'string')
            chunk = Buffer.from(chunk as string, encoding as BufferEncoding);

        if (this.buffer === undefined) return this.send(chunk, callback);
        else this.writeBuffer(chunk).then(callback as () => void).catch(callback);
    }

    _final(callback: (error?: (Error | null)) => void): void {
        if (this.buffer !== undefined && this.bufferOffset != 0) {
            this.flushBuffer().then(callback as () => void).catch(callback);
        } else {
            callback();
        }
    }
}

export enum NtripRtpMessageType {
    DATA_STREAM = 96,
    HTTP = 97,
    CONNECTION_END = 98
}

export class NtripRtpSession extends RtpSession {
    static readonly PACKET_MAX_SIZE = 1526;
    static readonly TIMESTAMP_PERIOD_NS = 125000;

    static readonly DATA_PACKET_MAX_CONTENT_SIZE = 1514;
    static readonly DATA_PACKET_HIGH_WATER_MARK = NtripRtpSession.DATA_PACKET_MAX_CONTENT_SIZE * 0.75;
    static readonly DATA_PACKET_TIMEOUT_MS = 50;

    constructor(socket: dgram.Socket) {
        super(socket, {
            timestampPeriod: NtripRtpSession.TIMESTAMP_PERIOD_NS,
            bufferSize: NtripRtpSession.PACKET_MAX_SIZE
        });

        this.dataStream.once('close', () => this.end());
    }

    push(packet: RtpPacket, encoding?: BufferEncoding): boolean {
        if (packet.payloadType === NtripRtpMessageType.CONNECTION_END) this.end();
        return super.push(packet, encoding);
    }

    _final(callback: (error?: (Error | null)) => void): void {
        this.write(new RtpPacket({
            payloadType: NtripRtpMessageType.CONNECTION_END,
            sequenceNumber: this.newSequenceNumber(),
            timestamp: this.newTimestamp(),
            ssrc: this.ssrc
        }), callback);
    }

    public readonly dataStream = new RtpPacketPayloadStream(this, NtripRtpMessageType.DATA_STREAM, {
        bufferSize: NtripRtpSession.DATA_PACKET_MAX_CONTENT_SIZE,
        bufferHighWaterMark: NtripRtpSession.DATA_PACKET_HIGH_WATER_MARK,
        bufferTimeout: NtripRtpSession.DATA_PACKET_TIMEOUT_MS
    });

    public readonly httpStream = new RtpPacketPayloadStream(this, NtripRtpMessageType.HTTP);
}