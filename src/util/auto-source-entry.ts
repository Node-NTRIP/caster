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
import ecefProjector = require('ecef-projector');
import countries = require('i18n-iso-countries');
import {Sourcetable} from '../sourcetable';
import {
    RtcmMessage,
    RtcmMessageMsm,
    RtcmMessagePhysicalReferenceStationPosition,
    RtcmMessageReceiverAntennaDescriptor, RtcmMessageStationArp,
    RtcmMessageType,
    RtcmNavSystem,
    RtcmVersion, signalIdMapping
} from '@gnss/rtcm';
import {GeoNames} from '@ntrip/geonames';
import {Mountpoint} from '../mountpoint';
import NavSystem = Sourcetable.NavSystem;

const BITRATE_UPDATE_INTERVAL = 30 * 60 * 1000;
const BITRATE_WARMUP_SHIFT = 12;
const CARRIER_SAMPLING_TIMEOUT = 15 * 1000;
const CARRIER_RESET_INTERVAL = 15 * 60 * 1000;
const LOCATION_ACCURACY_DECIMAL = 4;
const MESSAGES_TIMING_ARRAY_SIZE = 25;
const MESSAGES_TIMING_MINIMUM_COUNT = 3;
const MESSAGES_TIMING_MAX_INTERVAL = 2 * 60 * 1000;
const MESSAGES_TIMING_TRUNCATE_TIMEOUT = 10 * 60 * 1000;
const MESSAGES_UPDATE_INTERVAL = 5 * 1000;
const MESSAGES_TIMEOUT_INTERVAL = 30 * 60 * 1000;
const NAV_SYSTEMS_SAMPLING_TIMEOUT = 15 * 1000;
const NAV_SYSTEMS_RESET_INTERVAL = 15 * 60 * 1000;

const RTCM_NAV_SYSTEM_MAP: Record<RtcmNavSystem, Sourcetable.NavSystem | undefined> = {
    [RtcmNavSystem.GPS]: Sourcetable.NavSystem.GPS,
    [RtcmNavSystem.GLONASS]: Sourcetable.NavSystem.GLONASS,
    [RtcmNavSystem.GALILEO]: Sourcetable.NavSystem.GALILEO,
    [RtcmNavSystem.QZSS]: Sourcetable.NavSystem.QZSS,
    [RtcmNavSystem.SBAS]: Sourcetable.NavSystem.SBAS,
    [RtcmNavSystem.BEIDOU]: Sourcetable.NavSystem.BEIDOU,
    [RtcmNavSystem.IRNSS]: Sourcetable.NavSystem.IRNSS,
    [RtcmNavSystem.FUTURE]: undefined
};

export interface AutoSourceEntryOptions {
    ignoreExisting: boolean;
    setDefault: boolean;

    geoNamesPlaces?: string;

    carrier: boolean;
    country: boolean;
    format: boolean;
    formatDetails: boolean;
    identifier: boolean;
    generator: boolean;
    location: boolean;
    navSystems: boolean;
    bitrate: boolean;
}

/**
 * Automatic sourcetable entry data filler
 *
 * Fills in missing fields in a mountpoint's sourcetable entry based on the data sent by the server.
 * Accepts a stream of {@code RtcmMessage} objects.
 */
export class AutoSourceEntry extends stream.Writable {
    private readonly sourceEntry: Sourcetable.SourceEntry;

    private readonly geoNames?: GeoNames;

    private readonly options: AutoSourceEntryOptions = {
        ignoreExisting: true,
        setDefault: true,

        geoNamesPlaces: undefined,

        carrier: true,
        country: true,
        format: true,
        formatDetails: true,
        identifier: true,
        generator: true,
        location: true,
        navSystems: true,
        bitrate: true
    };

    private carriers: { l1: boolean, l2: boolean } = {l1: false, l2: false};
    private carriersInitialSet = true;
    private location?: { latitude: number, longitude: number };
    private messages: Map<RtcmMessageType, {
        last: number,
        timings: number[]
    }> = new Map();
    private navSystems: RtcmNavSystem[] = [];
    private navSystemsInitialSet = true;
    private rtcmVersion: RtcmVersion = RtcmVersion.V3_0;

    constructor(private readonly mountpoint: Mountpoint, options?: Partial<AutoSourceEntryOptions>) {
        super({objectMode: true});

        const sourceEntry = this.sourceEntry = mountpoint.sourceEntry;

        Object.assign(this.options, options);

        // Ignore values already in the source entry
        if (this.options.ignoreExisting) {
            this.options.carrier = sourceEntry.carrier === undefined;
            this.options.country = sourceEntry.country === undefined;
            this.options.format = sourceEntry.format === undefined;
            this.options.formatDetails = sourceEntry.formatDetails === undefined;
            this.options.identifier = sourceEntry.identifier === undefined;
            this.options.generator = sourceEntry.generator === undefined;
            this.options.location = sourceEntry.latitude === undefined && sourceEntry.longitude === undefined;
            this.options.navSystems = sourceEntry.navSystem === undefined;
        }

        // Set undefined values in source entry to their defaults
        if (this.options.setDefault) {
            this.sourceEntry.carrier = this.sourceEntry.carrier ?? Sourcetable.CarrierPhaseInformation.None;
            this.sourceEntry.nmea = this.sourceEntry.nmea ?? false;
            this.sourceEntry.solution = this.sourceEntry.solution ?? Sourcetable.SolutionType.SingleBase;
            this.sourceEntry.compressionEncryption = this.sourceEntry.compressionEncryption ?? 'none';
        }

        // List of places to use for location/country
        if (options?.geoNamesPlaces !== undefined)
            this.geoNames = new GeoNames(options?.geoNamesPlaces);

        if (this.options.formatDetails) {
            setInterval(() => this.updateFormatDetails(), MESSAGES_UPDATE_INTERVAL);
            setInterval(() => this.truncateFormatDetails(), MESSAGES_TIMEOUT_INTERVAL);
        }

        if (this.options.carrier) {
            setInterval(() => {
                this.carriers.l1 = false;
                this.carriers.l2 = false;
                this.options.carrier = true;
            }, CARRIER_RESET_INTERVAL);
            setTimeout(() => {
                setInterval(() => {
                    this.options.carrier = false;
                    this.updateCarriers();
                }, CARRIER_RESET_INTERVAL);

                this.options.carrier = false;
                this.carriersInitialSet = false;
            }, CARRIER_SAMPLING_TIMEOUT);
        }

        if (this.options.navSystems) {
            setInterval(() => {
                this.navSystems = [];
                this.options.navSystems = true;
            }, NAV_SYSTEMS_RESET_INTERVAL);
            setTimeout(() => {
                setInterval(() => {
                    this.options.navSystems = false;
                    this.updateNavSystems();
                }, NAV_SYSTEMS_RESET_INTERVAL);

                this.options.navSystems = false;
                this.navSystemsInitialSet = false;
            }, NAV_SYSTEMS_SAMPLING_TIMEOUT);
        }

        if (this.options.bitrate)
            this.updateBitrate(this.mountpoint.stats.in, BITRATE_WARMUP_SHIFT);
    }

    _write(message: RtcmMessage, encoding: string, callback: (error?: (Error | null)) => void): void {
        const constructor = message.constructor as typeof RtcmMessage;

        // Update RTCM version to minimum necessary
        this.updateRtcmVersion(constructor.sinceVersion);

        // Include message type in format details
        this.addToFormatDetails(message.messageType);

        // Include GNSS system if message (if any)
        this.addToNavSystems(constructor.navSystem);

        // Set receiver type as data generator
        if (message instanceof RtcmMessageReceiverAntennaDescriptor) this.updateGenerator(message.receiverTypeDescriptor);

        // Set station location (latitude/longitude, country, city)
        if (message instanceof RtcmMessageStationArp || message instanceof RtcmMessagePhysicalReferenceStationPosition) {
            const [latitude, longitude] = ecefProjector.unproject(
                    message.arpEcefX / 10000, message.arpEcefY / 10000, message.arpEcefZ / 10000);
            this.updateLocation({latitude: latitude, longitude: longitude});
        }

        // Calculate RTK carrier
        if (this.options.carrier) {
            switch (message.messageType) {
                case RtcmMessageType.GPS_L1_OBSERVATIONS:
                case RtcmMessageType.GPS_L1_OBSERVATIONS_EXTENDED:
                case RtcmMessageType.GLONASS_L1_OBSERVATIONS:
                case RtcmMessageType.GLONASS_L1_OBSERVATIONS_EXTENDED:
                    this.addToCarriers(true);
                    break;
                case RtcmMessageType.GPS_L1_L2_OBSERVATIONS:
                case RtcmMessageType.GPS_L1_L2_OBSERVATIONS_EXTENDED:
                case RtcmMessageType.GLONASS_L1_L2_OBSERVATIONS:
                case RtcmMessageType.GLONASS_L1_L2_OBSERVATIONS_EXTENDED:
                    this.addToCarriers(true, true);
                    break;
            }

            if (message instanceof RtcmMessageMsm) {
                const frequencySet = new Set(message.info.signalIds.map(id => signalIdMapping[constructor.navSystem!][id][0]));
                this.addToCarriers(frequencySet.has(1), frequencySet.has(2));
            }
        }

        callback();
    }

    private updateLocation(val: { latitude: number, longitude: number }) {
        const accuracy = Math.pow(10, LOCATION_ACCURACY_DECIMAL);
        val.longitude = Math.round(val.longitude * accuracy) / accuracy;
        val.latitude = Math.round(val.latitude * accuracy) / accuracy;
        if (this.location?.longitude === val.longitude && this.location?.latitude === val.latitude) return;
        this.location = val;

        if (this.options.location) {
            this.sourceEntry.latitude = val.latitude;
            this.sourceEntry.longitude = val.longitude;
        }

        // Update country and location identifier if places are available
        this.geoNames?.nearest(val).then((place) => {
            if (place === undefined) return;

            if (this.options.country)
                this.sourceEntry.country = countries.alpha2ToAlpha3(place.countryCode);

            if (this.options.identifier)
                this.sourceEntry.identifier = place.asciiName;
        });
    }

    private updateGenerator(val: string) {
        if (this.options.generator) this.sourceEntry.generator = val;
    }

    private addToFormatDetails(type: RtcmMessageType) {
        if (!this.options.formatDetails) return;

        const current = Date.now();

        if (!this.messages.has(type)) {
            this.messages.set(type, {
                last: current,
                timings: []
            });

            this.updateFormatDetails();
            return;
        }

        const timing = this.messages.get(type)!;
        const time = (current - timing.last) / 1000;

        timing.last = current;
        timing.timings.push(time);
        if (timing.timings.length > MESSAGES_TIMING_ARRAY_SIZE) timing.timings.shift();
        if (timing.timings.length === MESSAGES_TIMING_MINIMUM_COUNT) this.updateFormatDetails();
    }

    private updateFormatDetails() {
        const messages = [];
        for (const [messageType, timing] of this.messages) {
            const average = Math.round(timing.timings.reduce((a, b) => a + b, 0)
                    / Math.max(timing.timings.length, 1));

            // Ignore inconsistent intervals to avoid burst messages (e.g. ephemerides, MSM multi message)
            const includeInterval = average <= MESSAGES_TIMING_MAX_INTERVAL && average > 0
                    && timing.timings.length >= MESSAGES_TIMING_MINIMUM_COUNT
                    && timing.timings.every(t => t < 5 * average);
            messages.push({
                type: messageType,
                rate: includeInterval ? average : undefined
            });
        }
        this.sourceEntry.formatDetails = messages.sort((a, b) => a.type - b.type);
    }

    private truncateFormatDetails() {
        const cutoff = Date.now() - MESSAGES_TIMING_TRUNCATE_TIMEOUT;
        for (const [messageType, timing] of this.messages) if (timing.last < cutoff) this.messages.delete(messageType);
    }

    private updateBitrate(old: number, warmup: number) {
        const current = this.mountpoint.stats.in;
        this.sourceEntry.bitrate = Math.round((current - old) * 8 * 1000 / (BITRATE_UPDATE_INTERVAL >> warmup));
        setTimeout(() => {
            this.updateBitrate(current, Math.max(0, warmup - 1))
        }, BITRATE_UPDATE_INTERVAL >> Math.max(0, warmup - 1));
    }

    private updateRtcmVersion(val: RtcmVersion) {
        if (!this.options.format) return;
        if (val <= this.rtcmVersion) return;
        if (val === RtcmVersion.FUTURE) return; // Ignore future messages, version is currently unknown to us
        this.rtcmVersion = val;
        this.sourceEntry.format = `RTCM ${val.toFixed(1)}`;
    }

    private addToNavSystems(rtcmSystem: RtcmNavSystem | null) {
        if (rtcmSystem === null) return;
        if (this.navSystems.includes(rtcmSystem)) return;

        this.navSystems.push(rtcmSystem!);
        if (this.navSystemsInitialSet) this.updateNavSystems();
    }

    private updateNavSystems() {
        const navSystems = Object.values(Sourcetable.NavSystem);
        this.sourceEntry.navSystem = Array.from(this.navSystems.map(s => RTCM_NAV_SYSTEM_MAP[s]))
                .filter((s): s is NavSystem => s !== undefined)
                .sort((a, b) => navSystems.indexOf(a) - navSystems.indexOf(b));
    }

    private addToCarriers(l1: boolean = false, l2: boolean = false) {
        if (!this.options.carrier) return;

        this.carriers.l1 = this.carriers.l1 || l1;
        this.carriers.l2 = this.carriers.l2 || l2;

        if (this.carriersInitialSet) this.updateCarriers();
    }

    private updateCarriers() {
        this.sourceEntry.carrier = this.carriers.l1 ?
                (this.carriers.l2 ?
                        Sourcetable.CarrierPhaseInformation.L1_L2 : Sourcetable.CarrierPhaseInformation.L1)
                : Sourcetable.CarrierPhaseInformation.None;
    }
}