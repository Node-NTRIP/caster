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

import VError from 'verror';

export namespace Sourcetable {
    /**
     * An entry in the caster sourcetable
     *
     * Provides helper methods for filtering sourcetable entries and generating sourcetable text lines.
     */
    export abstract class Entry {
        /** The sourcetable entry type as 3 characters e.g. STR, CAS, NET */
        get entryType(): string {
            return (this.constructor as any).ENTRY_TYPE;
        };

        /**
         * Returns the entry as a sourcetable text line
         */
        toSourcetableLine(): string {
            return this.toSourcetableLineElements()
                    .map(item => item ?? '')
                    .join(';');
        };

        /**
         * Returns a list of elements included in the entry's sourcetable text line
         */
        toSourcetableLineElements(): Element[] {
            let result = Entry.structureElementsToLine(
                    this.toRawSourcetableLineElements(),
                    (this.constructor as any).STRUCTURING_CONVERSIONS);

            // Insert entry type
            result.unshift(this.entryType);

            return result;
        }

        /**
         * Returns a list of elements included in the entry's sourcetable text line in their raw form
         *
         * Same as {@link #toSourcetableLineElements} but without elements converted to strings and numbers
         */
        abstract toRawSourcetableLineElements(): any[]

        /**
         * Parses the provided sourcetable text line and updates fields in this entry
         *
         * @param line Sourcetable text line
         */
        fromSourcetableLine(line: string): void {
            const elements = line.split(';');
            if (elements[0] !== this.entryType) throw new Error(`Unexpected entry type: ${elements[0]}`);

            this.fromSourcetableLineElements(elements);
        };

        /**
         * Updates the entry's elements based on the provided list of elements
         */
        fromSourcetableLineElements(elements: string[]): void {
            // Remove entry type
            elements = elements.slice(1);

            this.fromRawSourcetableLineElements(
                    Entry.destructureElementsFromLine(elements,
                            (this.constructor as any).DESTRUCTURING_CONVERSIONS));
        }

        /**
         * Updates the entry's elements based on the provided list of elements in their raw form
         *
         * Same as {@link #fromSourcetableLineElements} but with elements converted from strings and numbers
         */
        abstract fromRawSourcetableLineElements(elements: any[]): void;

        static destructureElementsFromLine(elements: string[], destructuringConversions: (null | ((s: string) => any))[]): any[] {
            return elements.map((element, index) => {
                element = element.trim();
                if (element.length === 0) return undefined;

                const conversion = destructuringConversions[index];
                if (conversion === null || conversion === undefined) return element;

                let value = conversion(element);

                // Treat NaN as error/undefined
                if (typeof value === 'number' && isNaN(value)) return undefined;
                return value;
            });
        }

        static structureElementsToLine(elements: any[], structuringConversions: (null | ((e: any) => Element))[]): Element[] {
            return elements.map((element, index) => {
                if (element == undefined) return element;

                const conversion = structuringConversions[index];
                if (conversion === null || conversion === undefined) return element as (string | number);

                return conversion(element);
            });
        }

        /**
         * Filter this source entry by simple and advanced element filtering
         *
         * @param filters Filter lists
         * @param simple Whether a simple search is being performed
         * @param strict Whether to throw errors when an invalid condition is found
         */
        filter(filters: AdvancedFilterList[], simple: boolean, strict: boolean = false): boolean {
            return filters.every(f => this.filterElements(f, simple, strict));
        }

        /**
         * Filters this source entry based on its elements
         *
         * @param filters List of filters for each element
         * @param simple Whether a simple search is being performed
         * @param strict Whether to throw errors when an invalid condition is found
         */
        private filterElements(filters: AdvancedFilterList, simple: boolean, strict: boolean): boolean {
            // No filtering to be done if elements list is empty
            if (filters.length == 0) return true;

            const elements = this.toSourcetableLineElements();

            // Was a specific entry type requested
            const typeRequested = typeof filters[0] === 'string' &&
                    [CasterEntry.ENTRY_TYPE, NetworkEntry.ENTRY_TYPE, SourceEntry.ENTRY_TYPE].includes(filters[0]);

            // Prevent ambiguity in strict mode
            if (!simple && strict && !typeRequested)
                throw new Error("Sourcetable entry type was not selected in filter, will result in search term ambiguity");

            // Check if all filter conditions are met
            return filters.every((filter, i) => {
                const element = elements[i];

                // Don't check match for undefined elements
                if (filter === undefined) return true;

                // If element is provided but not set for entry, match fails
                if (element === undefined) return false;

                // Simple matching, loosely compare values
                if (typeof filter === 'string') return element == filter;

                // Number approximation filter (for closest stream) is applied later
                if (typeof filter === 'number') return true;

                const {string, number} = filter;

                const newParseError = (type: 'string' | 'number', cause: Error) =>
                        new VError(cause, "Could not parse sourcetable entry %s element using provided filters", type);

                // Advanced comparison with operators
                if (typeof element === 'string') {
                    if (string instanceof Error) {
                        if (strict) throw newParseError('string', string);
                        // Be as forgiving as possible by default
                        return true;
                    }

                    // Attempt to match
                    return string.test(element);
                } else { // if (typeof selfElement === "number") {
                    if (number instanceof Error) {
                        if (strict) throw newParseError('number', number);
                        // Be as forgiving as possible by default
                        return true;
                    }

                    // Attempt to match
                    return number.some(terms => // One of ORs must be true
                            terms.every(term => { // All ANDs must be true
                                if (term instanceof Error) {
                                    if (strict) throw newParseError('number', term);
                                    // Be as forgiving as possible by default
                                    return true;
                                }

                                return term.test(element as number);
                            })
                    );
                }
            });
        }

        /**
         * Parses the provided sourcetable text line and returns a corresponding sourcetable entry object
         *
         * @param line Sourcetable text line
         */
        static parseSourcetableLine(line: string): Entry | Error {
            let entry: Entry;
            if (line.startsWith(CasterEntry.ENTRY_TYPE)) {
                entry = new CasterEntry('', 0);
            } else if (line.startsWith(NetworkEntry.ENTRY_TYPE)) {
                entry = new NetworkEntry('');
            } else if (line.startsWith(SourceEntry.ENTRY_TYPE)) {
                entry = new SourceEntry('');
            } else {
                return new Error(`Unexpected sourcetable entry type: ${line.slice(0, 3)}`);
            }
            entry.fromSourcetableLine(line);
            return entry;
        }
    }

    function fromOneZeroValue(val: string): boolean {
        return val === '1';
    }

    function toOneZeroValue(val: boolean): string {
        return val ? '1' : '0';
    }

    function fromYesNoValue(val: string): boolean {
        return val === 'Y';
    }

    function toYesNoValue(val: boolean): string {
        return val ? 'Y' : 'N';
    }

    function fromFormatDetails(val: string) {
        let rawTypes = val.split(',');
        let parsedTypes = rawTypes.map(type => /^(?<type>.+)(?:\((?<rate>[0-9]+)\))?$/.exec(type)?.groups);
        return parsedTypes.some(t => t === undefined) ? rawTypes : parsedTypes;
    }

    function toFormatDetails(val: {type: string, rate?: number}[] | string[] | string) {
        if (!(val instanceof Array)) return val;
        if (val.length === 0) return '';
        if (typeof val[0] === 'object') {
            val = (val as { type: string, rate?: number }[])
                    .map(type => `${type.type}${type.rate === undefined ? '' : `(${type.rate})`}`);
        }
        return val.join(',');
    }

    export class SourceEntry extends Entry {
        mountpoint: string;                 // Caster mountpoint
        identifier?: string;                // Source identifier, e.g. name of city next to source location
        format?: Sourcetable.Format | string;           // Data format RTCM, RAW, etc
        formatDetails?: {type: string | number, rate?: number}[] | string[] | string;  // E.g. RTCM message types or RAW data format etc., update periods in parenthesis in seconds
        carrier?: Sourcetable.CarrierPhaseInformation | number; // Data stream contains carrier phase information
        // 0 = No (e.g. for DGPS)
        // 1 = Yes, L1 (e.g. for RTK)
        // 2 = Yes, L1&L2 (e.g. for RTK)
        navSystem?: (Sourcetable.NavSystem | string)[]; // Navigation system(s)
        network?: string;                   // Network
        country?: string;                   // Three character country code in ISO3166
        latitude?: number;                  // Position, latitude, north (approximate position in case of nmea = 1)
        longitude?: number;                 // Position, longitude, east (approximate position in case of nmea = 1)
        nmea?: boolean;                     // Necessity for Client to send NMEA message with approximate position to Caster
        // 0 = Client must not send NMEA message with approximate position to Caster
        // 1 = Client must send NMEA GGA message with approximate position to Caster
        solution?: Sourcetable.SolutionType | number;   // Stream generated from single reference station or from networked reference stations
        // 0 = Single base
        // 1 = Network
        generator?: string;                 // Hard- or software generating data stream
        compressionEncryption?: string;     // Compression/Encryption algorithm applied
        authentication?: Sourcetable.AuthenticationMode | string; // Access protection for this particular data stream, N = None, B = Basic, D = Digest
        fee?: boolean;                      // User fee for receiving this particular data stream, N = No user fee, Y = Usage is charged
        bitrate?: number;                   // Bit rate of data stream, bits per second
        misc?: string[];                    // Miscellaneous information, last data field in record

        static readonly ENTRY_TYPE = 'STR';

        static readonly DESTRUCTURING_CONVERSIONS: (null | ((s: string) => any))[] = [
            null, null, null, fromFormatDetails, parseInt, (s) => s.split('+'), null, null, parseFloat, parseFloat,
            fromOneZeroValue, parseInt, null, null, null, fromYesNoValue, parseFloat];

        static readonly STRUCTURING_CONVERSIONS: (null | ((e: any) => string | number | undefined))[] = [
            null, null, null, toFormatDetails, null, (e) => e.join('+'), null, null, null, null,
            toOneZeroValue, null, null, null, null, toYesNoValue, null];

        constructor(mountpoint: string) {
            super();
            this.mountpoint = mountpoint;
        }

        fromRawSourcetableLineElements(elements: any[]): void {
            if (typeof elements[0] === 'string') this.mountpoint = elements[0];

            [, this.identifier, this.format, this.formatDetails, this.carrier, this.navSystem,
                this.network, this.country, this.latitude, this.longitude, this.nmea, this.solution, this.generator,
                this.compressionEncryption, this.authentication, this.fee, this.bitrate, ...this.misc] = elements;
        }

        toRawSourcetableLineElements(): any[] {
            return [this.mountpoint, this.identifier, this.format, this.formatDetails, this.carrier, this.navSystem,
                this.network, this.country, this.latitude, this.longitude, this.nmea, this.solution, this.generator,
                this.compressionEncryption, this.authentication, this.fee, this.bitrate, ...(this.misc ?? ['none'])];
        }
    }

    export class CasterEntry extends Entry {
        host: string;              // Caster Internet host domain name or IP address
        port: number;              // Port number
        identifier?: string;                // Caster identifier, e.g. name of provider
        operator?: string;                  // Name of institution / agency / company operating the Caster
        nmea?: Sourcetable.SolutionType | number;       // Capability of Caster to receive NMEA message with approximate position from Client
        // 0 = Caster is not able to handle incoming NMEA message with approximate position from Client
        // 1 = Caster is able to handle incoming NMEA GGA message with approximate position from Client
        country?: string;                   // Three character country code in ISO 3166
        latitude?: number;                  // Position, latitude, north
        longitude?: number;                 // Position, longitude, east
        fallback_host?: string = '0.0.0.0'; // Fallback Caster IP address, No Fallback: 0.0.0.0
        fallback_port?: number = 0;         // Fallback Caster port number, No Fallback: 0
        misc?: string[];          // Miscellaneous information, last data field in record

        static readonly ENTRY_TYPE = 'CAS';

        static readonly DESTRUCTURING_CONVERSIONS: (null | ((s: string) => any))[] = [
            null, parseInt, null, null, parseInt, null, parseFloat, parseFloat, null, parseInt];

        static readonly STRUCTURING_CONVERSIONS: (null | ((e: any) => string | number | undefined))[] = [
            null, null, null, null, null, null, null, null, null, null];

        constructor(host: string, port: number) {
            super();
            this.host = host;
            this.port = port;
        }

        fromRawSourcetableLineElements(elements: any[]): void {
            if (typeof elements[0] === 'string') this.host = elements[0];
            if (typeof elements[1] === 'number') this.port = elements[1];

            [, , this.identifier, this.operator, this.nmea, this.country,
                this.latitude, this.longitude, this.fallback_host, this.fallback_port, ...this.misc] = elements;
        }

        toRawSourcetableLineElements(): any[] {
            return [this.host, this.port, this.identifier, this.operator, this.nmea, this.country,
                this.latitude, this.longitude, this.fallback_host, this.fallback_port, ...(this.misc ?? ['none'])];
        }
    }

    export class NetworkEntry extends Entry {
        identifier: string;        // Network identifier, e.g. name of a network of GNSS permanent reference stations
        operator?: string;                  // Name of institution / agency / company operating the network
        authentication?: Sourcetable.AuthenticationMode | string; // Access protection for data streams of the network, N = None, B = Basic, D = Digest
        fee?: boolean;                      // User fee for receiving data streams from this network, N = No user fee, Y = Usage is charged
        webNetwork?: string;                // Web-address for network information
        webStream?: string;                 // Web-address for stream information
        webRegistration?: string;           // Web address or mail address for registration
        misc?: string[];                    // Miscellaneous information, last data field in record

        static readonly ENTRY_TYPE = 'NET';

        static readonly DESTRUCTURING_CONVERSIONS: (null | ((s: string) => any))[] = [
            null, null, fromYesNoValue, null, null, null];

        static readonly STRUCTURING_CONVERSIONS: (null | ((e: any) => string | number | undefined))[] = [
            null, null, toYesNoValue, null, null, null];

        constructor(identifier: string) {
            super();
            this.identifier = identifier;
        }

        fromRawSourcetableLineElements(elements: any[]): void {
            if (typeof elements[0] === 'string') this.identifier = elements[0];

            [, this.operator, this.authentication, this.fee, this.webNetwork,
                this.webStream, this.webRegistration, ...this.misc] = elements;
        }

        toRawSourcetableLineElements(): any[] {
            return [this.identifier, this.operator, this.authentication, this.fee, this.webNetwork,
                this.webStream, this.webRegistration, ...(this.misc ?? ['none'])];
        }
    }

    const FILTER_SIMPLE_CHECK = /^[^!|+=<>*~]*$/;
    const FILTER_NUMBER_CHECK = /^[0-9!|+=<>.]+$/;
    const FILTER_NUMBER_COMPARISON = /^(?<negate>!)?(?<comparator><|>|<=|>=|=)?(?<number>[-+]?(?:\d*\.\d+|\d+)?)$/;
    const FILTER_NUMBER_APPROXIMATION = /^~(?<number>[-+]?(?:\d*\.\d+|\d+))$/;

    type Element = string | number | undefined;
    export type SimpleFilter = string | undefined;
    export type SimpleFilterList = SimpleFilter[];
    export type AdvancedFilter = SimpleFilter | number | { string: RegExp | Error, number: (NumberFilter | Error)[][] | Error };
    export type AdvancedFilterList = AdvancedFilter[];
    class NumberFilter {
        constructor(private readonly negate: boolean, private readonly comparator: '=' | '>' | '<' | '>=' | '<=',
                private readonly value: number) { }

        test(input: number) {
            return this.compare(input) != this.negate;
        }

        private compare(input: number): boolean {
            let a = input;
            let b = this.value;
            switch (this.comparator) {
                case '=': return Math.abs(a - b) < Number.EPSILON;
                case '>': return a > b;
                case '<': return a < b;
                case '>=': return a >= b;
                case '<=': return a <= b;
            }
        }
    }

    /**
     * Filters applicable when requesting sourcetable entries
     */
    export interface Filters {
        /** Authentication request to only include entries which user has access to */
        auth?: boolean;

        /** Whether to throw errors when an invalid condition is found */
        strict?: boolean;

        /** Simple (direct text match based) filter lists */
        simple?: SimpleFilterList[];

        /** Advanced filter lists */
        advanced?: AdvancedFilterList[];
    }

    /**
     * Parses advanced NTRIP filters
     *
     * Converts filters from string form to RegExp/number matcher or simplified string form.
     *
     * Used to process filters that were passed in by the user during sourcetable GET request.
     *
     * @param filters Parsed advanced filter list
     */
    export function parseAdvancedFilters(filters: (string | undefined)[]): AdvancedFilterList {
        return filters.map(filter => {
            // Undefined filters are ignored
            if (filter === undefined || filter.length === 0) return undefined;

            // Strings not containing any special characters are treated as simple filters
            if (FILTER_SIMPLE_CHECK.test(filter)) return filter;

            // Number approximation filter (for closest stream)
            const approximation = FILTER_NUMBER_APPROXIMATION.exec(filter)?.groups?.['number'];
            if (approximation !== undefined) return parseFloat(approximation);

            // Parse for both number and string values (warnings shown when filtering is performed in strict mode)
            let string: RegExp | Error;
            let number: (NumberFilter | Error)[][] | Error;

            // Number filter
            if (FILTER_NUMBER_CHECK.test(filter)) {
                // Convert to SourcetableElementNumberFilter for later application
                number = filter.split('|') // Split ORs
                        .map(terms => terms.split('+')
                                .map(term => {
                                    const match = FILTER_NUMBER_COMPARISON.exec(term);
                                    if (match === null) return new Error(`Invalid term for number filter: ${term}`);

                                    return new NumberFilter(match.groups!['negate'] !== undefined,
                                            (match.groups!['comparator'] as '=' | '>' | '<' | '>=' | '<=') ?? '=',
                                            parseFloat(match.groups!['number']));
                                }));
            } else {
                number = new Error(`Invalid number filter: ${filter}`);
            }

            // String filter
            try {
                // Double up each group of parentheses (for internal ORs)
                filter = filter.replace(/[()]/g, '$&$&');

                // Escape RegExp characters (except parentheses, * and |)
                filter = filter.replace(/[.+?^${}[\]\\]/g, '\\$&');

                // Treat each OR as an independent group
                filter = filter.replace(/\|/g, ')|(');

                // Entire string must be matched
                filter = '^((' + filter + '))$';

                // Replace all wildcards
                filter = filter.replace(/\*/g, '.*');

                // Replace all negations
                filter = filter.replace(/\(!([^)]+)\)/g, '((?!$1).*)');

                string = new RegExp(filter, 'i');
            } catch (error) {
                string = new Error(`Invalid string filter: ${filter}`);
            }

            // Return options for both string and number depending on element type
            return {
                string: string,
                number: number
            };
        });
    }

    /**
     * Performs filtering of sourcetable for approximation filters (closest values)
     *
     * Allows user to provide one or more values for which the closest matching entries are to be returned.
     *
     * For example, user could request nearest servers by lat/lng with STR;;;;;;;;~53.1;~-7.6.
     *
     * A score is calculated for each entry as the sum of the distances of its elements to the target values.
     *
     * Multiple values can be provided for a given field to allow for multiple simultaneous filters, and each is
     * added to the cumulative score for each entry.
     *
     * @param filters Array of numbers at entry element indices to approximate
     * @param entries List of entries to filter
     * @param strict Whether to throw an error if a non numeric element is encountered in an entry when expected
     * @return Filtered list of entries containing the entries closest to the request values
     */
    export function filterApproximations(filters: AdvancedFilterList[], entries: Entry[], strict: boolean = false): Entry[] {
        if (entries.length <= 1) return entries;

        // Aggregate from filter list to numbers to approximate for each element
        const maxElements = Math.max(...filters.map((filters) => filters.length));
        const approximations: (undefined | number)[] = [];
        for (let i = 0; i < maxElements; i++) {
            let numbers = filters.map((filters) => filters[i])
                    .filter((filter) => typeof filter === "number") as number[];

            approximations[i] = numbers.length === 0 ? undefined :
                    numbers.reduce((a, b) => a + b, 0) / numbers.length;
        }

        if (approximations.length == 0) return entries;

        return entries.map(entry => {
            // Select elements from each entry
            const elements = entry.toSourcetableLineElements();
            let score = 0;
            for (let i = 0; i < approximations.length; i++) {
                const number = approximations[i];

                // Skip undefined approximation filter entries
                if (number === undefined) continue;

                const element = elements[i];

                // Element must also be a number to be compared (can't approximate string)
                if (typeof element !== 'number') {
                    if (strict) throw new Error("Could not approximate entry element value as it is not a number");
                    return null;
                }

                score += Math.abs(element - number);
            }

            // Store entry and its score for later reduction
            return {
                entry: entry,
                score: score
            };
        }).reduce((accumulator, entry) => {
            // Ignore entries that were invalid
            if (entry === null) return accumulator;

            if (accumulator.entries.length == 0 || entry.score < accumulator.score) {
                // First entry or entry with lower score
                accumulator.entries = [entry.entry];
                accumulator.score = entry.score;
            } else if (Math.abs(entry.score - accumulator.score) < Number.EPSILON) {
                // Entry with same score as current best
                accumulator.entries.push(entry.entry);
            }

            return accumulator;
        }, {entries: [] as Entry[], score: Infinity}).entries;
    }

    export enum Format {
        BINEX = 'BINEX',
        CMR = 'CMR',
        NMEA = 'NMEA',
        RAW = 'RAW',
        RTCA = 'RTCA',
        RTCM_2 = 'RTCM 2',
        RTCM_2_1 = 'RTCM 2.1',
        RTCM_2_2 = 'RTCM 2.2',
        RTCM_2_3 = 'RTCM 2.3',
        RTCM_3 = 'RTCM 3',
        RTCM_3_0 = 'RTCM 3.0',
        RTCM_3_1 = 'RTCM 3.1',
        RTCM_3_2 = 'RTCM 3.2',
        RTCM_3_3 = 'RTCM 3.3',
        RTCM_SAPOS = 'RTCM SAPOS'
    }

    export enum NavSystem {
        GPS = 'GPS',
        GLONASS = 'GLO',
        GALILEO = 'GAL',
        BEIDOU = 'BDS',
        QZSS = 'QZS',
        SBAS = 'SBAS',
        IRNSS = 'IRS'
    }

    export enum SolutionType {
        SingleBase = 0,
        Network = 1
    }

    export enum AuthenticationMode {
        None = 'N',
        Basic = 'B',
        Digest = 'D'
    }

    export enum CarrierPhaseInformation {
        None = 0,
        L1 = 1,
        L1_L2 = 2
    }
}