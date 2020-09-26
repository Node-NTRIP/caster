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

export interface AuthRequest {
    type?: 'server' | 'client';
    mountpoint: string | null;

    host: string | null;
    source?: {
        host: string;
        port: number;
        family: string;
    };

    credentials: AuthCredentials;
}

export interface AuthResponse extends AuthRequest {
    authenticated: boolean;
    token?: any;
}

export interface AuthCredentials {
    anonymous?: boolean;
    basic?: {username: string, password: string};
    bearer?: string;
    certificate?: string;
    secret?: string;
}

export interface AuthManager {
    authenticate(request: AuthRequest): Promise<AuthResponse>;
}