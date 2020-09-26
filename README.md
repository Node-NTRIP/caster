# NTRIP caster
NTRIP caster library with support for:

- NTRIP V1/V2
- HTTP/RTSP/RTP
- "Push/pull" (NTRIP client/server) connections to other casters
- Raw TCP/IP server/client
- Serial port reading/writing
- File reading/writing
- Extensible authentication system
- RTCM/NMEA decoding
- Sourcetable filtering

## Installing

```
npm install -S @ntrip/caster
```

## Basic Usage
```typescript
const caster = new Caster({
    authManager: {
        async authenticate(auth: AuthRequest) {
            return {...auth, authenticated: true}
        }
    }
});
caster.addTransport(NtripTransport.new({port: 2101}));
```

## Transports
#### NTRIP Caster
```typescript
export interface NtripTransportOptions {
    port: number;
    tls?: tls.SecureContextOptions & tls.TlsOptions;

    protocols?: {
        http?: boolean;
        rtsp?: boolean;
        rtp?: boolean;
    },

    versions?: {
        [NtripVersion.V1]?: boolean;
        [NtripVersion.V2]?: boolean;
    }

    browserFavicon?: () => Buffer;
    browserStreamAccess?: boolean;
}

NtripTransport.new({port: 2101});
```

#### NTRIP Server/Client
```typescript
export interface NtripPushPullTransportOptions {
    mode: 'push' | 'pull';

    remote: {
        host: string;
        port: number;
        family?: string;
    }
    tls?: tls.SecureContextOptions & tls.CommonConnectionOptions;

    protocol: 'http' | 'rtsp' | 'rtp';

    localMountpoint: string;
    remoteMountpoint: string;

    ntripVersion: NtripVersion;

    localStr?: string;
    localGga?: string;

    remoteStr?: string;
    remoteGga?: string;

    credentials?: {
        basic?: {username: string, password: string};
        bearer?: string;
        secret?: string;
    }
}

NtripPushPullTransport.new({
    mode: 'pull',
    
    remote: {
        host: 'euref-ip.net',
        port: 2101
    },

    localMountpoint: 'ACOR00ESP0_MIRROR',
    remoteMountpoint: 'ACOR00ESP0',
    
    ntripVersion: NtripVersion.V2,

    credentials: {
        basic: {
            username: 'test',
            password: 'test'        
        }
    }
});
```

## Testing
`npm test`

## License
GPLv3

## Contributions
Contributions via pull requests are welcome. Please ensure that code style matches that of the existing files.  