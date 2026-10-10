"""Guarded public HTTP transport for typed extraction; never inherits urllib redirects."""
from __future__ import annotations
import gzip
import http.client
import ipaddress
import math
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from architect.http import Response, MAX_BYTES, parse_robots, UA

class UnsafeURL(ValueError):
    pass

class AccessDenied(PermissionError):
    pass

@dataclass(frozen=True)
class AccessResult:
    response: Response
    signals: dict[str, str]


def _parts(url: str):
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ('https','http') or not p.hostname or p.username or p.password or p.fragment:
        raise UnsafeURL('only public http(s) URLs without userinfo or fragments are allowed')
    try:
        port = p.port or (443 if p.scheme == 'https' else 80)
    except ValueError:
        raise UnsafeURL('invalid port') from None
    if port != (443 if p.scheme == 'https' else 80):
        raise UnsafeURL('nonstandard port blocked')
    if len(url) > 2048 or any(c in url for c in '\r\n\t'):
        raise UnsafeURL('invalid URL')
    host = p.hostname.lower().rstrip('.')
    if host == 'localhost' or host.endswith('.localhost'):
        raise UnsafeURL('local host blocked')
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not literal.is_global:
            raise UnsafeURL('non-public IP literal')
    return p,port


def _resolve(host: str, port: int) -> list[str]:
    return list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)))


def _public_ips(host: str, port: int, resolver) -> list[str]:
    try:
        addresses = list(resolver(host,port))
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise UnsafeURL('non-public DNS result')
    except (OSError,ValueError) as e:
        raise UnsafeURL(f'unsafe or unresolved host: {host}') from e
    return addresses


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host,port,timeout=timeout)
        self.ip=ip
    def connect(self):
        self.sock=socket.create_connection((self.ip,self.port), self.timeout)

class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,port,ip,timeout):
        super().__init__(host,port,timeout=timeout,context=ssl.create_default_context())
        self.ip=ip
    def connect(self):
        raw=socket.create_connection((self.ip,self.port), self.timeout)
        try:
            self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _transport(url: str, pinned_ip: str, timeout: float) -> Response:
    p,port=_parts(url)
    conn=(_PinnedHTTPS if p.scheme=='https' else _PinnedHTTP)(p.hostname,port,pinned_ip,timeout)
    try:
        conn.request('GET',urllib.parse.urlunsplit(('','',p.path or '/',p.query,'')),
                     headers={'Host':p.netloc,'User-Agent':UA,'Accept-Encoding':'gzip'})
        r=conn.getresponse()
        data=r.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES: raise AccessDenied('response too large')
        headers={k.lower():v for k,v in r.getheaders()}
        if headers.get('content-encoding','').lower()=='gzip':
            with gzip.GzipFile(fileobj=__import__('io').BytesIO(data)) as f:
                data=f.read(MAX_BYTES+1)
            if len(data)>MAX_BYTES: raise AccessDenied('decompressed response too large')
        return Response(url,r.status,headers,data,headers.get('content-type',''))
    finally:
        conn.close()


def _signals(raw: str) -> dict[str,str]:
    result={}
    for chunk in raw.split(','):
        if '=' in chunk:
            k,v=chunk.split('=',1)
            result[k.strip().lower()]=v.strip().lower()
    return result


def fetch_public(url: str, *, resolver=None, transport=None, timeout: float=15) -> AccessResult:
    resolver=resolver or _resolve
    transport=transport or _transport
    seen=set()
    robots_cache={}
    last_page_by_origin={}
    deadline=time.monotonic()+30
    current=url
    for _ in range(6):
        remaining=deadline-time.monotonic()
        if remaining<=0: raise AccessDenied('typed fetch deadline exceeded')
        p,port=_parts(current)
        if current in seen: raise UnsafeURL('redirect loop')
        seen.add(current)
        addresses=_public_ips(p.hostname,port,resolver)
        origin=f'{p.scheme}://{p.netloc}'
        if origin not in robots_cache:
            robots_url=origin+'/robots.txt'
            robots_resp=transport(robots_url,addresses[0],min(timeout,max(0.1,deadline-time.monotonic())))
            if robots_resp.status==404:
                robots=None
            elif robots_resp.status==200:
                if len(robots_resp.body)>MAX_BYTES: raise AccessDenied('robots too large')
                text = robots_resp.text
                ct = robots_resp.content_type.lower()
                if any(t in ct for t in ('text/html','application/json','xml')) or text.lstrip().startswith('<'):
                    raise AccessDenied('robots response is not robots.txt')
                keys = {line.partition(':')[0].strip().lower() for line in text.splitlines()
                        if ':' in line and not line.lstrip().startswith('#')}
                if text.strip() and not keys.intersection({'user-agent','sitemap','content-signal'}):
                    raise AccessDenied('unrecognized robots policy')
                robots=parse_robots(text)
            else:
                raise AccessDenied(f'robots unavailable: HTTP {robots_resp.status}')
            robots_cache[origin]=robots
        robots=robots_cache[origin]
        path=p.path or '/'
        if robots and not robots.can_fetch(path + ('?'+p.query if p.query else '')):
            raise AccessDenied('robots disallows page')
        if robots and robots.crawl_delay is not None:
            delay=robots.crawl_delay
            if not math.isfinite(delay) or delay>5:
                raise AccessDenied('robots crawl-delay exceeds typed-fetch budget')
            if delay>0 and origin in last_page_by_origin:
                wait=last_page_by_origin[origin]+delay-time.monotonic()
                if wait>0:
                    if wait>deadline-time.monotonic():
                        raise AccessDenied('crawl-delay exceeds remaining deadline')
                    time.sleep(wait)
        remaining=deadline-time.monotonic()
        if remaining<=0: raise AccessDenied('typed fetch deadline exceeded')
        response=transport(current,addresses[0],min(timeout,remaining))
        last_page_by_origin[origin]=time.monotonic()
        if len(response.body)>MAX_BYTES:
            raise AccessDenied('response too large')
        if response.status in (301,302,303,307,308):
            location=response.headers.get('location')
            if not location: raise UnsafeURL('redirect without location')
            next_url=urllib.parse.urljoin(current,location)
            current=urllib.parse.urldefrag(next_url).url  # fragments never reach HTTP
            continue
        signals=dict(robots.signals) if robots else {}
        signals.update(_signals(response.headers.get('content-signal','')))
        return AccessResult(response,signals)
    raise UnsafeURL('too many redirects')
