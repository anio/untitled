#!/bin/env python3

import os
import sys
import string
import asyncio
import logging as log
from time import time
from hashlib import sha3_224
from urllib.parse import urlparse, parse_qsl, quote, urlencode, urlunparse, \
    unquote_plus
from argparse import ArgumentParser, BooleanOptionalAction

from aiohttp import ClientSession, ClientTimeout, \
    client_exceptions, TCPConnector

log.basicConfig(
    filename='error.log',
    level=log.DEBUG,
    format=('%(asctime)s - %(pathname)s:%(lineno)d - %(message)s')
)

timeout = ClientTimeout(
    total=60 * 60 * 24 * 365,
    connect=5,
    sock_connect=5,
    sock_read=15
)

rps = 256
semaphore = asyncio.Semaphore(256)

# consts
methods: list[str] = [
    'GET',
    'POST',
    'OPTIONS',
    'PUT',
    'DELETE',
    # 'TRACE',
    'HEAD',
    # 'CONNECT',
    'PATCH'
]

ERR_429 = 0
ERR_429_TS = time()


async def get_response(
    session: ClientSession,
    hostname: str,
    url: str,
    method: str = 'get',
    args={}
) -> None:

    saved_args = locals()

    global semaphore, ERR_429, ERR_429_TS, rps

    method = method.lower()

    if (time() - ERR_429_TS) > 3 and rps < args.rps:
        rps = rps + 1
        semaphore = asyncio.Semaphore(rps)

        # reset timer and counter
        ERR_429_TS = time()
        ERR_429 = 0

        sys.stderr.write(f'RPS to {rps}; 429 count -> {ERR_429}\n')

    if ERR_429 > 10 and rps > 15:
        rps = rps - 10
        semaphore = asyncio.Semaphore(rps)
        sys.stderr.write(f'RPS to {rps}; 429 count -> {ERR_429}\n')
        ERR_429 = 0
        await asyncio.sleep(3)

    try:
        async with semaphore:
            async with getattr(session, method)(
                url,
                skip_auto_headers=['User-Agent', 'Content-Type'],
                allow_redirects=args.redirect
            ) as response:
                headers: list = response.headers

                content_type: str = response.content_type or '---'
                content_len: int = headers.get('content-length', '!!!')
                location: str = headers.get('location', None)
                num_headers: int = len(headers)
                server: str = headers.get('Server',
                                          headers.get('X-Powered-By', '###'))
                text: str = await response.text()

                request_info = response.request_info

                conditions = [
                    not args.match or
                    (args.match and args.match in text),
                    not args.status or
                    (args.status and response.status in args.status)
                ]

                message = (
                    f'{response.status}, '
                    f'{content_len}, '
                    f'{server}, '
                    f'{num_headers}, '
                    f'{content_type}, '
                    f'{method.upper()}, '
                    f'{url}'
                )

                if location:
                    message += f', {location}'

                if all(conditions):
                    print(message)
                if args.keep:
                    fn = sha3_224(url.translate(
                        url.maketrans(
                            string.printable[62:],
                            '_' * 38
                        )
                    ).encode('utf-8')).hexdigest()
                    fn = f'{method}_{response.status}_{hostname}_{fn}.txt'
                    with open(f'output/{fn}', 'w') as f:
                        f.write(f'{request_info.method} {url}\n')
                        for name, value in request_info.headers.items():
                            f.write(f'{name}: {value}\n')

                        f.write('\n')
                        f.write('-' * 80)
                        f.write('\n\n')
                        f.write(
                            f'HTTP/1.1 {response.status} {response.reason}\n'
                        )
                        for name, value in response.raw_headers:
                            name, value = name.decode(), value.decode()
                            f.write(f'{name}: {value}\n')

                        f.write(f'\n{text}')
        if response.status == 429:
            sys.stderr.write(f'Reschedule due to 429 on {url}\n')
            ERR_429 += 1
            ERR_429_TS = time()
            await asyncio.sleep(3)
            await get_response(**saved_args)
    except (
        client_exceptions.ServerTimeoutError,
        client_exceptions.ClientConnectorSSLError,
        client_exceptions.ClientConnectorError,
        client_exceptions.ClientOSError,
        client_exceptions.TooManyRedirects,
        client_exceptions.ServerDisconnectedError,
        # Exception
    ) as e:
        errtype: str = str(type(e))[8:-2]
        log.debug(f'[{url}] - {errtype} // {e}')


async def main() -> None:

    global methods, semaphore, rps

    parser = ArgumentParser()
    parser.add_argument('--match')
    parser.add_argument('--status')  # 200,500
    parser.add_argument('--method')  # get,post
    parser.add_argument('--params')  # a=1&b=2
    parser.add_argument('--format')  # https://@/index.html
    parser.add_argument('--discover-fn')  # file.txt
    parser.add_argument('--header', action='append', default=[])  # 'a: 1'
    parser.add_argument('--payload', action='append', default=[])  # 'o<i>o'
    parser.add_argument('--keep', action=BooleanOptionalAction)
    parser.add_argument('--redirect', action=BooleanOptionalAction,
                        default=True)
    parser.add_argument('--path-inject', action=BooleanOptionalAction)
    parser.add_argument('--param-inject',
                        action=BooleanOptionalAction, default=True)
    parser.add_argument('--rps', type=int, default=256)

    args = parser.parse_args()

    rps = args.rps
    semaphore = asyncio.Semaphore(args.rps)

    if args.keep:
        try:
            os.mkdir('output')
        except FileExistsError:
            pass

    if args.method:
        methods = args.method.split(',')

    if args.status:
        args.status = [int(s) for s in args.status.split(',')]

    if args.payload:
        payloads = set()
        for payload in args.payload:
            payloads.add(unquote_plus(payload))

    tasks: set = set()

    headers = {
        'Sec-Ch-Ua': '"Chromium";v="93", " Not;A Brand";v="99"',
        'Sec-Ch-Ua-Mobile': "?0",
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/"
        "537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
        'Sec-Ch-Ua-Platform': '"Linux"',
        'Content-Type': "text/plain",
        'Accept': "*/*",
        'Sec-Fetch-Site': "cross-site",
        'Sec-Fetch-Mode': "cors",
        'Sec-Fetch-Dest': "empty",
        'Accept-Encoding': "identity",  # "gzip, deflate"
        'Accept-Language': "en-US,en;q=0.9"
    }

    for header in args.header:
        name, value = header.split(': ', maxsplit=1)

        headers[name] = value

    async with ClientSession(
        timeout=timeout,
        connector=TCPConnector(ssl=False),
        headers=headers
    ) as session:
        for _url in sys.stdin.readlines():
            _url = _url.strip()

            if args.format:
                _url = args.format.replace('@', _url)

            urls: set = set()

            parsed_url = urlparse(_url)
            parsed_qs = parse_qsl(parsed_url.query)

            if not parsed_url.path:
                parsed_url = parsed_url._replace(path='/')

            if args.params:
                parsed_qs += parse_qsl(args.params)

            if args.param_inject and args.payload:
                for idx, qs in enumerate(parsed_qs):
                    for payload in payloads:
                        qs: tuple = (qs[0], payload)
                        qs_copy: list[tuple] = parsed_qs[::]
                        qs_copy[idx] = qs
                        query = urlencode(qs_copy, quote_via=quote)
                        print(qs_copy)
                        purl_copy = parsed_url._replace(query=query)
                        url = urlunparse(purl_copy)
                        urls.add(url)

            if args.path_inject and args.payload and parsed_url.path != '/':
                paths = parsed_url.path.split('/')[1:]
                for idx, path in enumerate(paths):
                    for payload in payloads:
                        paths_copy = paths[::]
                        paths_copy[idx] = payload
                        new_paths = '/'.join(paths_copy)
                        purl_copy = parsed_url._replace(
                            path='/' + new_paths
                        )
                        url = urlunparse(purl_copy)
                        urls.add(url)

            if args.discover_fn:
                with open(args.discover_fn, 'r') as f:
                    for line in f.readlines():
                        line = line.strip()
                        url = _url + line
                        urls.add(url)

            if not urls:
                urls.add(_url)

            for url in urls:
                for method in methods:
                    task = asyncio.create_task(
                        get_response(session, parsed_url.hostname,
                                     url, method, args))
                    tasks.add(task)

        sys.stderr.write(f'Number of requests to send: {len(tasks)}\n')
        await asyncio.gather(*tasks)


asyncio.run(main())
