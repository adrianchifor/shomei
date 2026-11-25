import argparse
from contextlib import ExitStack
import getpass
from http.cookiejar import MozillaCookieJar
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Interaction(UserInteraction):
    def request_pin(self, permissions, rp_id):
        return getpass.getpass(f"YubiKey PIN for {rp_id}: ")

    def prompt_up(self):
        print("Touch your YubiKey.", file=sys.stderr)


def https_origin(value):
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.path not in ("", "/") or url.query or url.fragment):
        raise argparse.ArgumentTypeError("expected an HTTPS origin")
    return f"https://{url.netloc}"


def post(opener, origin, step, body):
    request = Request(f"{origin}/_shomei/api/auth/{step}",
                      json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=10) as response:
            return json.loads(response.read(32768))
    except HTTPError as error:
        try:
            detail = json.loads(error.read(4096))["error"]
        except (ValueError, KeyError, TypeError):
            detail = error.reason
        raise ValueError(f"HTTP {error.code}: {detail}") from error


def sign(origin, options):
    with ExitStack() as stack:
        keys = []
        for device in CtapHidDevice.list_devices():
            stack.callback(device.close)
            if device.descriptor.vid == 0x1050:
                keys.append(device)
        if len(keys) != 1:
            raise ValueError("Connect exactly one USB YubiKey with FIDO enabled.")
        client = Fido2Client(keys[0], DefaultClientDataCollector(origin), Interaction())
        if not any(version.startswith("FIDO_2_") for version in client.info.versions):
            raise ValueError("The connected YubiKey needs FIDO2 support.")
        return dict(client.get_assertion(options).get_response(0))


def write_output(path, write):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
    try:
        write(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Sign in to Shomei with a USB YubiKey.")
    parser.add_argument("--ca-file", help="PEM CA for the proxy server")
    parser.add_argument("origin", type=https_origin)
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("http").add_argument("cookie_jar", type=Path)
    tcp = modes.add_parser("tcp")
    tcp.add_argument("csr", type=Path)
    tcp.add_argument("certificate", type=Path)
    args = parser.parse_args()

    context = ssl.create_default_context(cafile=args.ca_file)
    cookies = MozillaCookieJar()
    opener = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(cookies), NoRedirect())
    body = {} if args.mode == "http" else {"client_csr_pem": args.csr.read_text()}
    start = post(opener, args.origin, "start", body)
    credential = sign(args.origin, start["publicKey"])
    grant = post(opener, args.origin, "finish", {"challenge_id": start["challenge_id"], "credential": credential})
    if args.mode == "http":
        session = next((cookie for cookie in cookies if cookie.name == "__Host-shomei" and cookie.secure), None)
        if session is None:
            raise ValueError("Shomei did not return a session cookie.")
        session.domain = urlsplit(args.origin).hostname
        session.set_nonstandard_attr("HTTPOnly", None)
        write_output(args.cookie_jar, lambda path: cookies.save(path, ignore_discard=True))
    else:
        write_output(args.certificate, lambda path: path.write_text(grant["certificate_pem"]))
    print(f"Expires at {grant['expires_at']} (Unix seconds).")


if __name__ == "__main__":
    try:
        main()
    except (ClientError, OSError, URLError, ValueError, KeyError) as error:
        sys.exit(str(error))
    except KeyboardInterrupt:
        sys.exit(130)
