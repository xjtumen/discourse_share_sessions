import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import pickle
from urllib import parse
from flask import Flask, request, abort, make_response, send_file
from redis import Redis
from config import TRUSTED_HOSTNAMES, name_of, AttrDict, Status

r = Redis()

app = Flask(__name__)

DIS_SHARE_SESSION_KEY = os.environ['DIS_SHARE_SESSION_KEY']


def rget(name, key):
    return r.get(name_of(name, key))


def rset(name, key, value):
    r.set(name_of(name, key), value)


def get_domain_policy(host):
    return host if host == 'xjtu.live' else None


@app.route('/share_sessions/universal.gif', methods=['GET', 'OPTIONS'])
def universal_auth():
    cookies = request.cookies
    host = request.host

    if request.method == 'OPTIONS':
        print(f'options {host}')
    else:
        print(f'get {host}')
    js_key = request.args.get('key', None)
    js_username = request.args.get('username', None)
    if js_key is None:
        return abort(404)

    if request.host not in TRUSTED_HOSTNAMES:
        return abort(404)

    status = rget(js_key, 'status')
    resp = make_response(send_file('static/1x1.gif', mimetype='image/gif'))

    if status is None:
        logged_in = cookies.get('logged_in')
        if logged_in is None:
            return abort(404)
        try:
            cookie_logged_in = parse.unquote(logged_in)
            cookie_logged_in = base64.b64decode(cookie_logged_in)
            cookie_logged_in = json.loads(cookie_logged_in)
            _json = cookie_logged_in['json']
            calculated_hmac = hmac.new(bytes(DIS_SHARE_SESSION_KEY, 'utf-8'),
                                       bytes(_json, 'utf-8'),
                                       hashlib.sha256).hexdigest()
        except Exception as e:
            logging.error(e)
            return abort(404)

        if calculated_hmac != cookie_logged_in['hmac']:
            return abort(404)

        user_info = json.loads(_json)
        del cookie_logged_in
        user_info = AttrDict(user_info)
        username = user_info.username

        if username != js_username:
            return abort(404)

        other_domains = TRUSTED_HOSTNAMES.copy()
        other_domains.remove(host)

        origin = f'https://{host}'

        rset(js_key, 'status', Status.PENDING.value)
        rset(js_key, 'cookies', pickle.dumps(cookies))
        rset(js_key, 'origin', origin)
        rset(js_key, 'other_domains', '|'.join(other_domains))

        return resp

    else:
        status = rget(js_key, 'status')

        # TODO: handle partial finished (user log in to other domain manually)
        if Status(int(status.decode())) == Status.FINISHED.value:
            return abort(404)

        origin = rget(js_key, 'origin')
        origin = origin.decode()
        cookies = rget(js_key, 'cookies')
        cookies = pickle.loads(cookies)
        other_domains = rget(js_key, 'other_domains')
        other_domains = other_domains.decode()
        other_domains = set(other_domains.split('|'))
        if host not in other_domains and request.method == 'GET':
            return abort(404)

        resp.headers.add('Access-Control-Allow-Origin', origin)
        resp.headers.add('Access-Control-Allow-Credentials', 'true')

        if request.method == 'GET':
            req_cookies = request.cookies
            flag_should_remove_host = []
            for k, v in cookies.items():
                print(f'{host}: set {k} to {v}')
                if k == '_t':
                    expire_date = datetime.datetime.now() + datetime.timedelta(days=60)  # 1440 hours
                elif k == '_forum_session':
                    expire_date = None
                else:
                    expire_date = None
                resp.set_cookie(k, v, domain=get_domain_policy(host), httponly=True, secure=True, samesite='None',
                                expires=expire_date)
                if req_cookies.get(k) == v:
                    flag_should_remove_host.append(True)
            if len(flag_should_remove_host) > 0 and all(flag_should_remove_host):
                logging.warning(f'{host}: removed')
                other_domains.remove(host)
            rset(js_key, 'other_domains', '|'.join(other_domains))
            if len(other_domains) == 0:
                rset(js_key, 'status', Status.FINISHED.value)

        print(f'host {host} finished')
        return resp
