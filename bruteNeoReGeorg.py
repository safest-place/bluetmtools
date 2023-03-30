#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# author : safest_place
# Brute force normal Neo-reGeorg webshell password which return 200 code

import argparse
import base64
import codecs
import random,hashlib,sys
from http.server import BaseHTTPRequestHandler
from io import BytesIO

import requests

HEADERS = {}

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.raw_requestlines = self.rfile.readlines()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

class Rand:
    def __init__(self, key):
        n = int(hashlib.sha512(key.encode()).hexdigest(), 16)
        self.k_clist = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.v_clist = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
        self.k_clen = len(self.k_clist)
        self.v_clen = len(self.v_clist)
        random.seed(n)

    def header_key(self):
        str_len = random.getrandbits(4) + 2 # len 2 to 17
        return ''.join([ self.k_clist[random.getrandbits(10) % self.k_clen] for _ in range(str_len) ]).capitalize()

    def header_value(self):
        str_len = random.getrandbits(6) + 2 # len 2 to 65
        return ''.join([ self.v_clist[random.getrandbits(10) % self.v_clen] for _ in range(str_len) ])

    def base64_chars(self, charslist):
        if sys.version_info >= (3, 2):
            newshuffle = random.shuffle
        else:
            try:
                xrange
            except NameError:
                xrange = range
            def newshuffle(x):
                def _randbelow(n):
                    getrandbits = random.getrandbits
                    k = n.bit_length()
                    r = getrandbits(k)
                    while r >= n:
                        r = getrandbits(k)
                    return r

                for i in xrange(len(x) - 1, 0, -1):
                    j = _randbelow(i+1)
                    x[i], x[j] = x[j], x[i]
        newshuffle(charslist)

def brutePass(dic_file,base64_chars,data):
    with open(dic_file,"r") as f:
        for line in f.readlines():
            password = line.strip("\n")
            rand = Rand(password)
            rand.base64_chars(base64_chars)
            key = rand.header_value()
            if key in data:
                print("password is => "+password)
                return password
    return "Error"

def file_read(filename):
    try:
        with codecs.open(filename, encoding="utf-8") as f:
            return f.read()
    except:
        print("Failed to read file: %s" % filename)
        exit()

def decrypt(key,BASE64CHARS,M_BASE64CHARS,reqFile):
    b64chars = BASE64CHARS
    m_b64chars = M_BASE64CHARS
    rand = Rand(key)
    rand.base64_chars(m_b64chars)
    m_b64chars = ''.join(m_b64chars)
    EncodeMap = str.maketrans(b64chars, m_b64chars)
    DecodeMap = str.maketrans(m_b64chars, b64chars)
    BASICCHECKSTRING = ('<!-- ' + rand.header_value() + ' -->').encode()
    K = {}
    V = {}
    rV = {}
    for name in ["X-STATUS", "X-ERROR", "X-CMD", "X-TARGET", "X-REDIRECTURL"]:
        K[name] = rand.header_key()
    for name in ["FAIL", "Failed creating socket", "Failed connecting to target", "OK", "Failed writing socket",
                 "CONNECT", "DISCONNECT", "READ", "FORWARD", "Failed reading from socket", "No more running, close now",
                 "POST request read filed", "Intranet forwarding failed"]:
        value = rand.header_value()
        V[name] = value
        rV[value] = name
    tf = file_read(reqFile)
    for k in K:
        if K[k] in tf:
            tf = tf.replace(K[k], k)
    for r in rV:
        if r in tf:
            tf = tf.replace(r, rV[r])
    request = HTTPRequest(tf.encode())
    if request.command == "POST":
        s = request.raw_requestlines[-1].decode()
        d = base64.b64decode(s.translate(DecodeMap)).decode()
        tf = tf.replace(s,d)
    print(tf)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u","--url",help="Specify a neo-reGeorg webshell url")
    parser.add_argument("-d","--dictionary",help="Specify a password list")
    parser.add_argument("-f", "--requestMessage", help="Specify a HTTP request message file")
    args = parser.parse_args()
    url = args.url
    dic_file = args.dictionary
    req_txt = args.requestMessage
    conn = requests.Session()
    conn.headers['Accept-Encoding'] = 'gzip, deflate'
    conn.headers['User-Agent'] = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0"
    response = conn.get(url, headers=HEADERS, timeout=10)
    data = response.content.decode()
    BASE64CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    M_BASE64CHARS = list(BASE64CHARS)
    password = brutePass(dic_file,M_BASE64CHARS,data)
    #Reset M_BASE64CHARS
    M_BASE64CHARS = list(BASE64CHARS)
    if (password != "Error") and (len(req_txt) != 0):
        decrypt(password,BASE64CHARS,M_BASE64CHARS,req_txt)

if __name__ == '__main__':
    main()