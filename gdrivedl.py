#!/usr/bin/env python
from __future__ import unicode_literals
import json
import os
import re
import sys
import unicodedata
import argparse
import logging
import queue
import threading

try:
    #Python3
    from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
    from http.cookiejar import CookieJar
except ImportError:
    #Python2
    from urllib2 import Request, urlopen, build_opener, HTTPCookieProcessor
    from cookielib import CookieJar

ITEM_URL = 'https://drive.google.com/open?id={id}'
FILE_URL = 'https://docs.google.com/uc?export=download&id={id}&confirm={confirm}'
FOLDER_URL = 'https://drive.google.com/embeddedfolderview?id={id}#list'
CHUNKSIZE = 4096
USER_AGENT = 'Mozilla/5.0'

ID_PATTERNS = [
    re.compile('/file/d/([0-9A-Za-z_-]{10,})(?:/|$)', re.IGNORECASE),
    re.compile('/folders/([0-9A-Za-z_-]{10,})(?:/|$)', re.IGNORECASE),
    re.compile('id=([0-9A-Za-z_-]{10,})(?:&|$)', re.IGNORECASE),
    re.compile('([0-9A-Za-z_-]{10,})', re.IGNORECASE)
]
FOLDER_PATTERN = re.compile('<a href="(https://drive.google.com/.*?)".*?<div class="flip-entry-title">(.*?)</div>',
                            re.DOTALL | re.IGNORECASE)
CONFIRM_PATTERN = re.compile("download_warning[0-9A-Za-z_-]+=([0-9A-Za-z_-]+);",
                             re.IGNORECASE)
FILENAME_PATTERN = re.compile('attachment;filename="(.*?)"',
                             re.IGNORECASE)

def output(text):
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        sys.stdout.write(text.encode('utf8'))

# Big thanks to leo_wallentin for below sanitize function (modified slightly for this script)
# https://gitlab.com/jplusplus/sanitize-filename/-/blob/master/sanitize_filename/sanitize_filename.py
def sanitize(filename):
    blacklist = ["\\", "/", ":", "*", "?", "\"", "<", ">", "|", "\0"]
    reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
        "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
        "LPT6", "LPT7", "LPT8", "LPT9",
    ]

    filename = "".join(c for c in filename if c not in blacklist)
    filename = "".join(c for c in filename if 31 < ord(c))
    filename = unicodedata.normalize("NFKD", filename)
    filename = filename.rstrip(". ")
    filename = filename.strip()

    if all([x == "." for x in filename]):
        filename = "_" + filename
    if filename in reserved:
        filename = "_" + filename
    if len(filename) == 0:
        filename = "_"
    if len(filename) > 255:
        parts = re.split(r"/|\\", filename)[-1].split(".")
        if len(parts) > 1:
            ext = "." + parts.pop()
            filename = filename[:-len(ext)]
        else:
            ext = ""
        if filename == "":
            filename = "_"
        if len(ext) > 254:
            ext = ext[254:]
        maxl = 255 - len(ext)
        filename = filename[:maxl]
        filename = filename + ext
        filename = filename.rstrip(". ")
        if len(filename) == 0:
            filename = "_"

    return filename

def url_to_id(url):
    for pattern in ID_PATTERNS:
        match = pattern.search(url)
        if match:
            return match.group(1)

    logging.error('Unable to get ID from {}'.format(url))
    sys.exit(1)

class GDriveDL(object):
    def __init__(self, quiet=False, overwrite=False, workers=4):
        self._quiet = quiet
        self._workers = workers
        self._overwrite = overwrite
        self._create_empty_dirs = True

        self._kill = False
        self._work_queue = queue.Queue()
        self._resp_queue = queue.Queue()
        self._opener = build_opener(HTTPCookieProcessor(CookieJar()))

    def _request(self, url):
        logging.debug('Requesting: {}'.format(url))
        req = Request(url, headers={'User-Agent': USER_AGENT})
        return self._opener.open(req)

    def _worker(self):
        while not self._work_queue.empty():
            item = self._work_queue.get_nowait()
            try:
                func = item.pop(0)
                self._resp_queue.put(func(*item))
            except Exception as e:
                self._resp_queue.put(e)
            finally:
                self._work_queue.task_done()

    def process_url(self, url, directory, filename=None):
        id = url_to_id(url)

        if '://' not in url:
            url = ITEM_URL.format(id=id)
            resp = self._request(url)
            url = resp.geturl()

        if '/file/' in url.lower():
            self.process_file(id, directory, filename)
        elif '/folders/' in url.lower():
            if filename:
                logging.warn("Ignoring --output-document option for folder download")
            self.process_folder(id, directory)
        else:
            logging.error('That id {} returned an unknown url {}'.format(id, url))
            sys.exit(1)

        threads = []
        logging.debug('Starting {} workers'.format(self._workers))

        try:
            for i in range(self._workers):
                thread = threading.Thread(target=self._worker)
                thread.daemon = True
                thread.start()
                threads.append(thread)

            while not self._work_queue.empty():
                result = self._resp_queue.get()
                if isinstance(result, Exception):
                    raise
        except:
            with self._work_queue.mutex:
                self._work_queue.queue.clear()
            self._kill = True

        for thread in threads:
            thread.join()

    def process_folder(self, id, directory):
        url = FOLDER_URL.format(id=id)
        resp = self._request(url)
        html = resp.read().decode('utf-8')

        matches = re.findall(FOLDER_PATTERN, html)

        if not matches and 'ServiceLogin' in html:
            logging.error('Folder: {} does not have link sharing enabled'.format(id))
            sys.exit(1)

        if self._create_empty_dirs and not matches:
            os.makedirs(directory)
            logging.info('Directory: {directory} [Created]'.format(directory=directory))

        for match in matches:
            url, item_name = match
            id = url_to_id(url)

            if '/file/' in url.lower():
                self._work_queue.put([self.process_file, id, directory, sanitize(item_name)])
            elif '/folders/' in url.lower():
                self._work_queue.put([self.process_folder, id, os.path.join(directory, sanitize(item_name))])

    def process_file(self, id, directory, filename=None, confirm=''):
        file_path = None

        if filename:
            file_path = filename if os.path.isabs(filename) else os.path.join(directory, filename)
            if not self._overwrite and os.path.exists(file_path):
                logging.info('{file_path} [Exists]'.format(file_path=file_path))
                return

        url = FILE_URL.format(id=id, confirm=confirm)
        resp = self._request(url)

        if 'ServiceLogin' in resp.url:
            logging.error('File: {} does not have link sharing enabled'.format(id))
            sys.exit(1)

        cookies = resp.headers.get('Set-Cookie') or ''
        if not confirm and 'download_warning' in cookies:
            confirm = CONFIRM_PATTERN.search(cookies)
            return self.process_file(id, directory, filename=filename, confirm=confirm.group(1))

        if not file_path:
            filename = FILENAME_PATTERN.search(resp.headers.get('content-disposition')).group(1)
            file_path = os.path.join(directory, sanitize(filename))
            if not self._overwrite and os.path.exists(file_path):
                logging.info('{file_path} [Exists]'.format(file_path=file_path))
                return

        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            os.makedirs(directory)
            logging.info('Directory: {directory} [Created]'.format(directory=directory))

        success = False
        try:
            with open(file_path, 'wb') as f:
                dl = 0
                last_out = 0
                while not self._kill:
                    chunk = resp.read(CHUNKSIZE)
                    if not chunk:
                        success = True
                        break

                    if b'Too many users have viewed or downloaded this file recently' in chunk:
                        logging.error('Quota exceeded for this file')
                        sys.exit(1)

                    dl += len(chunk)
                    f.write(chunk)
                    if not self._quiet and (not last_out or dl-last_out > 1048576):
                        output("\r{} {:.2f}MB".format(
                            file_path,
                            dl / 1024 / 1024,
                        ))
                        last_out = dl
                        sys.stdout.flush()
        except:
            raise
        finally:
            if not success and os.path.exists(file_path):
                os.remove(file_path)

            if success and not self._quiet:
                output('\n')


def main(args=None):
    parser = argparse.ArgumentParser(description='Download Google Drive files & folders')
    parser.add_argument("url", help="Shared Google Drive URL")
    parser.add_argument("-P", "--directory-prefix", default='.', help="Output directory (default is current directory)")
    parser.add_argument("-O", "--output-document", help="Output filename. Defaults to the GDrive filename. Not valid when downloading folders")
    parser.add_argument("-q", "--quiet", help="Disable console output", default=False, action="store_true")
    args = parser.parse_args(args)

    if args.quiet:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.WARN)
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

    url = args.url
    id = ''

    for pattern in ID_PATTERNS:
        match = pattern.search(url)
        if match:
            id = match.group(1)
            break

    if not id:
        logging.error('Unable to get ID from {}'.format(url))
        sys.exit(1)

    gdrive = GDriveDL(quiet=args.quiet, overwrite=args.output_document is not None)
    gdrive.process_url(url, directory=args.directory_prefix, filename=args.output_document)


if __name__ == "__main__":
    main()
