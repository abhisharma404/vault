#! /usr/bin/python

from html.parser import HTMLParser
import urllib.request
import urllib.response
import urllib.parse
import urllib.error
import colors
from vault_cli import errors


class Linkfinder(HTMLParser):

    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for(attribute, value) in attrs:
                if attribute == 'href':
                    url = urllib.parse.urljoin(self.base_url, value)
                    self.links.add(url)

    def links_obtained(self):
        return self.links

    def error(self, message):
        pass


class Imagefinder(HTMLParser):

    def __init__(self, url):
        super().__init__()
        self.url = url
        self.img_links = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'img':
            for(attribute, value) in attrs:
                if attribute == 'src' or attribute == 'alt' or \
                   attribute == 'srcset':
                    url = urllib.parse.urljoin(self.url, value)
                    self.img_links.add(url)

    def img_links_obtained(self):
        return self.img_links

    def error(self, message):
        pass

    def crawl(self):
        try:
            if not self.url.lower().startswith('ftp:/') or not \
               self.url.lower().startswith('file:/'):
                req = urllib.request.\
                      Request(self.url, headers={'User-Agent': 'Mozilla/5.0'})
                con = urllib.request.urlopen(req, timeout=15)
                html_string = con.read().decode("utf-8")
                self.feed(html_string)

        except urllib.error.HTTPError as e:
            # Per-page status errors (404, ...) are benign; keep as prints.
            print("Was not able to open the URL.")
            print(str(e.reason))
        except urllib.error.URLError as e:
            if isinstance(e.reason, TimeoutError):
                errors.report_error('Request timed out while opening: ' +
                                    self.url, exc=e, code='E2002')
            else:
                errors.report_error('Request failed while opening: ' +
                                    self.url, exc=e, code='E2001')
        except TimeoutError as e:
            errors.report_error('Request timed out while opening: ' +
                                self.url, exc=e, code='E2002')
        except Exception as e:
            errors.report_error('Failed to open ' + self.url + ': ' +
                                str(e), exc=e)
        return ''


def initiate(list_url, path):
    try:
        from . import imutil as imu
        c = 0
        for x in list_url:
            I = Imagefinder(x)
            I.crawl()
            for i in I.img_links_obtained():
                imu.image_download(i, path + '/'+str(c))
                c = c+1
        if c == 0:
            colors.warning('No images were collected from the crawled URLs.')
        print('[X]Returning..')

    except ImportError as e:
        errors.report_error('Could not import the required module', exc=e,
                            code='E6001')

    except Exception as e:
        errors.report_error(str(e), exc=e)
