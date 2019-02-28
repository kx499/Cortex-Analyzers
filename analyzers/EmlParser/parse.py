#!/usr/bin/env python3
# encoding: utf-8
import email.parser
import eml_parser
from cortexutils.analyzer import Analyzer
import magic
import binascii
import hashlib
import base64
import re
from pprint import pprint

class EmlParserAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        #filename of the observable
        self.filename = self.getParam('attachment.name', 'noname.ext')

        #filepath to the observable, looks like /tmp/cortex-4224850437865873235-datafile
        self.filepath = self.getParam('file', None, 'File is missing')

    def run(self):
        if self.data_type == 'file':
            try:
                parsingResult = parseEml(self.filepath)
                self.report(parsingResult)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()

    def artifacts(self, raw):
        r_privip = '^(10\.|192\.168\.|172\.[123][0-9])'
        r_ip = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        r_dom = '[\s\>/](([a-zA-Z0-9\-]+\.)+[a-z]{2,8})[\s\:\</\?\[]'
        r_url = '(((meows?|h[Xxt]{2}ps?)://)?((([a-zA-Z0-9\-]+\[?\.\]?)+[a-z]{2,8})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[?\.\]?){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/[^\s\<"]+)'
        r_email = '([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'

        artifacts = []
        body = raw.get('body', '')
        attachments = raw.get('attachments', [])
        header_rcvd = raw.get('headers', {}).get('Received', '')
        header_from = raw.get('headers', {}).get('From', '')

        for ip in re.findall(r_ip, header_rcvd):
            if re.match(r_privip, ip):
                continue
            artifacts.append({'type': 'ip', 'value': ip, 'message': 'Received header ioc'})

        for dom in re.findall(r_dom, header_rcvd):
            artifacts.append({'type': 'domain', 'value': dom, 'message': 'Received header ioc'})

        for dom in re.findall(r_dom, header_from):
            artifacts.append({'type': 'domain', 'value': dom, 'message': 'From header ioc'})

        for dom in re.findall(r_email, header_from):
            artifacts.append({'type': 'email', 'value': dom, 'message': 'From header ioc'})

        for url in re.findall(r_url, body):
            artifacts.append({'type': 'url', 'value': url, 'message': 'Body ioc'})

        for dom in re.findall(r_dom, body):
            artifacts.append({'type': 'domain', 'value': dom, 'message': 'Body ioc'})

        for a in attachments:
            if a.get('sha256'):
                artifacts.append({'type': 'hash', 'value': a['sha256'], 'message': 'Attachment ioc'})

            if a.get('md5'):
                artifacts.append({'type': 'hash', 'value': a['md5'], 'message': 'Attachment ioc'})

            if a.get('filename'):
                artifacts.append({'type': 'filename', 'value': a['filename'], 'message': 'Attachment ioc'})

        #dedup
        artifacts = [dict(t) for t in {tuple(d.items()) for d in artifacts}]
        return artifacts

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "EmlParser"
        predicate = "Attachments"
        value = "\"0\""

        if "attachments" in raw:
            value = len(raw["attachments"])
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


def parseEml(filepath):

    result = dict()
    result['subject'] = str()
    result['date'] = str()
    result['receivers'] = str()
    result['displayFrom'] = str()
    result['sender'] = str()
    result['topic'] = str()
    result['bcc'] = str()
    result['displayto'] = str()
    result['headers'] = str()
    result['body'] = str()
    result['attachments'] = list()

    #read the file
    with open(filepath, 'r') as f:
        raw_eml = f.read()

    #parsing the headers with the email library
    #cause eml_parser does not provide raw headers (as far as I know)
    hParser = email.parser.HeaderParser()
    h = hParser.parsestr(raw_eml)
    result['headers'] = dict(h)

    parsed_eml = eml_parser.eml_parser.decode_email(filepath, include_raw_body=True, include_attachment_data=True)
    #parsed_eml['header'].keys() gives:
    #dict_keys(['received_foremail', 'from', 'date', 'received_domain', 'to', 'header', 'received_ip', 'subject', 'received'])

    result['subject'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('subject', ''))
    result['date'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('date', ''))
    result['receivers'] = ', '.join(parsed_eml.get('header', '').get('to', ''))
    result['displayFrom'] = parsed_eml.get('header', '').get('from', '')
    result['sender'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('x-env-sender', ''))
    result['topic'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('thread-topic', ''))
    result['bcc'] = parsed_eml.get('header', '').get('header', '').get('bcc', '')
    result['displayto'] = ', '.join(parsed_eml.get('header', '').get('header', '').get('to', ''))

    #for some emails, the body field is empty because the email body is
    #identified as an attachment
    if parsed_eml['body']:
        #normal case
        result['body'] = parsed_eml['body'][0]['content']
    else:
        #email body is in attachment
        #from what I've seen, there are 2 attachments
        #one with the email body as text
        #and one with the email body as text but wrapped in html
        #let's arbitrary take the one wrapped in html as body
        for attachment in parsed_eml['attachment']:
            if 'HTML text' in attachment['content_header']['content-description']:
                result['body'] = base64.b64decode(attachment['raw']).decode('utf-8')

    #attachments
    try:
        for attachment in parsed_eml['attachment']:
            attachmentSumUp = dict()
            attachmentSumUp['filename'] = attachment.get('filename', '')

            #because of module conflict name with magic
            #eml-parser does not provide the mime type
            #it has to be calculated, the attachment is in base64
            attachmentSumUp['mime'] = magic.from_buffer(binascii.a2b_base64(attachment['raw']))
            attachmentSumUp['extension'] = attachment.get('extension', '')
            attachmentSumUp['md5'] = attachment['hash']['md5']
            attachmentSumUp['sha1'] = attachment['hash']['sha1']
            attachmentSumUp['sha256'] = attachment['hash']['sha256']
            result['attachments'].append(attachmentSumUp)

    except KeyError as e:
        pass

    return result

if __name__ == '__main__':
    EmlParserAnalyzer().run()
