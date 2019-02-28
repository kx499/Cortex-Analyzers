#!/usr/bin/env python
# encoding: utf-8

from lib.msgParser import Message
from cortexutils.analyzer import Analyzer


class MsgParserAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.filename = self.get_param('filename', 'noname.ext')
        self.filepath = self.get_param('file', None, 'File is missing')

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "MsgParser"
        predicate = "Attachments"
        value = "0"

        if "attachments" in raw:
            value = len(raw["attachments"])
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        r_dom = '[\s\>/](([a-zA-Z0-9\-]+\.)+[a-z]{2,8})[\s\:\</\?\[]'
        r_url = '(((meows?|h[Xxt]{2}ps?)://)?((([a-zA-Z0-9\-]+\[?\.\]?)+[a-z]{2,8})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[?\.\]?){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/[^\s\<"]+)'
        r_email = '([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'

        artifacts = []
        body = raw.get('body', '')
        attachments = raw.get('attachments', [])
        header_from = raw.get('sender', '')

        for dom in re.findall(r_dom, header_from):
            artifacts.append({'type': 'domain', 'value': dom[0], 'message': 'From header ioc'})

        for em in re.findall(r_email, header_from):
            artifacts.append({'type': 'email', 'value': em, 'message': 'From header ioc'})

        for url in re.findall(r_url, body):
            artifacts.append({'type': 'url', 'value': url[0], 'message': 'Body ioc'})

        for dom in re.findall(r_dom, body):
            artifacts.append({'type': 'domain', 'value': dom[0], 'message': 'Body ioc'})

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

    def run(self):
        if self.data_type == 'file':
            try:
                self.report(Message(self.filepath).getReport())
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    MsgParserAnalyzer().run()
