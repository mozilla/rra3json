#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import apiclient.discovery
import apiclient.http
import argparse
from bs4 import BeautifulSoup
from datetime import datetime
from oauth2client.service_account import ServiceAccountCredentials
import os
from httplib2 import Http
import io
import json
import yaml

class DotDict(dict):
    """
    dict.item notation for dict()'s
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in list(dct.items()):
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value

    def __getstate__(self):
        return self.__dict__

class gdrive_rra(object):
    def __init__(self, credentials_file, config, debug):
        self.scopes = ['https://www.googleapis.com/auth/drive.metadata.readonly',
                       'https://www.googleapis.com/auth/drive.file ',
                       'https://www.googleapis.com/auth/drive']
        self.rra_directory_id = config.rra3json.rra_directory_id
        self.rra_mime_type = 'application/vnd.google-apps.document'
        self.rra_description_tag = 'RRA version 3.0.0'
        self.rra_schema_file = config.rra3json.rra_schema
        self.credentials_file = credentials_file
        self.http_auth = None
        self.drive_service = None
        self.debug = debug
        self._authorize()

    def _authorize(self):
        credentials = ServiceAccountCredentials.from_json_keyfile_name(self.credentials_file,
                                                                       self.scopes)
        self.http_auth = credentials.authorize(Http())
        self.drive_service = apiclient.discovery.build('drive', 'v3', http=self.http_auth)

    def find_rra_files(self):
        page_token = None
        rra_files = []
        search_query =" mimeType='{}' and '{}' in parents".format(self.rra_mime_type, self.rra_directory_id)
        while True:
            response = self.drive_service.files().list(q=search_query,
                                                       spaces='drive',
                                                       fields='nextPageToken, files(id, name)',
                                                       pageToken=page_token).execute()
            for gfile in response.get('files', []):
                rra_files.append(gfile)

            page_token = response.get('nextPageToken', None)
            if page_token is None:
                break
        return rra_files

    def _html_table_to_rows(self, table):
        data = self._html_table_to_dict(table)
        output = []
        for i in data:
            output.append((i, data[i]))
        return output

    def _html_table_to_dict(self, table):
        data = table.find_all('tr')
        output = {}
        for rows in data:
            # row[col]
            row = rows.find_all('span')
            key = row[0].text
            value = row[1].text
            output[key] = value
        return output

    def _html_list_to_rows(self, lists):
        data = lists.find_all('li')
        output = []
        for rows in data:
            # row[col]
            tmp_rows = []
            for row in rows.find_all('span'):
                # Google likes to insert this special char everywhere
                if row.text != '\xa0':
                    tmp_rows.append(row.text)
            output.append(tmp_rows)
        return output

    def _check_is_meta_table(self, meta):
        return 'Service Name' in list(meta.keys())

    def _check_is_data_dict_table(self, data):
        return 'Data name / type' in list(data.keys())

    def parse_rra(self, rra_gdocs_file):
        rra_id = rra_gdocs_file.get('id')
        if self.debug:
            print(("Parsing RRA {} id {}".format(rra_gdocs_file.get('name'), rra_id)))
        # This is the HTML style that allows to find the footer of the document as we don't get class ids passed, this
        # is the next best thing, *sigh*
        footer_sep = {'style': 'font-size:8pt;font-style:italic'}
        data = self._download_rra_html(rra_id)
        soup = BeautifulSoup(data.decode('utf-8'), 'html.parser')

        ## META
        tables = soup.find_all('table')
        # Document's own classification label is the first table
        # Metadata table is the 2nd table
        meta = self._html_table_to_dict(tables[1])
        if not self._check_is_meta_table(meta):
            raise Exception('ParsingError', 'Invalid metadata table')
        # Find Analyst and Last Modified from the footer
        # Footer is always at the bottom of the doc (ie -1, ie end of list)
        # Ex input: Rapid Risk Analysis is a lightweight risk and threat modeling framework.RRA was last reviewed at 2017-11-13 06:40:12 by gdestuynder@mozilla.com'
        footer = soup.find_all('span', footer_sep)[-1]
        # tmp = ['2017-11-13 06:40:12', ' by gdestyunder@mozilla.com']
        tmp = footer.text.split('last reviewed at ')[-1].split(' by')
        meta['Last Modified'] = tmp[0].strip()
        meta['Analyst'] = tmp[1].split(' by ')[-1].strip()

        ## DATA DICTIONARY
        # Data dictionnary is the 3rd table
        data_dict = self._html_table_to_dict(tables[2])
        if not self._check_is_data_dict_table(data_dict):
            raise Exception('ParsingError', 'Invalid data dictionary table')
        del data_dict['Data name / type'] # cleanup

        # Document is split in sections by h2 headers
        h2 = soup.find_all('h2')
        # h2[0] is the Data dictionary
        # => We pass here, already parsed by table parser code
        # h2[1] is Service notes
        # h2[2] is Threat scenarios

        ## THREATS
        # Threats are sub-divided by h3 headers for each category
        h3 = h2[2].findNextSiblings('h3')
        threats = {'confidentiality': [], 'integrity': [], 'availability': []}
        ## h3[0] is Confidentiality
        threats['confidentiality'] = self._html_list_to_rows(h3[0].findNextSibling('ul'))
        ## h3[1] is Integrity
        threats['integrity'] = self._html_list_to_rows(h3[1].findNextSibling('ul'))
        ## h3[2] is Availability
        threats['availability'] = self._html_list_to_rows(h3[2].findNextSibling('ul'))

        ## RECOMMENDATIONS
        # h2[3] is Recommendations
        recommendations = self._html_list_to_rows(h2[3].findNextSibling('ul'))

        return self._generate_rra(rra_id, meta, data_dict, threats, recommendations)

    def _normalize_data_classification(self, data):
        """
        Maps internal data classification labels from https://wiki.mozilla.org/Security/Data_Classification
        ref: standard_internal_data = ['PUBLIC', 'RESTRICTED', 'INTERNAL', 'SECRET']
        """
        if data.find('Workgroup'):
            return 'RESTRICTED'
        elif data.find('Staff'):
            return 'INTERNAL'
        elif data.find('Public'):
            return 'PUBLIC'
        elif data.find('Individual'):
            return 'SECRET'
        else:
            raise Exception('ParsingError', 'Could not translate data classification level')

    def _p2_get_timestamp(self, dt):
        """Implements datetime.datetime timestamp() that works with python2"""
        # We are already force-localized to UTC, so, cool.
        return dt.strftime("%s")

    def _generate_rra(self, rra_id, meta, data_dict, threats, recommendations):
        with open(self.rra_schema_file) as fd:
            rrajson = DotDict(json.load(fd))

        ## META-MOZDEF
        rrajson.timestamp = datetime.now().isoformat()
        # ref: Last Modified: 2017-11-13 06:40:12
        lastmodified = datetime.strptime(meta.get('Last Modified'), '%Y-%m-%d %H:%M:%S')
        rrajson.lastmodified = lastmodified.isoformat()
        rrajson.summary = 'RRA for {}'.format(meta.get('Service Name'))
        rrajson.source = rra_id
        # We don't have a version record from gdocs, use something unique
        rrajson.version = str(int(self._p2_get_timestamp(lastmodified)))

        ## META
        rrajson.details.metadata.service = meta.get('Service Name')
        rrajson.details.metadata.service_provided = meta.get('Service Name')
        rrajson.details.metadata.description = 'See original document'
        rrajson.details.metadata.scope = 'See original document'
        rrajson.details.metadata.owner = meta.get('Service Owner(s)').split(',')[0]
        rrajson.details.metadata.contacts = meta.get('Service Owner(s)').split(',')+[meta.get('Owner’s Director')]
        rrajson.details.metadata.analyst = meta.get('Analyst')

        ## DATA DICTIONARY
        for d in data_dict:
            md = self._normalize_data_classification(data_dict[d])
        rrajson.details.data.default = self._normalize_data_classification(meta.get('Service Data Classification'))

        ## THREATS
        for i in threats:
            ct = threats[i][0] # Current threat
            if ct[0] in ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'MAXIMUM']:
                for rtype in ['reputation', 'finances', 'productivity']:
                    # We fill in all risk types (rtype) to be the same impact as we do not currently distinguish them
                    # in RRA3
                    # Note: ct[1:] is the rationale
                    rrajson.details.risk[i][rtype]['impact'] = ct[0]
                    # We default to LOW as RRA3 does not support this
                    rrajson.details.risk[i][rtype]['probability'] = 'LOW'
            else:
                # Unknown threat ?!
                raise Exception('ParsingError', 'Invalid threat')

        ## RECOMMENDATIONS
        for i in recommendations:
            recom_text = ''.join(i[1:])
            recom_level = i[0]
            if recom_level in ['LOW', 'MEDIUM', 'HIGH', 'MAXIMUM']:
                rrajson.details.recommendations[recom_level].append(recom_text)
            else:
                rrajson.details.recommendations.Unknown.append(recom_text)

        return rrajson

    def _download_rra_html(self, rra_id):
        fd = io.BytesIO()
        req = self.drive_service.files().export_media(fileId=rra_id, mimeType='text/html')
        # Careful, this may fail for big files see https://github.com/google/google-api-python-client/issues/15
        downloader = apiclient.http.MediaIoBaseDownload(fd, req)
        done = False
        while not done:
            status, done = downloader.next_chunk()
        fd.seek(0)
        data = fd.read()
        return data

def post_rra(config, rrajson, debug):
    url = '{proto}://{host}:{port}{endpoint}'.format(proto=config['proto'], host=config['host'],
                                                        port=config['port'], endpoint=config['endpoint'])
    payload = json.dumps(rrajson)

    verify=config['x509cert']

    headers = {'SERVICEAPIKEY': config['apikey']}

    if debug:
        print(payload)
        return

    r = requests.post(url, data=payload, headers=headers, verify=verify)
    if r.status_code != requests.codes.ok:
        raise Exception('PostRRAFailed', 'Failed to post RRA error code {} message {} rra {}'.format(r.status_code, r.content, rrajson['source']))

if __name__ == "__main__":
    os.environ['TZ'] = 'UTC' # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Specify a configuration file')
    parser.add_argument('-s', '--credentials', required=True, help='Specify the Google Service Account credentials file')
    parser.add_argument('-d', '--debug', action="store_true", help='Does not send RRA to servicemap, display it instead - with any other debug info along the way')
    args = parser.parse_args()
    with open(args.config or 'rra3json.yml') as fd:
        config = DotDict(yaml.load(fd))

    d = gdrive_rra(credentials_file=args.credentials, config=config, debug=args.debug)
    rra_files = d.find_rra_files()
    for rra in rra_files:
        try:
            rrajson = d.parse_rra(rra)
        except Exception as e:
            print(('!!! RRA Parsing failed for {} because {}'.format(rra, e)))
            if args.debug:
                import traceback
                traceback.print_exc()
        post_rra(config.servicemap, rrajson, args.debug)
