#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Simple LDAP change detector and publisher via pypubsub."""

import sys
import yaml
import time
import requests
import ldap
import ldapurl
import ldap.ldapobject
import ldap.syncrepl


class SyncReplClient(ldap.ldapobject.ReconnectLDAPObject, ldap.syncrepl.SyncreplConsumer):
    def __init__(self, *args, **kwargs):
        self.cookie = None
        self.sync_done = False
        self.changedb = {}
        self.__presentUUIDs = {}
        self.pubsub_url = "http://localhost:2069/private/ldap"

        ldap.ldapobject.ReconnectLDAPObject.__init__(self, *args, **kwargs)

    def syncrepl_get_cookie(self):
        return self.cookie

    def syncrepl_set_cookie(self,cookie):
        self.cookie = cookie

    def syncrepl_entry(self, dn, attributes, uuid):
        previous_attributes = {}
        if uuid in self.changedb:
            change_type = 'modify'
            previous_attributes = self.changedb[uuid]
        else:
            change_type = 'add'
        attributes['dn'] = dn
        self.changedb[uuid] = attributes
        if self.sync_done:
            print('Detected %s of entry %r' % (change_type, dn))
            self.post_change(dn, attributes, previous_attributes, change_type)

    def syncrepl_delete(self,uuids):
        uuids = [uuid for uuid in uuids if uuid in self.changedb]
        for uuid in uuids:
            dn = self.changedb[uuid]['dn']
            print('Detected deletion of entry %r' % dn)
            self.post_change(dn, {}, self.changedb[uuid], 'delete')
            del self.changedb[uuid]

    def syncrepl_present(self,uuids,refreshDeletes=False):
        if uuids is None:
            if refreshDeletes is False:
                deleted_entries = [
                    uuid
                    for uuid in self.changedb.keys()
                    if uuid not in self.__presentUUIDs and uuid != 'ldap_cookie'
                ]
                self.syncrepl_delete( deleted_entries )
            self.__presentUUIDs = {}
        else:
            if refreshDeletes is True:
                self.syncrepl_delete( uuids )
            else:
                for uuid in uuids:
                    self.__presentUUIDs[uuid] = True

    def syncrepl_refreshdone(self):
        print('Initial sync done, polling for changes...')
        self.sync_done = True


    def post_change(self,dn,attributes,previous_attributes, change_type):
        print(f"Publishing change-set for {dn}")
        js = {
            'dn': stringify(dn),
            'change_type': change_type,
            'old_attributes': stringify(previous_attributes),
            'new_attributes': stringify(attributes),
        }
        try:
            requests.put(self.pubsub_url, json = js)
        except Exception as e:
            print(f"Could not push payload: {e}")
        return True
    
    def set_pubsub_url(self, url):
        self.pubsub_url = url

def stringify(obj):
    """Turn bytes into strings within a nested dict/list"""
    if isinstance(obj, bytes):
        obj = str(obj, 'utf-8')
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, bytes):
                obj[k] = str(v, 'utf-8')
            elif isinstance(v, list):
                obj[k] = stringify(v)
    elif isinstance(obj, list):
        newlist = []
        for el in obj:
            if isinstance(el, bytes):
                el = str(el, 'utf-8')
            elif isinstance(el, list):
                el = stringify(el)
            newlist.append(el)
        obj = newlist
    return obj

def main(config):
    ldap_url = ldapurl.LDAPUrl(config['ldapurl'])
    while True:
        print('Connecting to %s...' % ldap_url.initializeUrl())
        # Prepare the LDAP server connection (triggers the connection as well)
        ldap_connection = SyncReplClient(ldap_url.initializeUrl())
        if config.get("pubsuburl"):
            ldap_connection.set_pubsub_url(config['pubsuburl'])

        # Now we login to the LDAP server
        try:
            ldap_connection.simple_bind_s(ldap_url.who, ldap_url.cred)
        except ldap.INVALID_CREDENTIALS as err:
            print('Login to LDAP server failed: %s' % err)
            sys.exit(1)
        except ldap.SERVER_DOWN:
            print('LDAP server is down, going to retry.')
            time.sleep(5)
            continue

        # Commence the syncing
        print('Starting syncrepl...')
        ldap_search = ldap_connection.syncrepl_search(
            ldap_url.dn or '',
            ldap_url.scope or ldap.SCOPE_SUBTREE,
            mode = 'refreshAndPersist',
            attrlist=ldap_url.attrs,
            filterstr = ldap_url.filterstr or '(objectClass=*)'
        )

        try:
            while ldap_connection.syncrepl_poll( all = 1, msgid = ldap_search):
                pass
        except KeyboardInterrupt:
            # User asked to exit
            return
        except Exception as err:
            # Handle any exception
            print('Unhandled exception, reconnecting in 5 seconds: %s' % err)
            time.sleep(5)

if __name__ == '__main__':
    config = yaml.safe_load(open("pypubsub-ldap.yaml"))
    main(config)
