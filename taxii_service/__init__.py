import logging
import os
import re

from django.template.loader import render_to_string
from django.utils.safestring import SafeText

from crits.core.handlers import does_source_exist
from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger("crits." + __name__)

class TAXIIClient(Service):
    """
    Send TAXII message to TAXII server.
    """

    name = "taxii_service"
    version = "2.1.0"
    supported_types = []
    required_fields = ['_id']
    description = "Send TAXII messages to a TAXII server."
    template = "taxii_service_results.html"

    @staticmethod
    def parse_service_config(config):
        namespace = config.get("namespace", "").strip()
        ns_prefix = config.get("ns_prefix", "").strip()
        max_rels = config.get("max_rels", "")
        errors = []
        if not namespace:
            errors.append("You must specify a XML Namespace.")
        if not ns_prefix:
            errors.append("You must specify a XML Namespace Prefix.")
        if not max_rels or max_rels > 5000 or max_rels < 0:
            errors.append("Maximum Related must be in the range 0-5000.")
        if errors:
            raise ServiceConfigError("<br>".join(errors))

    @staticmethod
    def parse_server_config(config):
        name = config.get("servername", "").strip()
        hostname = config.get("hostname", "").strip()
        ppath = config.get("ppath", "").strip()
        ipath = config.get("ipath", "").strip()
        keyfile = config.get("keyfile", "").strip()
        lcert = config.get("lcert", "").strip()
        errors = []
        if not name:
            errors.append("You must specify a name for the TAXII Server.")
        if not re.match("^[\w ]+$", name):
            errors.append("Server name can only contain letters, "
                          "numbers, and spaces.")
        if not hostname:
            errors.append("You must specify a TAXII Server hostname.")
        if not ppath:
            errors.append("You must specify a TAXII Server Poll Path.")
        if not ipath:
            errors.append("You must specify a TAXII Server Inbox Path.")
        if keyfile and not lcert:
            errors.append("If you provide a keyfile, you must also provide a certificate.")
        if not keyfile and lcert:
            errors.append("If you provide a certificate, you must also provide a keyfile.")
        if keyfile and not os.path.isfile(keyfile):
            errors.append("Keyfile does not exist at given location.")
        if lcert and not os.path.isfile(lcert):
                errors.append("Local cert file does not exist "
                              "at given location.")
        if errors:
            raise ServiceConfigError("<br>".join(errors))

    @staticmethod
    def parse_feed_config(config):
        srv_name = config.get("srv_name", "").strip()
        feedname = config.get("feedname", "").strip()
        source = config.get("source", "").strip()
        subID = config.get("subID", "").strip()
        fcert = config.get("fcert", "").strip()
        fkey = config.get("fkey", "").strip()
        errors = []
        if not srv_name:
            errors.append("No server name to which to relate this feed")
        if not re.match("^[\w ]+$", srv_name):
            errors.append("Provided server name is invalid")
        if not feedname:
            errors.append("You must specify a Feed Name")
        if not source:
            errors.append("You must specify a CRITs source")
        else:
            if not does_source_exist(source):
                errors.append("Provided CRITs source is invalid")
        if fcert and not os.path.isfile(fcert):
            errors.append("Encryption Certificate does not exist at given location")
        if fkey and not os.path.isfile(fkey):
            errors.append("Decryption Key does not exist at given location")
        if errors:
            raise ServiceConfigError("<br>".join(errors))

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.TAXIIServiceConfigForm().fields
        for name, field in fields.iteritems():
            # Convert sigfiles to newline separated strings
            if name == 'taxii_servers':
                display_config[field.label] = ', '.join(config[name])
            else:
                display_config[field.label] = config[name]

        return display_config

    @staticmethod
    def migrate_config(existing_config):
        # Migrate version 2.0 config to 2.1 config
        feeds = {}
        to_remove = ['certfile', 'hostname', 'data_feed',
                     'https', 'keyfile', 'certfiles']
        for fid, cf in enumerate(existing_config['certfiles']):
            cf_list = cf.split(',')
            feeds[str(fid)] = {'source': cf_list[0],
                               'feedname': cf_list[1],
                               'fcert': cf_list[2],
                               'fkey': existing_config.get('keyfile', ''),
                               'subID': ''}
        server = {'hostname': existing_config.get('hostname', ''),
                  'version': '0',
                  'https': existing_config.get('https', ''),
                  'lcert': existing_config.get('certfile', ''),
                  'ppath': '/poll/',
                  'ipath': '/inbox/',
                  'keyfile': existing_config.get('keyfile', ''),
                  'port': '',
                  'user': '',
                  'pword': '',
                  'feeds': feeds}
        for key in to_remove:
            if key in existing_config:
                del existing_config[key]
        existing_config['taxii_servers'] = {'Migrated': server}
        return existing_config

    @classmethod
    def get_config(self, existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.TAXIIServiceConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            if 'hostname' in existing_config: # then migrate old style config
                existing_config = self.migrate_config(existing_config)
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        # Populate form with configured TAXII Servers
        choices = [(server, server) for server in config['taxii_servers']]
        form = forms.TAXIIServiceConfigForm(choices, initial=config)
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': form,
                                 'config_error': None})

        # Change form action from service default
        idx = html.find('action="')
        idx2 = html[idx:].find('" ')
        action = 'action="/services/taxii_service/configure/'
        html = html[0:idx] + action + html[idx + idx2:]

        # Add TAXII Server config buttons to form
        idx = html.rfind('</td></tr>\n        </table>')
        buttons = '<br /><input class="form_submit_button" type="button" id="add" value="Add" /> <input class="form_submit_button" type="button" id="edit" value="Edit Selected" /> <input class="form_submit_button" type="button" id="remove" value="Remove Selected" />'
        html = html[0:idx] + buttons + html[idx:]

        # Add JS events for TAXII Server config buttons
        html = html + "\n<script>$('#add').click(function() {location.href = '/services/taxii_service/configure/';});$('#edit').click(function() {var data = $('#id_taxii_servers').val(); if (data) {location.href = '/services/taxii_service/configure/' + data + '/';}}); $('#remove').click(function() {var data = {'remove_server': $('#id_taxii_servers').val()}; var url = '/services/taxii_service/configure/'; $.ajax({async: false, type: 'POST', url: url, data: data, datatype: 'json', success: function(data) {if (data.success) {$('#id_taxii_servers').html(data.html);} else {$('#service_edit_results').text('Failed to remove server configuration.');}}});});</script>"

        return forms.TAXIIServiceConfigForm, SafeText(html)

    def run(self, obj, config):
        pass # Not available via old-style services.
