# (c) 2017, Lionel PRAT <lionel.prat9@gmail.com>
# based on service pdf2txt of Adam Polkosnik && meta_office => Thank!
# use tool : https://github.com/lprat/static_analysis
# All rights reserved.
import logging
import hashlib
import shutil
import os
import tempfile
import re
from datetime import datetime
import subprocess
import json

from django.template.loader import render_to_string

from crits.core.user_tools import get_user_info
from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.acls import SampleACL
from crits.core.class_mapper import class_from_id
from django.conf import settings
from django.template.loader import render_to_string

# for adding the extracted files
from crits.screenshots.handlers import add_screenshot

#get info Sample object
from crits.samples.sample import Sample

from crits.indicators.indicator import Indicator
from crits.indicators.handlers import handle_indicator_ind
from crits.vocabulary.acls import IndicatorACL
from crits.vocabulary.indicators import (
    IndicatorCI,
    IndicatorAttackTypes,
    IndicatorThreatTypes,
    IndicatorTypes
)

from . import forms

logger = logging.getLogger(__name__)


class ExtractEmbeddedService(Service):
    """
    Extract embedded files with clamscan.
    """

    name = "ExtractEmbedded"
    version = '0.0.2'
    #template = "extract_embedded_service_template.html"
    supported_types = ['Sample']
    description = "Extract embedded files with clamscan."

    @staticmethod
    def parse_config(config):
        clamscan_path = config.get("clamscan_path", "")
        if not clamscan_path:
            raise ServiceConfigError("You must specify a valid path for clamscan.")
        if not os.path.isfile(clamscan_path):
            raise ServiceConfigError("clamscan path does not exist.")
        if not os.access(clamscan_path, os.X_OK):
            raise ServiceConfigError("clamscan is not executable.")
        if not 'clamscan' in clamscan_path.lower():
            raise ServiceConfigError("Executable does not appear to be clamscan.")
        analysis_path = config.get("analysis_path", "")
        if not analysis_path:
            raise ServiceConfigError("You must specify a valid path for analysis static tool.")
        if not os.path.isfile(analysis_path):
            raise ServiceConfigError("Analysis static tool path does not exist.")
        pattern_path = config.get("pattern_path", "")
        if not pattern_path:
            raise ServiceConfigError("You must specify a valid path for pattern DB file.")
        if not os.path.isfile(pattern_path):
            raise ServiceConfigError("Pattern DB file path does not exist.")
        yararules_path = config.get("yararules_path", "")
        if not yararules_path:
            raise ServiceConfigError("You must specify a valid path for yara rules.")
        coef_path = config.get("coef_path", "")
        if not coef_path:
            raise ServiceConfigError("You must specify a valid path for coef configuration path.")
        if not os.path.isfile(coef_path):
            raise ServiceConfigError("Coef Configuration path does not exist.")
        tlp_value = config.get("tlp_value", "")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.ExtractEmbeddedConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'clamscan_path': config['clamscan_path'],
                'analysis_path': config['analysis_path'],
                'pattern_path': config['pattern_path'],
                'yararules_path': config['yararules_path'],
                'coef_path': config['coef_path'],
                'tlp_value': config['tlp_value']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ExtractEmbeddedConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ExtractEmbeddedConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        if not obj.filedata:
            return False
        #work for all types
        return True

    @staticmethod
    def save_runtime_config(config):
        if config['debug_log']:
            del config['debug_log']
        if config['import_file']:
            del config['import_file']
        if config['import_file_ioc']:
            del config['import_file_ioc']
        if config['import_file_yara']:
            del config['import_file_yara']

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'debug_log' not in config:
            config['debug_log'] = False
        if 'import_file' not in config:
            config['import_file'] = False
        if 'import_file_ioc' not in config:
            config['import_file_ioc'] = False
        if 'import_file_yara' not in config:
            config['import_file_yara'] = False
        form = forms.ExtractEmbeddedRunForm(data=config)
        return form

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.ExtractEmbeddedRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html
        
    def run(self, obj, config):
        obj.filedata.seek(0)
        data8 = obj.filedata.read(8)
        obj.filedata.seek(0)
        user = self.current_task.user
        self.config = config
        self.obj = obj
        self._debug("ExtractEmbedded started")
        tlp_value = self.config.get("tlp_value", "tlp_value")
        clamscan_path = self.config.get("clamscan_path", os.path.dirname(os.path.realpath(__file__))+'/static_analysis/clamav-devel/clamscan/clamscan')
        analysis_path = self.config.get("analysis_path", os.path.dirname(os.path.realpath(__file__))+'/static_analysis/analysis.py')
        yararules_path = self.config.get("yararules_path", os.path.dirname(os.path.realpath(__file__))+'/static_analysis/yara_rules/')
        pattern_path = self.config.get("pattern_path", os.path.dirname(os.path.realpath(__file__))+'/static_analysis/pattern.db')
        coef_path = self.config.get("coef_path", os.path.dirname(os.path.realpath(__file__))+'/static_analysis/coef.conf')
        #write out the sample stored in the db to a tmp file
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            new_env = dict(os.environ)  # Copy current environment
            args = []
            obj.filedata.seek(0)
            #make temp file for get json result and graph
            dirtmp = tempfile._get_default_tempdir()
            file_png=dirtmp+'/'+next(tempfile._get_candidate_names())+'.png'
            file_json=dirtmp+'/'+next(tempfile._get_candidate_names())+'.json'
            if os.path.isfile(file_png) or os.path.isfile(file_json):
                self._warning('Error: File temp exist.')
            else:
                #TODO add choice: verbose mode and extracted file emmbed
                args = ['python', analysis_path, '-c', clamscan_path, '-g', '-y', yararules_path, '-p', pattern_path, '-f', tmp_file, '-m', coef_path, '-s', file_png, '-j', file_json]
                if config['debug_log']:
                    args = ['python', analysis_path, '-c', clamscan_path, '-g', '-y', yararules_path, '-p', pattern_path, '-f', tmp_file, '-m', coef_path, '-s', file_png, '-j', file_json, '-v']
                #verify user can write sample
                acl_write = user.has_access_to(SampleACL.WRITE)
                if not acl_write:
                    self._info("User does not have permission to add Sample Data to CRITs")
                # pdftotext does not generate a lot of output, so we should not have to
                # worry about this hanging because the buffer is full
                proc = subprocess.Popen(args, env=new_env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, cwd=working_dir)
                # Note that we are redirecting STDERR to STDOUT, so we can ignore
                # the second element of the tuple returned by communicate().
                output, serr = proc.communicate()
                #print stderr without message 'empty database file'
                self._info(output)
                if serr:
                    self._warning(serr)
                #run command problem
                if proc.returncode:
                    msg = ("analysis could not process the file.")
                    self._warning(msg)
                    if os.path.isfile(file_json):
                        os.remove(file_json)
                    if os.path.isfile(file_png):
                        os.remove(file_png)         
                #run command OK
                else:
                    #add json information and png file
                    result_extract = None
                    if os.path.isfile(file_json):
                        with open(file_json) as data_file:
                            try:
                                result_extract = json.load(data_file)
                            except Exception as e:
                                self._warning("Error to parse json result: "+str(e))
                        os.remove(file_json)
                    if os.path.isfile(file_png):
                        #add screeshot
                        fileh = open(file_png, "rb")
                        fileh.seek(0)
                        res = add_screenshot(description='Render of analysis embedded files',
                                                     tags=None,
                                                     method=self.name,
                                                     source=obj.source,
                                                     reference=None,
                                                     analyst=self.current_task.user.username,
                                                     screenshot=fileh,
                                                     screenshot_ids=None,
                                                     oid=obj.id,
                                                     tlp=tlp_value,
                                                     otype="Sample")
                        if res.get('message') and res.get('success') == True:
                            self._warning("res-message: %s id:%s" % (res.get('message'), res.get('id') ) )
                            self._add_result('Graph analysis', res.get('id'), {'Message': res.get('message')})
                        self._info("id:%s, file: %s" % (res.get('id'), file_png))
                        fileh.close()
                        os.remove(file_png)
                    if type(result_extract) is dict:
                        parse_result(self, result_extract, acl_write, None)
                        if result_extract['TempDirExtract'] and dirtmp in str(result_extract['TempDirExtract']) and os.path.isdir(str(result_extract['TempDirExtract'])):
                            #remove dir tmp
                            shutil.rmtree(result_extract['TempDirExtract'])
   
def parse_result(self, result_extract, acl_write, md5_parent):
    stream_md5 = None
    if type(result_extract) is dict:
        #make reccursion extract each file embbed
        if 'FileMD5' in result_extract and result_extract['FileMD5']:
            tmp_dict={}
            b_yara=False
            b_ioc=False
            #extract info
            no_info=['ExtractInfo','ContainedObjects', 'Yara', 'PathFile', 'FileMD5', 'RootFileType', 'TempDirExtract']
            for key, value in result_extract.iteritems():
                if not key in no_info:
                    self._add_result('File: '+result_extract['FileMD5'] + ' - Info', key, {'value': str(value)})
            #extract yara match
            if result_extract['Yara']:
                for item_v in result_extract['Yara']:
                    for key, value in item_v.iteritems():
                        self._add_result('File: '+result_extract['FileMD5'] + ' - Signatures yara matched', key, value)
                        b_yara = True
            #extract IOC
            if result_extract['ExtractInfo']:
                for item_v in result_extract['ExtractInfo']:
                    for key, value in item_v.iteritems():
                        self._add_result('File: '+result_extract['FileMD5'] + ' - Extract potential IOC', key, {'value': str(value)})
                        b_ioc = True
            #add_sample
            if 'PathFile' in result_extract and type(result_extract['PathFile']) is list and len(result_extract['PathFile']) > 0:
                if os.path.isfile(str(result_extract['PathFile'][0])):
                    with open(str(result_extract['PathFile'][0]), 'r') as content_file_tmp:                        
                        content_tmp = content_file_tmp.read()
                        stream_md5 = hashlib.md5(content_tmp).hexdigest()
                        name = str(stream_md5).decode('ascii', errors='ignore')
                        id_ = Sample.objects(md5=stream_md5).only('id').first()
                        if id_:
                            self._info('Add relationship with sample existed:'+str(stream_md5))
                            #make relationship
                            id_.add_relationship(rel_item=self.obj,
                                     rel_type=RelationshipTypes.CONTAINED_WITHIN,
                                     rel_date=datetime.now(),
                                     analyst=self.current_task.user.username)
                        else:
                            if acl_write and (self.config['import_file'] or (self.config['import_file_yara'] and b_yara) or (self.config['import_file_ioc'] and b_ioc)):
                                obj_parent = None
                                if md5_parent:
                                    obj_parent = Sample.objects(md5=md5_parent).only('id').first()
                                if not obj_parent:
                                    sample = handle_file(name, content_tmp, self.obj.source,
                                            related_id=str(self.obj.id),
                                            related_type=str(self.obj._meta['crits_type']),
                                            campaign=self.obj.campaign,
                                            source_method=self.name,
                                            relationship=RelationshipTypes.CONTAINED_WITHIN,
                                            user=self.current_task.user)
                                else:
                                    sample = handle_file(name, content_tmp, obj_parent.source,
                                            related_id=str(obj_parent.id),
                                            related_type=str(obj_parent._meta['crits_type']),
                                            campaign=obj_parent.campaign,
                                            source_method=self.name,
                                            relationship=RelationshipTypes.CONTAINED_WITHIN,
                                            user=self.current_task.user)
                                self._info('Add sample '+str(stream_md5))
                            else:
                                #add IOC if not add sample
                                if self.current_task.user.has_access_to(IndicatorACL.WRITE) and b_yara:
                                    res = handle_indicator_ind(stream_md5,
                                                    self.obj.source,
                                                    IndicatorTypes.MD5,
                                                    IndicatorThreatTypes.UNKNOWN,
                                                    IndicatorAttackTypes.UNKNOWN,
                                                    self.current_task.user,
                                                    add_relationship=True,
                                                    source_method=self.name,
                                                    campaign=self.obj.campaign,
                                                    description='Extracted by service '+self.name)
                                    self._info('Add indicator md5:'+str(stream_md5)+' -- id: '+str(res))
            #contains file
            if 'ContainedObjects' in result_extract and type(result_extract['ContainedObjects']) is list and result_extract['ContainedObjects']:
                for item_v in result_extract['ContainedObjects']:
                    if item_v['FileMD5'] and item_v['FileType'] and item_v['FileSize']:
                        #search if file exist
                        id_ = Sample.objects(md5=str(item_v['FileMD5'])).only('id').first()
                        sample_exist = False
                        ioc_exist = False
                        if id_:
                            sample_exist = True
                        id_ =  Indicator.objects(value=str(item_v['FileMD5'])).only('id').first()
                        if id_:
                            ioc_exist = True
                        self._add_result('File: '+result_extract['FileMD5'] + ' - Contains md5 files', item_v['FileMD5'], {'type': str(item_v['FileType']), 'size': str(item_v['FileSize']), 'Exists Sample': str(sample_exist), 'Exists IOC md5': str(ioc_exist)})
                for item_v in result_extract['ContainedObjects']:
                    #re do loop for best display result
                    parse_result(self, item_v, acl_write, stream_md5)
