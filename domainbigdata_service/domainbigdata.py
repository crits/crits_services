###############################################################################
#Author: Lionel PRAT - Original author: Roberto Sponchioni - <rsponchioni@yahoo.it> @Ptr32Void
#Modified: 12/10/2017
#Modified source code: https://github.com/Ptr32Void/OSTrICa/blob/master/ostrica/Plugins/DomainBigData/__init__.py
###############################################################################
####################### HEAD OF ORIGIN SOURCE CODE:
#-------------------------------------------------------------------------------
# Name:            OSTrICa - Open Source Threat Intelligence Collector - DomainBigData plugin
# Purpose:        Collection and visualization of Threat Intelligence data
#
# Author:          Roberto Sponchioni - <rsponchioni@yahoo.it> @Ptr32Void
#
# Created:         20/12/2015
# Licence:         This file is part of OSTrICa.
#
#                OSTrICa is free software: you can redistribute it and/or modify
#                it under the terms of the GNU General Public License as published by
#                the Free Software Foundation, either version 3 of the License, or
#                (at your option) any later version.
#
#                OSTrICa is distributed in the hope that it will be useful,
#                but WITHOUT ANY WARRANTY; without even the implied warranty of
#                MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#                GNU General Public License for more details.
#
#                You should have received a copy of the GNU General Public License
#                along with OSTrICa. If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------
###############################################################################
import sys
import string
import re
from bs4 import BeautifulSoup

import requests

class DomainBigData:

    host = "domainbigdata.com"

    def __init__(self):
        self.intelligence = {}
        self.index_value = ''
        self.intelligence_list = []
        pass

    def __del__(self):
        self.intelligence = {}

    def email_information(self, email, log):
        query = '/email/%s' % (email)
        url = "http://%s%s"%(self.host,query)
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36'}
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            content = r.text.encode('utf8')
            self.collect_email_intelligence(content)
            return self.intelligence
        else:
            return {domain: r.status_code}

    def collect_email_intelligence(self, server_response):
        soup = BeautifulSoup(server_response, 'html.parser')
        associated_sites = soup.findAll('table', {'class':'t1'})
        if len(associated_sites) == 1:
            self.extract_associated_sites(associated_sites[0].tbody)
        name_soup = soup.findAll('tr', {'id':'trRegistrantName'})
        if len(name_soup) == 1:
            email2name = self.extract_information_from_dd(name_soup[0])
            self.intelligence['Domain_For_Name'] = email2name
        org_soup = soup.findAll('tr', {'id':'trRegistrantName'})
        if len(org_soup) == 1:
            email2org = self.extract_information_from_dd(org_soup[0])
            self.intelligence['Domain_For_Org'] = email2org
                
    def extract_associated_sites(self, soup):
        associated_sites = []
        idx = 0
        related_sites = soup.findAll('td')
        for site in related_sites:
            if idx == 0:
                associated_site = site.get_text()
                idx += 1
                continue
            elif idx == 1:
                creation_date = site.get_text()
                idx += 1
                continue
            elif idx == 2:
                registrar = site.get_text()
                idx = 0
                associated_sites.append({'associated_site':associated_site, 'creation_date':creation_date, 'registrar':registrar})
                continue
        self.intelligence['associated_sites'] = associated_sites

    def name2dom_collect_information(self, url):
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36'}
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            content = r.text.encode('utf8')
            return self.collect_email2dom_intelligence(content)
        else:
            return {domain: r.status_code}

    def collect_email2dom_intelligence(self, server_response):
        soup = BeautifulSoup(server_response, 'html.parser')
        associated_sites = soup.findAll('table', {'class':'t1'})
        if len(associated_sites) == 1:
            return self.extract_associated_sites2nj(associated_sites[0].tbody)
    
    def extract_associated_sites2nj(self, soup):
        associated_sites = []
        idx = 0
        related_sites = soup.findAll('td')
        for site in related_sites:
            if idx == 0:
                associated_site = site.get_text()
                idx += 1
                continue
            elif idx == 1:
                creation_date = site.get_text()
                idx += 1
                continue
            elif idx == 2:
                registrar = site.get_text()
                idx = 0
                associated_sites.append({'associated_site':associated_site, 'creation_date':creation_date, 'registrar':registrar})
                continue
        return associated_sites

    def domain_information(self, domain, log):
        query = '/%s' % (domain)
        url = "http://%s%s"%(self.host,query)
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36'}
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            content = r.text.encode('utf8')
            self.collect_domain_intelligence(content)
            return self.intelligence
        else:
            return {domain: r.status_code}

    def collect_domain_intelligence(self, server_response):
        soup = BeautifulSoup(server_response, 'html.parser')
        records = soup.findAll('div', {'id':'divDNSRecords'})

        if len(records) == 1:
            dns_records = records[0].findAll('table', {'class':'t1'})
            self.extract_associated_records(dns_records)

        records = soup.findAll('div', {'id':'divListOtherTLD'})
        if len(records) == 1:
            tdls = []
            other_tdls = records[0].findAll('a')
            for tdl in other_tdls:
                tdls.append(tdl.string)
            self.intelligence['other_tdls'] = tdls

        records = soup.findAll('div', {'id':'MainMaster_divRegistrantIDCard'})
        if len(records) == 1:
            self.collect_registrant_information(records[0])

    def collect_registrant_information(self, soup):
        registrant_organization = ''
        registrant_email = ''
        registrant_name = ''
        registrant_city = ''
        registrant_country = ''
        registrant_phone = ''

        organization_soup = soup.findAll('tr', {'id':'MainMaster_trRegistrantOrganization'})
        email_soup = soup.findAll('tr', {'id':'trRegistrantEmail'})
        name_soup = soup.findAll('tr', {'id':'trRegistrantName'})
        city_soup = soup.findAll('tr', {'id':'trRegistrantCity'})
        country_soup = soup.findAll('tr', {'id':'trRegistrantCountry'})
        phone_soup = soup.findAll('tr', {'id':'trRegistrantTel'})

        if len(organization_soup) == 1:
            registrant_organization = self.extract_information_from_registrant(organization_soup[0])
            orgdom = self.extract_information_from_dd(organization_soup[0])
            self.intelligence['Domain_For_Org'] = orgdom
            
        if len(email_soup) == 1:
            registrant_email = self.extract_information_from_registrant(email_soup[0])
            emaildom = self.extract_information_from_dd(email_soup[0])
            self.intelligence['Domain_For_Email'] = emaildom
            
        if len(name_soup) == 1:
            registrant_name = self.extract_information_from_registrant(name_soup[0])
            namedom = self.extract_information_from_dd(name_soup[0])
            self.intelligence['Domain_For_Name'] = namedom
            
        if len(city_soup) == 1:
            registrant_city = self.extract_information_from_registrant(city_soup[0])

        if len(country_soup) == 1:
            registrant_country = self.extract_information_from_registrant(country_soup[0])

        if len(phone_soup) == 1:
            registrant_phone = self.extract_information_from_registrant(phone_soup[0])

        self.intelligence['organization'] = registrant_organization
        self.intelligence['email'] = registrant_email
        self.intelligence['registrant_name'] = registrant_name
        self.intelligence['registrant_city'] = registrant_city
        self.intelligence['registrant_country'] = registrant_country
        self.intelligence['registrant_phone'] = registrant_phone

    def extract_information_from_dd(self, soup):
        soup = soup.findAll('td')
        link = None
        link = soup[1].find('a').get('href')
        name = ''
        if len(soup) == 3:
            soup_img = soup[1].findAll('img')
            if len(soup_img) == 1:
                name = soup[1].contents[1]
            else:
                name = soup[1].string
        elif len(soup) == 2:
            name = soup[1].string
        #get dom
        if link:
            domains = self.name2dom_collect_information("http://%s%s"%(self.host,link))
            return {name: domains}
                            
    def extract_information_from_registrant(self, soup):
        soup = soup.findAll('td')
        if len(soup) == 3:
            soup_img = soup[1].findAll('img')
            if len(soup_img) == 1:
                return soup[1].contents[1]
            else:
                return soup[1].string
        elif len(soup) == 2:
            return soup[1].string
        return ''

    def extract_associated_records(self, soups):
        associated_records = []
        for soup in soups:
            all_trs = soup.findAll('tr')
            self.extract_trs(all_trs)
            self.intelligence[self.index_value] = self.intelligence_list
            self.intelligence_list = []

    def extract_trs(self, soup):
        for tr in soup:
            self.extract_tds(tr)

    def extract_tds(self, soup):
        idx = True # idx flags the type of record that will be added in the dictionary if True
        record_list = []
        for td in soup:
            if idx and td.get_text() not in self.intelligence.keys():
                self.index_value = td.get_text()
                self.intelligence[self.index_value] = ''
            idx = False
            record_list.append(td.get_text())
        self.intelligence_list.append(record_list)

