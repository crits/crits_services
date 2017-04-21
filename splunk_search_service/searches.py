# Contains searches for a given TLO
import re


class SplunkSearches(object):
    def __init__(self, obj):
        
        # Dictionary passed from DataMine can be used as a map
        if isinstance(obj, dict):
            self.obj = obj
        # If it's a list, set it as list
        elif isinstance(obj, list):
            self.list = obj
        # Otherwise, convert the object to a mapping dictionary
        else:
            fields = obj.__dict__
            self.obj = {}
            for item in fields['_fields_ordered']:
                self.obj[item] = getattr(obj,item)
                
    # Function for making sure the search name doesn't have a . \ or $ in it
    def clean_keys(self, key):
        return key.replace("\\","&#92;").replace("\$","&#36;").replace(".","&#46;")
        
        
    def email_searches(self):
        '''
        # Potential Email attributes that can be called via {attribute} with .format(**self.obj)
        boundary
        cc
        date
        from_address
        helo
        message_id
        originating_ip
        raw_body
        raw_header
        reply_to
        sender
        subject
        to
        x_originating_ip
        x_mailer
        '''
        self.splunk_searches = {"description": "Searches Splunk based on email attibutes",
                          "searches": [{"name": self.clean_keys("Email sender"),
                                        "search": ("index=smtp src_user=\"{sender}\""
                                                   "| stats values(src_user) AS src_user "
                                                   "values(recipient) AS recipient count by subject").format(**self.obj)},
                                        {"name": self.clean_keys("Email subject"),
                                        "search": ("index=smtp subject=\"{subject}\""
                                                   "| stats values(src_ip) AS src_ip values(recipient) AS recipient "
                                                   "count by subject").format(**self.obj)}
                                      ]
                                }
                                        
        return self.splunk_searches
        
    def sample_searches(self):
        '''
        # Potential Email attributes that can be called via {attribute} with .format(**self.obj)
        filedata
        filename
        filenames
        filetype
        md5
        mimetype
        sha1
        sha256
        size
        ssdeep
        impfuzzy
        '''
        self.splunk_searches = {"description": "Searches Splunk based on sample attributes",
                                "searches": [{"name": self.clean_keys("MD5 Search"),
                                              "search": ("index=files md5=\"{md5}\""
                                                         "|stats values(dest_ip) AS dest_ip values(global_cuid) AS global_cuid"
                                                         " values(global_fuid) AS global_fuid count by src_ip").format(**self.obj)},
                                             ]
                               }
        return self.splunk_searches
                                              
    def datamined(self):

        self.splunk_searches = {"description": "Splunk searches for data mined from this object",
                                "searches": []}
        for key,val in self.obj.iteritems():
            if val!='':
                for item in val:
                    if key=='urls':
                        self.splunk_searches['searches'].append({"name": self.clean_keys(item), "search": "index=smtp_links url=\""+item+"\""}) 
                    elif key=='domains':
                        self.splunk_searches['searches'].append({"name": self.clean_keys(item), "search": "index=http domain="+item}) 
                    elif key=='ips':
                        self.splunk_searches['searches'].append({"name": self.clean_keys(item), "search": "index=http src_ip="+item+"OR dest_ip="+item}) 
                    elif key=='hashes':
                        self.splunk_searches['searches'].append({"name": self.clean_keys(str(item)), "search": "index=files "+item[0]+"=TERM("+item[1]+")"})
                    elif key=='emails':
                        self.splunk_searches['searches'].append({"name": self.clean_keys(item), "search": "index=smtp src_user=\""+item+"\""}) 
        
        return self.splunk_searches

    def url_searches(self):
        self.splunk_searches = {"description": "Splunk searches for URLs mined from this object",
                                "searches": []}
        for url in self.list:
            self.splunk_searches['searches'].append({"name": self.clean_keys(str("smtp_links search for "+url)), 
                                                     "search": ("index=smtp_links url=\""+url+"\""
                                                                "|stats values(url) AS url values(recipient) AS recipient "
                                                                "count by src_user subject")})
            # Strip the protocol
            pattern = r"^(https?|ftp)://"
            url_no_proto = re.sub(pattern, r"", url)
            self.splunk_searches['searches'].append({"name": self.clean_keys(str("http search for "+url_no_proto)), 
                                                     "search": ("index=http url=\""+url_no_proto+"\""
                                                                "|stats values(src_ip) AS src_ip values(dest_ip) AS dest_ip "
                                                                "values(url) AS url count by domain")})
        return self.splunk_searches
                                                                
    def domain_searches(self):
        self.splunk_searches = {"description": "Splunk searches for domains mined from this object",
                                "searches": []}
        for domain in self.list:
            self.splunk_searches['searches'].append({"name": self.clean_keys(str("smtp_links/http search for "+domain)), 
                                                     "search": ("index=smtp_links OR index=http domain=\""+domain+"\""
                                                                "|stats values(src_ip) AS src_ip values(url) AS url "
                                                                "values(src_user) AS src_user values(subject) AS subject "
                                                                "values(recipient) AS recipient count by index")})
                                                                
        return self.splunk_searches
        
    def ip_searches(self):
        self.splunk_searches = {"description": "Splunk searches for domains mined from this object",
                                "searches": []}
        for ip in self.list:
            self.splunk_searches['searches'].append({"name": self.clean_keys(str("smtp_links/http search for "+ip+" as domain")), 
                                                     "search": ("index=smtp_links OR index=http domain=\""+ip+"\""
                                                                "|stats values(src_ip) AS src_ip AS subject values(url) AS url "
                                                                "values(src_user) AS src_user values(subject) "
                                                                "values(recipient) AS recipient count by index")})
                                                                
        return self.splunk_searches
        
    