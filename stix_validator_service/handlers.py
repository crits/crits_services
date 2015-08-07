import sdv

from io import BytesIO

def validate_stix(xml):
    """
    Validate a STIX XML structure using stix-validator. Currently does not
    support profile validation until we can find a way to provide a profile
    file.

    :param xml: The XML to validate.
    :type xml: str
    :returns: dict
    """

    rdict = {'xml': None,
             'best_practices': None,
            #'profile': None,
             }
    xml = xml.encode('utf-8').strip()
    f = BytesIO(xml)
    try:
        result = sdv.validate_xml(f, schemaloc=True)
        rdict['xml'] = result.as_dict()
    except sdv.errors.UnknownSTIXVersionError, e:
        rdict['xml'] = "Could not determine @version attribute: %s" % str(e)
    except sdv.errors.InvalidSTIXVersionError, e:
        rdict['xml'] = "@version attribute is invalid: %s" % str(e)
    except sdv.errors.ValidationError, e:
        rdict['xml'] = "Schema directory not found or schemaloc is False: %s" % str(e)
    except sdv.errors.XMLSchemaImportError, e:
        rdict['xml'] = "Error while processing schemas for validation: %s" % str(e)
    except sdv.errors.XMLSchemaIncludeError, e:
        rdict['xml'] = "Error processing xs:include directives: %s" % str(e)
    except IOError, e:
        rdict['xml'] = "Not a valid XML document: %s" % str(e)
    except Exception, e:
        rdict['xml'] = str(e)

    f.seek(0)
    try:
        result = sdv.validate_best_practices(f)
        rdict['best_practices'] = result.as_dict()
    except sdv.errors.UnknownSTIXVersionError, e:
        rdict['best_practices'] = "Could not determine @version attribute: %s" % str(e)
    except sdv.errors.InvalidSTIXVersionError, e:
        rdict['best_practices'] = "@version attribute is invalid: %s" % str(e)
    except IOError, e:
        rdict['best_practices'] = "Not a valid XML document: %s" % str(e)
    except Exception, e:
        rdict['best_practices'] = str(e)

    #f.seek(0)
    #try:
    #    result = sdv.validate_profile(f)
    #    rdict['profile'] = result.as_dict()
    #except sdv.errors.ProfileParseError, e:
    #    rdict['profile'] = "Error parsing profile: %s" % str(e)
    #except IOError, e:
    #    rdict['profile'] = "Not a valid XML document: %s" % str(e)
    #except Exception, e:
    #    rdict['profile'] = str(e)

    return rdict
