import yara
import pprint
import binascii

from crits.samples.sample import Sample

def test_yara_rule(id_, rule):
    sample = Sample.objects(id=id_).first()
    data = sample.filedata.read()
    success = False
    message = ""
    if not sample or not data:
        message = "No sample found!"
    else:
        try:
            rules = yara.compile(source=rule)
            matches = rules.match(data=data)
            yara_results = []
            mcount = 0
            for match in matches:
                strings = {}
                for s in match.strings:
                    s_name = s[1]
                    s_offset = s[0]
                    try:
                        s_data = s[2].decode('ascii')
                    except UnicodeError:
                        s_data = "Hex: " + binascii.hexlify(s[2])
                    s_key = "{0}-{1}".format(s_name, s_data)
                    if s_key in strings:
                        strings[s_key]['offset'].append(s_offset)
                    else:
                        strings[s_key] = {
                            'rule': str(match),
                            'offset': [s_offset],
                            'name': s_name,
                            'data': s_data,
                        }
                string_list = []
                for key in strings:
                    string_list.append(strings[key])
                yara_results.append(string_list)
                mcount += 1
            success = True
            if mcount == 0:
                yara_results.append("No matches!")
            message = pprint.pformat(yara_results)
        except SyntaxError as e:
            message = "Syntax error in YARA rule: %s" % str(e)
    return {"success": success, "message": message}
