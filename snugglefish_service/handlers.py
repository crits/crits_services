from crits.samples.sample import Sample
from crits.core.user_tools import user_sources
from snugglefish_service.snugglefish import SnuggleIndex

def snugglefish_status():
    # Return a list of dictionaries, one per index. Filter out
    # the query as it can contain sensitive information like source names.
    # Also filter out the directory as it is not important for this.
    #
    # We do not filter out the index name though, so be careful not to put
    # sensitive names as your index name.
    ret = []

    sngindexes = SnuggleIndex.objects()
    if not sngindexes:
        return ret

    for sngindex in sngindexes:
        tmp = sngindex.to_dict()
        del(tmp['_id'])
        del(tmp['query'])
        del(tmp['directory'])
        try:
            tmp['percent'] = (float(sngindex.count)/sngindex.total) * 100
        except:
            tmp['percent'] = 0
        ret.append(tmp)
    return ret

def snugglefish_search(indexes, search, user):
    """Execute search of selected index with the given string."""

    import pysnugglefish

    # Return a dictionary where the key is the index name and the
    # value a dictionary with status and a list of potential matches.
    ret = {}

    # If there are no sources, return early.
    sources = user_sources(user)
    if not sources:
        return ret

    for idx in indexes:
        ret[idx] = {
                     'success': True,
                     'reason': '',
                     'files': []
                   }
        sngindex = SnuggleIndex.objects(name=idx).first()
        if not sngindex:
            ret[idx]['reason'] = "Index not found in database."
            ret[idx]['success'] = False
            continue
        snuggle = pysnugglefish.init(str(sngindex.directory + "/" + idx))
        try:
            tmp = snuggle.search(search)
            for res in tmp:
                if Sample.objects(md5=res, source__name__in=sources).count() > 0:
                    ret[idx]['files'].append(res)
        except Exception, e:
            ret[idx]['reason'] = "Error: %s" % e
            ret[idx]['success'] = False
    return ret
