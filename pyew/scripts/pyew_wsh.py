# This code is a modified version of the example echo_wsh.py websocket handler
# that comes with mod_pywebsocket for use as a CRITs service.
#
# Copyright 2011, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import base64
import os
import pexpect
import sys
import tempfile
from urlparse import urlparse, parse_qs

from crits.core.user import CRITsUser
from crits.samples.sample import Sample
from crits.services.service import CRITsService

_GOODBYE_MESSAGE = u'Goodbye'

def web_socket_do_extra_handshake(request):
    # This example handler accepts any request. See origin_check_wsh.py for how
    # to reject access from untrusted scripts based on origin value.

    pass  # Always accept.

def web_socket_transfer_data(request):
    # for some reason we need to set the timeout to 1 second.
    # it causes the responses to be as quick as the timeout
    # instead of taking forever :(
    timeout = 1
    log = ""

    id_ = None
    token = None
    if request.unparsed_uri:
        qs = parse_qs(urlparse(request.unparsed_uri).query)
        token = qs.get('token', [None])[0]
        id_ = qs.get('id', [None])[0]

    if not id_ or not token:
        text = "No id or token available to start pyew process"
    else:
        text = "\nStarting pyew process for id: %s...\n" % id_
    request.ws_stream.send_message(base64.b64encode(text),
                                   binary=False)

    if not id_ or not token:
        sys.exit(1)

    (c, sample_name) = start_pyew_shell(request, id_, token)

    i = c.expect([pexpect.TIMEOUT,'[*]>'], timeout=timeout)
    if i == 0:
        pass
    log += c.before
    request.ws_stream.send_message(base64.b64encode(log), binary=False)

    # delete temp file
    os.unlink(sample_name)

    while True:
        line = base64.b64decode(request.ws_stream.receive_message())
        if line is None:
            return
        c.sendline(line)
        i = c.expect([pexpect.TIMEOUT,'[*]>'], timeout=timeout)
        if i == 0:
            pass
        nlog = c.before
        request.ws_stream.send_message(base64.b64encode(nlog[len(log):]),
                                       binary=False)
        log = nlog

def start_pyew_shell(request, id_, token):

    # Make sure we can find pyew
    svc = CRITsService.objects(name='Pyew').first()
    if not svc:
        text = "\nPyew not found"
        request.ws_stream.send_message(base64.b64encode(text),
                                       binary=False)
        sys.exit(1)

    sc = svc.config
    pyew = str(sc['pyew'])

    if not os.path.exists(pyew):
        text = "\nPyew not found"
        request.ws_stream.send_message(base64.b64encode(text),
                                       binary=False)
        sys.exit(1)

    # Find CRITs user by token
    query = {'unsupported_attrs.pyew_token': token}
    user = CRITsUser.objects(__raw__=query).first()
    if not user:
        text = "\nCould not validate user"
        request.ws_stream.send_message(base64.b64encode(text),
                                       binary=False)
        sys.exit(1)

    # Remove this one-time use token
    ua = user.unsupported_attrs
    delattr(ua, 'pyew_token')
    user.unsupported_attrs = ua
    try:
        user.save()
    except:
        pass

    # Make sure we have a sample to work with that this user has access to
    sample = Sample.objects(id=id_, source__name__in=user.get_sources_list()).first()
    if not sample:
        text = "\nNo Sample found"
        request.ws_stream.send_message(base64.b64encode(text),
                                       binary=False)
        sys.exit(1)
    sample_data = sample.filedata.read()
    if not sample_data:
        text = "\nCould not get Sample from GridFS: %s" % id_
        request.ws_stream.send_message(base64.b64encode(text),
                                       binary=False)
        sys.exit(1)

    # write Sample to disk
    # temp_sample is the sample to read
    try:
        temp_sample = tempfile.NamedTemporaryFile(delete=False)
        sample_name = temp_sample.name
        temp_sample.write(sample_data)
        temp_sample.close()
    except Exception, e:
        text = "\nError writing file to disk: %s" % e
        request.ws_stream.send_message(base64.b64encode(text),
                                       binary=False)
        sys.exit(1)
    c = pexpect.spawn('/usr/bin/env python %s %s' % (pyew, sample_name))

    return c, sample_name

# vi:sts=4 sw=4 et
