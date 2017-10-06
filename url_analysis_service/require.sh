#!/bin/bash
wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 -O /tmp/phantomjs-2.1.1-linux-x86_64.tar.bz2
tar -zxf /tmp/phantomjs-2.1.1-linux-x86_64.tar.bz2
mv /tmp/phantomjs-2.1.1/bin/phantomjs /usr/bin/phantomjs
pip install selenium
pip install python-hashes

