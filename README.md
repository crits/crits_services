crits_services
==============

This repo contains services for CRITs that allow you to extend its
functionality. Information on how to use, install, and leverage these services
can be found in the main CRITs repository:

https://www.github.com/crits/crits

Each service comes with its own README, LICENSE, DEPENDENCIES, bootstrap, and requirements.txt file. If you
choose to leverage a service, make sure you read the DEPENDENCIES file to
determine what you’ll need to install to use it. The README will be a good guide
to determine what a service does, and in some cases how to set it up and use it.

The bootstrap in the crits_services folder is supposed to run the bootstrap in each services' folder. Each service's bootstrap in turn, after installing any OS level dependencies, kicks off pip to install the python dependencies listed in requirements.txt

At this point there are a few services that require some additional manual installation, this might change in the future as any pull requests to fix these issues are greatly appreciated.

The services that currently require some manual installation are (at least until somebody fixes them):

- chopshop_service
- metacap_service (it needs chopshop)
- pyew
- snugglefish_service
- taxii_service

