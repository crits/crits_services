The crits_services/taxii_service allows CRITs instances to send and receive Cyber Threat Intelligence (CTI) using OASIS CTI Technical Committee STIX, CybOX and TAXII Standards.

This document shows how to configure CRITS for communication with various TAXII Services (EclecticIQ test.taxiistand.com, Soltra hailataxii.com,


# EclecticIQ test.taxiistand.com

## Requirements

  CRITS Master Branch [5d182ae99a2912fdf1a86544e64e7b2ef066c994] (or later)
  
  CRITS_SERVICES Master Branch [86b56fc40ff2b9994c3cf42bd4f15b9cbf6516b5] (or later)


## Configuring the TAXII Service for EcelcticIQ TAXIIStand

### Initial Setup (if required)

![Service Config 1](./CRITS TAXII Service Screen 1- Config TAXII Service.png)


### Configure the EcelcticIQ TAXIIStand TAXII Server in your CRITs

![Service Config 2](./CRITS TAXII Service Screen 2 - Config TAXII Servers.png)


### Configure the EcelcticIQ TAXIIStand TAXII Feed you will pull Packages from

![Service Config 3](./CRITS TAXII Service Screen 3 - Config TAXII Feeds.png)


## Sending a Package to EcelcticIQ TAXIIStand

![SEND package 1](./CRITS TAXII Service Screen 4 - Send Package - Package Selection.png)
![SEND package 2](./CRITS TAXII Service Screen 5 - Send Package - Releasibility.png)
![SEND package 3](./CRITS TAXII Service Screen 5 - Send Package - Success.png)

## Receiving Packages from EcelcticIQ TAXIIStand
![TAXII Agent 1](./CRITS TAXII Agent Screen 1 - TAXII Agent Launch.png)
![TAXII Agent 2](./CRITS TAXII Agent Screen 2 - TAXII Agent Poll.png)
![TAXII Agent 3](./CRITS TAXII Agent Screen 3 - TAXII Agent Preview.png)
![TAXII Agent 4](./CRITS TAXII Agent Screen 4 - TAXII Agent Results.png)
![TAXII Agent 5](./CRITS TAXII Agent Screen 5 - Saved Polls and Uploads.png)


