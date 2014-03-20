atlas Nagios
============

Library for preforming various nagios checks using the RIPE Atlas[1] network. 

To use this library you will need to have a current ongoing atlas measurement and know the measurement id.  You should note that this is a work in progress so there are likley errors and almost definetly typos and spelling mistakes.

Basic Usage
-----------
for supported measuerment types run the following command

atlas-nagios -h 

To get information on what checks are supported run the following

atlas-nagios type -h

some measuerment types will have sub commands, such as the dns check.  to see what these support run the following 

atlas-nagios type subtype -h

Standard checks
---------------

There are a number of parameters that are standard for all check types

###Arguments
####Number of Warning probes
> -w/--warn-probes #of probes

This parameter takes an inteiger and intructes the script to exit with a warning state if # or more probes exit in a warning state.  Warning states are dependent on the check type
 
####Number of criticle probes
> -c/--crit-probes #of probes

This parameter takes an inteiger and intructes the script to exit with a critical state if # or more probes exit in a critical state.  Warning states are dependent on the check type
 
####Key
> -k/--key APIKEY

This is used to pass an API key for measurments that are marked as private.

####Maximum 
> --max_measurement_age #Seconds

This argument takes an int representinf seconds.  If a probes measurment data is older then this value then the probe is considered to be in a critical state

####Verbosity
> -v[v[v]]

This works like a standard -v flag the more you pass the more info you get back.  

SSL Check
---------
This runs checks agains the SSL check

###Arguments
####Common name
> --common-name CN

if the CN seen by the atlas probe dose not match this parameter then the probe will be marke in the critical state

####SSL Expiry
> --sslexpiry #days (default: 30 days)

If the expiry seen by the probe is less then the current time + this mount of days then the probe will go into a warning state.  If there certificate sen by the probe has already expired the probe will go into a critical state

####SSL SH1 hash
> --sha1hash Certificat:SHA1:hash

If the sha1 hash seen by the probe is different to the one past the probe will go into a critical state.



[1]https://atlas.ripe.net/
