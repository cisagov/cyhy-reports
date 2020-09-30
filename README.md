CyHy Reports
=============

This package is used to generate CyHy reports and scorecards.  

Installation
------------

Required third party libraries can be installed using: `pip install -r requirements.txt`

Required configurations:
Every report generator will read `/etc/cyhy/cyhy.conf` to determine which CyHy database to use.


Docker Goodies
--------------
Support for Docker has been added.  Note that the container's cyhy user can only write to the mapped home volume, which is the default working directory for all execs.  This is very important because any required input files (e.g. the PREVIOUS_SCORECARD_JSON_FILE for CybEx scorecard creation) must reside in the directory mapped to /home/cyhy.

To build the Docker container for cyhy-reports:

```console
docker build -t cisagov/cyhy-reports .
```

To generate a CyHy report:

```console
docker run --rm --volume /private/etc/cyhy:/etc/cyhy --volume /private/tmp/cyhy:/home/cyhy cisagov/cyhy-reports cyhy-report [OPTIONS]
```

To generate a Cyber Exposure (CybEx) scorecard:

```console
docker run --rm --volume /private/etc/cyhy:/etc/cyhy --volume /private/tmp/cyhy:/home/cyhy cisagov/cyhy-reports cyhy-cybex-scorecard [OPTIONS]
```
