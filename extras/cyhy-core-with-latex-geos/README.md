NCATS cyhy-core-with-latex-geos
================

This is a Docker image that builds on cyhy-core and installs LaTeX and GEOS, which are used by cyhy-reports.  Since those packages are large and don't change very often, we decided to remove them from the cyhy-reports image to reduce the time needed to build the cyhy-reports image.

Docker Build
------------

To build the Docker container for cyhy-core-with-latex-geos:

```bash
docker build -t dhub.ncats.dhs.gov:5001/cyhy-core-with-latex-geos .
```

To run the container:
```bash
docker run --name cyhy-core-with-latex-geos --detach dhub.ncats.dhs.gov:5001/cyhy-core-with-latex-geos
```

To attach a shell:
```bash
docker exec -ti cyhy-core-with-latex-geos /bin/bash
```
