FROM dhub.ncats.dhs.gov:5001/cyhy-core
MAINTAINER David Redmin <david.redmin@hq.dhs.gov>
ENV GEOS_VERSION="geos-3.6.0" \
    GEOS_DIR=/opt/${GEOS_VERSION}

USER root

# Install LaTeX packages
RUN apt-get update && apt-get -y install \
    texlive-xetex \
    texlive-latex-extra \
    texlive-fonts-extra \
    texlive-math-extra

# Install GEOS (required by basemap)
RUN curl -sO http://download.osgeo.org/geos/${GEOS_VERSION}.tar.bz2 && \
    tar xjf ${GEOS_VERSION}.tar.bz2 && \
    cd ${GEOS_VERSION} && \
    ./configure --prefix=${GEOS_DIR} && \
    make install-strip && \
    cd .. && rm -rf ${GEOS_VERSION}* && \
    ldconfig
