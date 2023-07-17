FROM cisagov/cyhy-core AS cyhy-core-with-latex-geos
LABEL maintainer="David Redmin <david.redmin@cisa.dhs.gov>"
LABEL description="Docker image to generate CyHy reports and scorecards."

USER root

# Install required packages
RUN apt-get update && apt-get -y install \
    libgeos-3.7.1 \
    libgeos-dev \
    python-dateutil \
    python-docopt \
    python-mpltoolkits.basemap \
    python-netaddr \
    python-numpy \
    python-pandas \
    python-progressbar \
    python-pypdf2 \
    python-unicodecsv \
    texlive \
    texlive-fonts-extra \
    texlive-latex-extra \
    texlive-science \
    texlive-xetex

FROM cyhy-core-with-latex-geos
ENV CYHY_REPORTS_SRC="/usr/src/cyhy-reports" \
    PHANTOMJS="phantomjs-2.1.1-linux-x86_64"

WORKDIR ${CYHY_REPORTS_SRC}

# Install our own fonts
COPY cyhy_report/assets/Fonts /usr/share/fonts/truetype/ncats
RUN fc-cache -fsv

# Install PhantomJS (used by cyhy-bod-scorecard and potentially by cyhy-cybex-scorecard); may not be needed in the future
RUN apt-get update && apt-get -y install \
    build-essential \
    chrpath \
    curl \
    libfontconfig1 \
    libfontconfig1-dev \
    libfreetype6 \
    libfreetype6-dev \
    libssl-dev \
    libxft-dev
RUN curl -sLO https://bitbucket.org/ariya/phantomjs/downloads/${PHANTOMJS}.tar.bz2 && \
    tar xvjf ${PHANTOMJS}.tar.bz2 && \
    mv ${PHANTOMJS} /usr/local/share && \
    ln -sf /usr/local/share/${PHANTOMJS}/bin/phantomjs /usr/local/bin

COPY . ${CYHY_REPORTS_SRC}

RUN pip install --no-cache-dir -r requirements.txt
COPY ./docker-entrypoint.sh /

USER cyhy
WORKDIR ${CYHY_HOME}

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["help"]
