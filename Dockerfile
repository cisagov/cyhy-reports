FROM dhub.ncats.dhs.gov:5001/cyhy-core-with-latex-geos
MAINTAINER David Redmin <david.redmin@hq.dhs.gov>
ENV CYHY_REPORTS_SRC="/usr/src/cyhy-reports" \
    PHANTOMJS="phantomjs-2.1.1-linux-x86_64"

USER root
WORKDIR ${CYHY_REPORTS_SRC}

# Install our own fonts
COPY cyhy_report/assets/Fonts /usr/share/fonts/truetype/ncats
RUN fc-cache -fsv

# Install PhantomJS (used by cyhy-bod-scorecard and potentially by cyhy-cybex-scorecard); may not be needed in the future
RUN apt-get update && apt-get -y install \
    build-essential chrpath libssl-dev libxft-dev \
    libfreetype6 libfreetype6-dev \
    libfontconfig1 libfontconfig1-dev
RUN curl -sLO https://bitbucket.org/ariya/phantomjs/downloads/${PHANTOMJS}.tar.bz2 && \
    tar xvjf ${PHANTOMJS}.tar.bz2 && \
    mv ${PHANTOMJS} /usr/local/share && \
    ln -sf /usr/local/share/${PHANTOMJS}/bin/phantomjs /usr/local/bin

COPY . ${CYHY_REPORTS_SRC}

RUN pip install --no-cache-dir -r requirements.txt
#RUN ln -snf ${CYHY_REPORTS_SRC}/var/getenv /usr/local/bin
COPY ./docker-entrypoint.sh /

USER cyhy
WORKDIR ${CYHY_HOME}

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["help"]
