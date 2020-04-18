FROM ubuntu:trusty
RUN apt-get update -y && \
    apt-get install -y perl python2.7  nmap sslscan postgresql libdnet-dev libpq-dev libpcap-dev bison flex wget build-essential
#install unicronscan
RUN wget http://sourceforge.net/projects/osace/files/unicornscan/unicornscan%20-%200.4.7%20source/unicornscan-0.4.7-2.tar.bz2/download -O unicornscan-0.4.7-2.tar.bz2 && \
    tar jxvf unicornscan-0.4.7-2.tar.bz2 && \   
    cd unicornscan-0.4.7/ && \
    ./configure CFLAGS=-D_GNU_SOURCE && \
    make && \
    sudo make install
WORKDIR \
COPY . /
ENTRYPOINT [ "sh" ]
CMD [ "massbleed.sh" ]
