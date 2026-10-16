# ============================================================
# Lambda Python 3.10 + GMP + PBC + Charm-Crypto (OpenSSL 1.1)
#
# Build from the PROJECT ROOT (context must contain crypto/ and tests/):
#   docker build -f docker/Dockerfile -t abe-lambda:poc2 .
#
# The same image is used for every role in examples/demo.sh (Authority, owner, cloud, user);
# only the Lambda function itself runs CMD ["app.handler"] (the cloud role: CTUpdate).
#
# OpenSSL note: Charm's extension links against OpenSSL 1.1; the Lambda base image ships an
# older libssl, so build *and* runtime are forced to /usr/lib64/openssl11.
# ============================================================

FROM public.ecr.aws/lambda/python:3.10

ARG PBC_VERSION=0.5.14
ARG CHARM_REF=v0.63

# 1) System dependencies
RUN yum -y update && \
    yum -y groupinstall "Development Tools" && \
    yum -y install \
        gcc gcc-c++ make cmake git wget tar gzip which findutils \
        gmp gmp-devel libffi libffi-devel python3-devel \
        flex bison swig patch \
        openssl11 openssl11-devel \
    && yum clean all

ENV OPENSSL_LIB_DIR=/usr/lib64/openssl11
ENV OPENSSL_INCLUDE_DIR=/usr/include/openssl11
ENV LD_LIBRARY_PATH=/usr/lib64/openssl11:/usr/local/lib:$LD_LIBRARY_PATH
ENV CFLAGS="-I/usr/include/openssl11"
ENV LDFLAGS="-L/usr/lib64/openssl11"

# 2) PBC (pairing-based cryptography)
RUN cd /tmp && \
    wget https://crypto.stanford.edu/pbc/files/pbc-${PBC_VERSION}.tar.gz && \
    tar xzf pbc-${PBC_VERSION}.tar.gz && \
    cd pbc-${PBC_VERSION} && ./configure && make -j2 && make install && \
    cd / && rm -rf /tmp/pbc-${PBC_VERSION}*

# 3) Python runtime dependencies
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -U pip setuptools wheel && \
    python3 -m pip install -r /tmp/requirements.txt --target /var/task
ENV PYTHONPATH=/var/task

# 4) Charm-Crypto, pinned to a release tag
RUN cd /tmp && \
    git clone --depth 1 --branch ${CHARM_REF} https://github.com/JHUISI/charm.git && \
    cd charm && cp -f config.dist.py charm/config.py && \
    python3 setup.py install --prefix=/var/task && \
    cd / && rm -rf /tmp/charm
ENV PYTHONPATH=/var/task/lib/python3.10/site-packages:/var/task

# 5) Test tooling (lets examples/demo.sh run pytest inside the image; drop for production)
COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN python3 -m pip install -r /tmp/requirements-dev.txt

# 6) Project code (all roles share abe_core.py)
COPY crypto/abe_core.py crypto/hybrid.py crypto/object_store.py \
     crypto/ta_local.py crypto/owner_encrypt.py crypto/owner_upkeygen.py \
     crypto/cloud_update.py crypto/client_decrypt.py crypto/app.py \
     /var/task/
COPY tests /var/task/tests

# 7) Lambda entry: S3 ObjectCreated on updates/<object_id>/tk_v<N>.json -> CTUpdate
CMD ["app.handler"]
