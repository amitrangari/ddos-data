# Container definition for the TIG-CDO (Paper 2) replication package.
# Builds an environment with every dependency needed by the scripts this
# repository's README.md and REPRODUCTION.md reference.
#
# Build:  docker build -t tig-cdo-repro .
# Run:    docker run --rm -it -v "$PWD:/repro" tig-cdo-repro bash
#         (mount the repo so output JSON/figures land back on the host)

FROM python:3.11-slim

WORKDIR /repro

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["bash"]
