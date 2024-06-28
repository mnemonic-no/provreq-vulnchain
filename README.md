# Vulnchain config generator

## Tool to generate Provreq configuration files for use with CVE entries.

This tool create [provreq](https://github.com/mnemonic-no/provreq) configuration files from
the NVD database data dumps.

## Install

Download all the CVE data files from [NVD](https://nvd.nist.gov/vuln/data-feeds)

Extract these files to a data directory (e.g. ~/data/nvd)

```bash
$ cd ~
$ mkdir src; cd src
$ git clone https://github.com/mnemonic-no/provreq-vulnchain
$ cd provreq-vulnchain
$ sudo python3 -m pip install .
$ provreq-build-cve-agent-promises --datadir ~/cvedata/
```
This creates the agent_promises.json and promise_descriptions.csv needed for use with provreq.

The Agent names are the CVE-nnnn-nnnnn IDs
