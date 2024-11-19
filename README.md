# Security Compass - Technical Assessment

## Requirements
- Python 3.13.0
- Docker
- A Kubernetes cluster (?)
- Helm (?)

## Installation

`pip install -r requirements.txt`

## To Run

See `python vulnreport.py` for instructions

## Trivy Usage Notes
This solution uses the docker release of aquasec/trivy
Some notes on usage:

`docker run aquasec/trivy:0.57.1 help`

`docker run aquasec/trivy:0.57.1 image {target}`


#