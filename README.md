# crl2f5-connector

[![License](https://img.shields.io/badge/license-BSD%203--Clause-yellow.svg?style=flat)](https://github.com/e-XpertSolutions/crl2f5-connector/blob/master/LICENSE)
[![Travis](https://travis-ci.org/e-XpertSolutions/crl2f5-connector.svg?branch=master)](https://travis-ci.org/e-XpertSolutions/crl2f5-connector)
[![GoReport](https://goreportcard.com/badge/github.com/e-XpertSolutions/crl2f5-connector)](https://goreportcard.com/report/github.com/e-XpertSolutions/crl2f5-connector)


`crl2f5-connector` is a small service that fetches at a regular interval a CRL
from its distribution point in order to upload it on possibly multiple F5 BigIP
instances. Once uploaded, the LTM client SSL profile defined in the
configuration file is updated with that new CRL file.


## Contributing

Contributions are greatly appreciated. The project follows the typical
[GitHub pull request model](https://help.github.com/articles/using-pull-requests/)
for contribution.


## License

The sources are release under a BSD 3-Clause License. The full terms of that
license can be found in `LICENSE` file of this repository.
