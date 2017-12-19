# Test project for edge-jwt-sample
This test project has automated test scripts based on cucumber in BDD style. The project uses [apickli](https://github.com/apickli/apickli) a REST API integration testing framework.

## Setup

### Node JS
[Download](https://nodejs.org/en/download/) and install NodeJS. NPM should be installed as part of it.

## Dependencies
Get dependencies in package.json by npm install.

```
$ cd edge-jwt-sample/test
$ npm install
```

## Run
To run BDD tests, first update org and env name in URL variable of file `edge-jwt-sample/test/features/support/init.js`. Then

```bash
$ ./node_modules/.bin/cucumberjs
```

Specify the feature file to run

```bash
$ ./node_modules/.bin/cucumberjs features/jws.feature
```

Specify the output format

```bash
$ ./node_modules/.bin/cucumberjs --format json
$ ./node_modules/.bin/cucumberjs --format summary
$ ./node_modules/.bin/cucumberjs --format progress
```

See [cucumber-js docs](https://github.com/cucumber/cucumber-js/blob/master/docs/cli.md) for more options.

