# Goprobber

A minimal tool for probing domains as fast as possible.

## Getting Started


### Prerequisites

The things you need before installing the software.

* go1.19+
* Preferably Linux, but Windows works too, just not as fast.

### Installation

```
$ go install -v github.com/its5Q/goprobber@latest
```

## Usage

```
usage: goprobber <resolvers path> <massdns ndjson output> <thread count>
``` 
Where 
* `<resolvers path>` - path to a list of DNS resolvers that would be used in case of redirects,   
* `<massdns ndjson output>` - path to the output file of [MassDNS](https://github.com/blechschmidt/massdns) in ndjson format, the resolved records from this file will be used to skip unnecessary DNS requests, increasing processing speed,
* `<thread count>` - the number of threads to use.


## Acknowledgments

* https://github.com/projectdiscovery/httpx for the `InsertInto` function used in favicon hash calculation
