# VTA

[![PyPI](https://img.shields.io/pypi/v/vta?color=orange)](https://pypi.python.org/pypi/vta/) [![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?color=blue)](http://choosealicense.com/licenses/mit/) [![image](https://img.shields.io/pypi/pyversions/vta.svg?color=brightgreen)](https://pypi.org/project/vta/)



VTA(VirusTotal API) is a provides module for VirusTotal API.



## Installation

**Python >= 3.x is required**

To install the package, you can just run the following command:

```sh
pip install vta
```



 To install the development version, do the following: 

```sh
$ git clone https://github.com/woodonggyu/vta.git
$ cd vta
$ python setup.py install
```



## Usage

The VirusTotal is available at  https://developers.virustotal.com/reference.

Using the *VTA*, You can use API for the above.

```python
import vta

vt = vta.VTA(
    'apikey'=''
)
vt.function(args)
```



### Contact

If you have any question, contact via email.

