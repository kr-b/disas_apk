# disas-apk
All-in-one tool for automating Android app reverse engineering
| Function | Complete |
|--|--|
| Decompile APK and output java source files | ✓ |
| Extract URLs and endpoints | ✓ |
| Extract possible hardcoded passwords | ✓ (sorta) |
| Extract possible API keys | ✓ |
| Check if JavaScript is enabled on webviews | ⏳ |
| Find outdated frameworks in use | ⏳ |

## Get Started
### Requirements
- Python 3.7 +
- Linux (Windows support in progress)
### Installation
```
$ git clone https://github.com/kr-b/disas-apk.git
$ cd disas-apk
$ pip install -r requirements.txt
```
### CLI Example
```
$ python disas-apk.py example.apk
```
Output is saved in `cwd` in a folder called `disas-output`
### Module Example
```
from disas_apk import disas_apk

results = disas_apk.disas_apk("./com.example.apk")
```