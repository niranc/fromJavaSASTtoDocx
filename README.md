# fromJavaSASTtoDocx
## Audit compile java code + source code & generate your report

<p>fromJavaSASTtoDocx.py does a static analyse of compiled java file and source code (dependencycheck & findsedbugs modules) and write a report.</p>

<p>Dependencycheck looks for CVEs in introduced packages.</p>
<p>FindSecBugs looks for security issues inside source code.</p>

<p>Please fill free to change the template word inside ./template/template_word.doc</p>

<p>Works only on windows.</p>

## Features

- Static analyze 
- Export elements as DOCx

## Install
```sh
pip install -r requirements.txt
```

## Usage
```sh
python .\fromJavaSASTtoDocx.py -h
Dependency check & FindSec bugs parser 1.0.0 - From [Jar/war] & [src code] to Docx
                                                                                  
 Fill ./apps/ repository with :                                                   
        - Binary files (war,jar,zip,ear, ...) inside ./apps/<package_name>/bin/  
            /!\ unzip .dar files beforce launching
        - Source code inside ./apps/<package_name>/src/>                          

usage: fromJavaSASTtoDocx.py [-h] [--no-dep-check NO_DEP_CHECK] [--no-findsecbugs NO_FINDSECBUGS] [--export-docx EXPORT_DOCX] [-v]
                                                                                                                                  
A python script to do your report.                                                                                                
                                                                                                                                  
optional arguments:                                                                                                               
  -h, --help            show this help message and exit                                                                           

Dependency Checker plugin:
  --no-dep-check NO_DEP_CHECK
                        Disable Dependency Check plugin. [Default : False]

Find Sec Bugs plugin:
  --no-findsecbugs NO_FINDSECBUGS
                        Disable FindSecBugs plugin. [Default : False]

Export:
  --export-docx EXPORT_DOCX
                        Output DOCX file to store the results in.

Configuration:
  -v, --verbose         Verbosity level (-v for verbose, -vv for advanced, -vvv for debug)
```

## TODO oneday
- Fix FindSecBugs module bugs
- Add dynamic analysis :proxy behaviour (zap/burp), nuclei templates output (markdown)
