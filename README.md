
# MAFIA - Mobile Automated Framework for Intelligent Analisys.

Mobile applications are really critical when it comes to vulnerabilities in production environment. The only option to remove a product issue is to force update the app, which is not at all a good user experience specially when the app download size is high. With this project, we aim to automate the manual security testing and leverage developers with a tool which helps them identify bugs well in advance.

#### Goals
- Perform end to end Security testing for a given mobile app.
- Create a self serve tool for developers and security engineers.

#### How to use it:

- `https://github.com/Flipkart-Incubator/Mafia.git` or download the zip
- `pip install -r requirements.txt`
- `python run.py` -> http://server_ip:5000

##### Things to do before running:

- in **config.py**
    - update values for GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SECRET_KEY etc
- in **run.py** 
    - edit the port of the app (Default: 5000)
    

##### TROUBLESHOOTS :

- READ FIRST : About Python 2 and 3 compatibility

    Some scripts and modules versions required here are written in python 2 and not ready yet for python 3
    so it is recommended to download and install both interpreters python 2 and also python 3 (for windows users don't forget to add their folder paths also in your environment variables)
    Then when calling python scripts in version 2 or 3 anyway (example with the package manager script PIP)
    
    you can run default python command like :
    
    `"python -m pip install ..." or "pip install ..."`
    
    To call only python 3 scripts choose  this  instead :
    
    `"py -m pip install ..." or "pip3 install ..."`


- Error parsing in requirements.txt ?

    Run instead this compatible formatted file :
        `python -m pip install -r requirements-pip2.txt`   
    or convert first your requirements.txt to a python2 / pip2 compatible format with this command :
        `python -m pip list --format=freeze > requirements.txt`

#### Milestones

- Version 1.0
    1. Static Android Applications Testing (Apk files)
    - Vulnerability coverage
        1. Tapjacking
        - Manifest Analysis
        - SSL issues
        - SQL injection
        - Logging based vulnerabilities
        - Content Providers access permissions
        - Web View Security
        - Sensitive data on the shared storage
        - External Storage
        - Cryptographic based vulnerabilities
        - Exposing external JavaScript Interfaces in webviews
    1. Self Serve Portal for Developers

-  Version 1.1
    1. Comparision between scan results
    
- Version 1.2
    1. Dashboard for scan results
    - Report downloads in JSON and XML format
    - UI look-n-feel Enhancements

#### Screenshots
#### New scan

![Login Page](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Login%20Page.png)

![Home Page](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Home%20Page.png)

![New Scan](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/New%20Scan.png)

![Scan in Progress](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Scan%20in%20Progress.png)
#### Scan Report

![Report Page](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Report%20Page.png)

![Analysis Summary](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Analysis%20Summery.png)

#### Detailed Report

![Detailed Report](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Detailed%20Report.png)

#### Scans Dashboard
![Scans Dashboard](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Dash%20board.png)

#### Scan Comparison
![Scans Comparison](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Compare%20Scans.png)

![Scan Comparison](https://github.com/Flipkart-Incubator/Mafia/raw/docs/Docs/Scan%20Comparison.png)


#### Roadmap
- Version 2.0
    1. Dynamic Android Application Testing.
        - Test the api calls
        - Third-party Data Transit on Unencrypted Channel
        - Sensitive information sent as a querystring parameter
        - Cleartext password in Response
        - Other Api/ Server related security test cases.
    2. Static Analysis Improvements 
        - Look for Debug Logs
        - Check for file creations
        - Sensitive information in Application Log Files
        - Application is Accessible on Rooted Device
        - Unencrypted Credentials in Databases (sqlite db)
        - Store sensitive information outside App Sandbox (on SDCard)
        - Allow Global File Permission on App Data
        - Store Encryption Key Locally/Store Sensitive Data in ClearText
        - Bypass Certificate Pinning
        - App/Web Caches Sensitive Data Leak
        - Leaking Content Provider

- Version 3.0
    1. IOS App Testing

#### Core Softwares :
- Python 2.7

##### License: Apache 2.0
~~~~

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
~~~~
