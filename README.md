# Sonar Reporter 
this Python tool performs an API call to your SonarQube instance and generates PDF report from the project specified using project key

## Installation 
* install Python 3
* install virtualenv
  ```
  pip install virtualenv
  ```
* create a virtualenv
  ```
  virtualenv ./venv
  ```
* switch to it by sourcing the activate file:
  ```
  . ./venv/bin/activate (Linux)
  venv\Scripts\activate.bat` (Windows)
* install the dependencies:
  ```
  (venv) pip install -r requirements.txt
  ```

## Execution
execute in virtualenv (see above)
* execution for a project:
  ```
  (venv) python sonar_reporter.py <url> <username> <password> <project_key>
  ```
  
  Get the project_key from SonarQube by clicking on existing project name and look for "Project Key" field at the bottom right part of the screen
* after execution a report named "sonarqube_report_project_name_date.pdf" will be created 
