# XVuln

An open-source orchestrator of vulnerability scanning tools.

## Using the orchestrator module

The orchestrator module invokes and creates the Docker containers to execute vulnerability checks for the provided code base.

Orchestrator variables customization is performed in ``"XVuln/docker/.env"``, the example file ``"XVuln/docker/.env.example"`` can be copied and used as a base.

```
# ORCHESTRATOR VARS ###########

ORCHESTRATOR_INPUT_HOST_DIR=/home/ubuntu/Desktop/XVuln/input    # Host input directory
ORCHESTRATOR_OUTPUT_HOST_DIR=/home/ubuntu/Desktop/XVuln/output  # Host output directory

CONFIG_HOST_DIR=/home/ubuntu/Desktop/XVuln/config   # Configuration directory

ORCHESTRATOR_CONFIG_FILE=stride.toml    # Configuration file name

ORCHESTRATOR_MSG_LVL=DEBUG  # Orchestrator message printing minimum level (1-DEBUG/2-INFO/3-WARNING/4-ERROR)
```

The orchestrator module is invoked with ``./dc-up.sh orchestrator``.

## Getting started with DefectDojo

XVuln has an upload module prepared to upload report files to a DefectDojo instance. The following steps show how to quickly install and run DefectDojo.

### Installing DefectDojo

```
git clone --recursive https://github.com/DefectDojo/django-DefectDojo.git
```

### Starting DefectDojo

```
cd django-DefectDojo
./dc-build.sh
./dc-up.sh # or ./dc-up.sh-d for detached mode
```

- By default, the application will be running on http://localhost:8080

### Getting the admin password

```
docker compose logs initializer | grep "Admin password:"
```

### Changing the admin password

```
docker exec -it django-defectdojo-uwsgi-1 ./manage.py changepassword admin
```

#### References

- https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md

## Using the upload module

With DefectDojo running and having access to an admin account, we need to grab an API key to allow the upload module to perform requests. By clicking on the profile arrow (top-right corner), we can head to "API v2 Key" to get the API key (or by the link http://localhost:8080/api/key-v2). 

Alternatively, we can use /api/v2/api-token-auth/ to get our token:

```
curl -X POST -H 'content-type: application/json' http://localhost:8080/api/v2/api-token-auth/ -d '{"username": "<YOURUSERNAME>", "password": "<YOURPASSWORD>"}'
```

The API key just needs to then be placed in the file ``"XVuln/docker/.env"``:

```
# UPLOAD VARS ###########

UPLOAD_INPUT_HOST_DIR=/home/ubuntu/Desktop/XVuln/output
UPLOAD_CONFIG_FILE=upload.toml
UPLOAD_AUTH_KEY=<OURTOKEN>
```

After having the correct API key placed, we can customize the upload configuration file ``"XVuln/config/upload.toml"`` to our needs before uploading report files, like changing the product or engagement name to where the discoveries will be uploaded:

```
active="false"
verified="false"
product_name="<PRODUCTNAME>"
engagement_name="<ENGAGEMENTNAME>"
url="http://localhost:8080"
file=""
dir="Reporting"
```

Finally, we can invoke the upload module with ``./dc-up.sh upload``.

## Using the report module

The report module is simply used to transform the created reports into more readable documents, with current options for Markdown, HTML and PDF files.

Once again in the project environment file ``"XVuln/docker/.env"``, we can specify the location of the sarif files to transform, the formatted reports output location and the type of formatted reports:

```
# REPORT VARS ###########

REPORT_INPUT_HOST_DIR=/home/ubuntu/Desktop/XVuln/output/Reporting
REPORT_OUTPUT_HOST_DIR=/home/ubuntu/Desktop/XVuln/output/Reporting/Formatted
REPORT_TYPE=<FORMATTEDFILETYPE> # MD, HTML or PDF
```

Invoke the report module with ``./dc-up.sh report``.

## LLM abuse case vulnerability matching component

The LLM abuse case vulnerability matching component in present in the folder ``"XVuln/vuln-matching"``, used to correlate scanner findings with categories from the STRIDE framework.

To run the LLM analysis, Ollama should be up and running, with the model ``llama3.1:8b`` being invoked by default. After placing the obtained scanner reports in the folder ``"XVuln/reports"``, ``filter_reports.py`` should be run to generate the filtered reports. Finally, ``run_analysis.sh`` is the file used to invoke the LLM to match each filtered report with one of the abuse cases present in ``abuse_cases.txt``. The resuling matches are placed in the folder ``"XVuln/stride_output"``.
