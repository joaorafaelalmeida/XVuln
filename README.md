# TrustVuln

A web application AppSec vulnerability check orchestrator. It was adapted from the tool [sarif-orchestrator](https://github.com/Barroqueiro/sarif-orchestrator).

## Using the orchestrator module

The orchestrator module invokes and creates the Docker containers to execute vulnerability checks for the provided code base.

Orchestrator variables customization is performed in ``"TrustVuln/docker/.env"``, the example file ``"TrustVuln/docker/.env.example"`` can be copied and used as a base.

```
# ORCHESTRATOR VARS ###########

ORCHESTRATOR_INPUT_HOST_DIR=/home/ubuntu/Desktop/TrustVuln/input    # Host input directory
ORCHESTRATOR_OUTPUT_HOST_DIR=/home/ubuntu/Desktop/TrustVuln/output  # Host output directory

CONFIG_HOST_DIR=/home/ubuntu/Desktop/TrustVuln/config   # Configuration directory

ORCHESTRATOR_CONFIG_FILE=php-config.toml    # Configuration file name

ORCHESTRATOR_MSG_LVL=DEBUG  # Orchestrator message printing minimum level (1-DEBUG/2-INFO/3-WARNING/4-ERROR)
```

The orchestrator module is invoked with ``./dc-up.sh orchestrator``.

## Getting started with DefectDojo

TrustVuln has an upload module prepared to upload report files to a DefectDojo instance. The following steps show how to quickly install and run DefectDojo.

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

The API key just needs to then be placed in the file ``"TrustVuln/docker/.env"``:

```
# UPLOAD VARS ###########

UPLOAD_INPUT_HOST_DIR=/home/ubuntu/Desktop/TrustVuln/output
UPLOAD_CONFIG_FILE=upload.toml
UPLOAD_AUTH_KEY=<OURTOKEN>
```

After having the correct API key placed, we can customize the upload configuration file ``"TrustVuln/config/upload.toml"`` to our needs before uploading report files, like changing the product or engagement name to where the discoveries will be uploaded:

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

Once again in the project environment file ``"TrustVuln/docker/.env"``, we can specify the location of the sarif files to transform, the formatted reports output location and the type of formatted reports:

```
# REPORT VARS ###########

REPORT_INPUT_HOST_DIR=/home/ubuntu/Desktop/TrustVuln/output/Reporting
REPORT_OUTPUT_HOST_DIR=/home/ubuntu/Desktop/TrustVuln/output/Reporting/Formatted
REPORT_TYPE=<FORMATTEDFILETYPE> # MD, HTML or PDF
```

Invoke the report module with ``./dc-up.sh report``.