"""
Upload module to integrate the automatic upload of sarif files to DefectDojo
"""

import os
import requests

from datetime import datetime, timedelta

# Local modules
import src.utils as utils

# Upload Functions

def upload_file(config, auth_key, file):
    """
    Upload a specific SARIF file to an engagement of a product in DefectDojo 
    """

    params = {k:v for k,v in config.items() if k not in ["url","file","dir","auth"]}
    params["scan_type"] = "SARIF"

    headers = {'Authorization': 'Token {}'.format(auth_key)}

    with open(file) as f:
        #r = requests.post("{url}/api/v2/import-scan/".format(url=config["url"]), files={'file': f}, data=params, headers=headers)
        try:
            r = requests.post("{url}/api/v2/import-scan/".format(url=config["url"]), files={'file': f}, data=params, headers=headers)
            utils.log_message(utils.msglvl.INFO, '"{}" upload concluded with code {}{}', file.split('/')[-1], r.status_code, f', {r.json()["message"]}' if 'message' in r.json() else f', {r.json()["statistics"]["after"]["total"]["total"]} total discoveries')
        except Exception as e:
            utils.log_message(utils.msglvl.ERROR, 'Could not upload file "{}", {}', file.split('/')[-1], repr(e))

    #print("Upload comcluded with code: ",r.status_code)

def upload_dir(config, auth_key):
    """
    Upload all SARIF files inside a directory to DefectDojo making use of the upload_file function
    """

    directory = config["dir"]
    for subdir, dirs, files in os.walk(f"{utils.INPUT_DIR_DOCKER}/{directory}"):
        for file in files:
            ext = os.path.splitext(file)[-1].lower()
            if ".sarif" in file:
                upload_file(config, auth_key, os.path.join(subdir, file))

def create_dojo_product(config, auth_key):
    """
    Create a DefectDojo product for further engagements additions
    """

    headers = {'Authorization': 'Token {}'.format(auth_key)}

    product_exists = False
    product_id = -1

    # Verify if the desired product already exists in DefectDojo
    try:
        r = requests.get("{url}/api/v2/products/".format(url=config["url"]), data=None, headers=headers)
        if r.status_code == 200:
            for result in r.json()['results']:
                if result['name'] == config['product_name']:
                    product_exists = True
                    product_id = result['id']
                    utils.log_message(utils.msglvl.DEBUG, 'Found product "{}" in DefectDojo', config['product_name'])
        utils.log_message(utils.msglvl.INFO, 'Get products concluded with code {}, {} total products', r.status_code, r.json()['count'])
    except Exception as e:
        utils.log_message(utils.msglvl.ERROR, 'Could not get DefectDojo products, {}', repr(e))

    # In case the product does not exist, create it
    if not product_exists:
        params = dict()

        # Fill basic mandatory post request parameters
        params['prod_type'] = 1 # NOTE: Right now corresponds to "Research and Development", which is the default type present in DefectDojo, might need customization
        params['name'] = config['product_name']
        params['description'] = f'{config["product_name"]} sample description'

        try:
            r = requests.post("{url}/api/v2/products/".format(url=config['url']), data=params, headers=headers)
            product_id = r.json()['id']
            utils.log_message(utils.msglvl.INFO, 'Post product "{}" concluded with code {}, product id {}', config['product_name'], r.status_code, r.json()['id'])
        except Exception as e:
            utils.log_message(utils.msglvl.ERROR, 'Could not post DefectDojo product, {}', repr(e))

    return product_id


def create_dojo_engagement(config, auth_key):
    """
    Create a DefectDojo engagement for further report additions
    """

    headers = {'Authorization': 'Token {}'.format(auth_key)}

    engagement_exists = False
    product_id = create_dojo_product(config, auth_key)
    if product_id == -1:
        return False

    # Verify if the desired engagement already exists in DefectDojo
    try:
        r = requests.get("{url}/api/v2/engagements/".format(url=config['url']), data=None, headers=headers)
        if r.status_code == 200:
            for result in r.json()['results']:
                if result['name'] == config['engagement_name']:
                    engagement_exists = True
                    utils.log_message(utils.msglvl.DEBUG, 'Found engagement "{}" in DefectDojo', config['engagement_name'])
        utils.log_message(utils.msglvl.INFO, 'Get engagements concluded with code {}, {} total engagements', r.status_code, r.json()['count'])
    except Exception as e:
        utils.log_message(utils.msglvl.ERROR, 'Could not get DefectDojo engagements, {}', repr(e))

    # In case the engagement does not exist, create it
    if not engagement_exists:
        params = dict()

        # Fill basic mandatory post request parameters
        params['product'] = product_id
        params['target_start'] = datetime.today().strftime('%Y-%m-%d')
        params['target_end'] = (datetime.today() + timedelta(days=7)).strftime('%Y-%m-%d') # NOTE: 7 days delta time, might need customization
        params['name'] = config['engagement_name']
        #params['description'] = f'{config['engagement_name']} sample description'

        try:
            r = requests.post("{url}/api/v2/engagements/".format(url=config['url']), data=params, headers=headers)
            utils.log_message(utils.msglvl.INFO, 'Post engagement "{}" concluded with code {}, engagement id {}', config['engagement_name'], r.status_code, r.json()['id'])
        except Exception as e:
            utils.log_message(utils.msglvl.ERROR, 'Could not post DefectDojo engagement, {}', repr(e))

    return True
