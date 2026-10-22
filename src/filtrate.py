import os
import json
import hashlib

import src.utils as utils

# Vulnerability ignoring functions

def hash_vuln(vuln):
    """
    Produce a SHA-256 hash of a result object
    """
    return hashlib.sha256(str(vuln).encode("utf-8")).hexdigest()

def update_single_sarif(filename):
    """
    Update a SARIF file with the hashes for each vulnerability found, if an hash or id is found within the ignoring files they are discarded from the final results
    """

    # Get items to ignore
    if os.path.isfile(utils.CONFIG_DIR_DOCKER + "/" + utils.HASH_IGNORE_FILE):
        hashes = open(utils.CONFIG_DIR_DOCKER + "/" + utils.HASH_IGNORE_FILE).read().split("\n")
        hashes = [h for h in hashes if h != "" and h[0] != "#" ]
    else:
        hashes = []

    if os.path.isfile(utils.CONFIG_DIR_DOCKER + "/" + utils.ID_IGNORE_FILE):
        ids = open(utils.CONFIG_DIR_DOCKER + "/" + utils.ID_IGNORE_FILE).read().split("\n")
        ids = [i for i in ids if i != "" and i[0] != "#" ]
    else:
        ids = []

    utils.log_message(utils.msglvl.INFO, 'Filtrating file "{}"', filename)

    # Load information
    with open(filename,"r") as f:
        #data = json.loads(f.read())
        # NOTE: for some reason some output files seem to be empty
        try:
            data = json.loads(f.read())
        except:
            utils.log_message(utils.msglvl.ERROR, 'File "{}" has invalid contents', filename)
            return
    
    if "runs" not in data:
        utils.log_message(utils.msglvl.ERROR, 'File "{}" is not sarif formatted', filename)
        ###################################################
        # The ESLint tool, which is not producing reports in SARIF format, has some cases where the result
        # specifies a huge list of messages (1000+) should we simply force it so that the result does not
        # encompass more than one message per reported file?
        # If yes, after doing it, upload the filtered results to check the difference in the total of findings.
        # Nonetheless, by doing that, we might lose important information in the process ??? -> actually, after checking, a lot of reports are repeated
        path_history = set()

        for result in data:
            if result['filePath'] not in path_history:
                path_history.add(result['filePath'])
            else:
                print("Repeated!", flush=True)
            
            #print(result['errorCount'], flush=True)
            if result['errorCount'] > 1:
                result['errorCount'] = 1

            if len(result['messages']) > 1:
                result['messages'] = [result['messages'][0]]

        with open(filename, "w", encoding='utf-8') as f:
            json.dump(data, f, indent=4)

        ###################################################
        return

    runs = data["runs"]

    message_history = set()
    path_history = dict()
    hash_history = set()
    #total_rem = 0

    # Remove or update the vulnerability entries
    for r in runs:
        iterator = [x for x in r["results"]]
        results = r["results"]
        for res in iterator:

            # Remove results which only differ in the ruleId key value, meaning the remaining of the body is exactly the same
            res_body = res.copy()
            res_body.pop('ruleId')

            dhash = hashlib.md5()
            encoded = json.dumps(res_body, sort_keys=True).encode()
            dhash.update(encoded)
            hash_body = dhash.hexdigest()
            
            if hash_body not in hash_history:
                hash_history.add(hash_body)
            else:
                results.remove(res)
                #utils.log_message(utils.msglvl.DEBUG, 'Removed repeated hash body "{}"', hash_body)

            """
            # Remove results with a message equal to a previous registered result message
            if res['message']['text'] not in message_history:
                message_history.add(res['message']['text'])
            else:
                #print(f'Location of ruleId {res["ruleId"]} result already mentioned in previous result', flush=True)
                results.remove(res)
                #total_rem += 1
            # TODO: Save the newly filtrated versions on new files instead of replacing the original ones (?)

            # Remove results with a path equal to a previous registered result path and line (?)
            if res['locations'][0]['physicalLocation']['artifactLocation']['uri'] not in path_history:
                path_history[res['locations'][0]['physicalLocation']['artifactLocation']['uri']] = [res['locations'][0]['physicalLocation']['region']['startLine']]
            else:
                is_same_line = False
                for line_num in path_history[res['locations'][0]['physicalLocation']['artifactLocation']['uri']]:
                    if line_num == res['locations'][0]['physicalLocation']['region']['startLine']:
                        results.remove(res)
                        #total_rem += 1
                        is_same_line = True
                        break
                
                if not is_same_line:
                    path_history[res['locations'][0]['physicalLocation']['artifactLocation']['uri']].append(res['locations'][0]['physicalLocation']['region']['startLine'])
            """

            # Remove ids
            if res["ruleId"] in ids:
                results.remove(res)
                continue

            # Get hash if it exists else hash the vulnerability
            if "properties" in res and "hash" in res["properties"]:
                hash = res["properties"]["hash"]
            else:
                hash = hash_vuln(res)
                if "properties" in res:
                    res["properties"]["hash"] = hash
                else:
                    res["properties"] = {"hash": hash}

            # Remove hashes
            if hash in hashes:
                results.remove(res)

    #utils.log_message(utils.msglvl.DEBUG, 'Removed {} discoveries from file "{}"', total_rem, filename)

    # Store the information back
    data["runs"] = runs

    with open(filename, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def update_sarif_reports():
    """
    Walk through a directory and find all sarif files, update each with hashing information
    """
    for subdir, dirs, files in os.walk(utils.OUTPUT_DIR_DOCKER + "/" + utils.REPORT_DIR):
        for file in files:
            if ".sarif" in file:
                update_single_sarif(os.path.join(subdir, file))
