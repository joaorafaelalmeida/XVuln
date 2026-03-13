"""
Docker container orchestrator for SARIF reporting tools
"""
import toml
import argparse

import src.orchestrator as orchestrator
import src.filtrate as filtrate
import src.report as report
import src.upload as upload
import src.utils as utils

def parse():
    parser = argparse.ArgumentParser(description="Orchestrating sarif tools")
    subparsers = parser.add_subparsers(title="subcommands", help="Different commands", dest="command")
    orchestrator_parser = subparsers.add_parser("orchestrator", help="Orchestrate tools to produce sarif reporting")
    orchestrator_parser.add_argument('--input-dir-host', type=str, required=True,
                        help='Directory to be shared with docker for input')
    orchestrator_parser.add_argument('--output-dir-host', type=str, required=True,
                        help='Directory to be shared with the docker runs for output')
    orchestrator_parser.add_argument('--config-dir-host', type=str, required=True,
                        help='Directory to be shared with the docker runs for configuration')
    orchestrator_parser.add_argument('--config', type=str, required=True,
                        help='Current path')
    orchestrator_parser.add_argument('--message-level', type=str, required=True,
                        help='Message printing level')
    orchestrator_parser.add_argument('--keep-images', action='store_true',
                        help='Keep images after finishing') # This makes the key "--keep-images" act as a flag, more precisely a toggle (does not require value)

    filtrate_parser = subparsers.add_parser("filtrate", help="Filtrate report files entries")
    filtrate_parser.add_argument('--input-dir-host', type=str, required=True,
                        help='Directory to be shared with docker for input')
    filtrate_parser.add_argument('--output-dir-host', type=str, required=True,
                        help='Directory to be shared with the docker runs for output')
    filtrate_parser.add_argument('--config-dir-host', type=str, required=True,
                        help='Directory to be shared with the docker runs for configuration')
    filtrate_parser.add_argument('--config', type=str, required=True,
                        help='Current path')
    filtrate_parser.add_argument('--message-level', type=str, required=True,
                        help='Message printing level')

    report_parser = subparsers.add_parser("report", help="Produce Markdown reports from sarif files")
    report_parser.add_argument('--type', type=str, required=True,
                        help='Type of report to produce')
    report_parser.add_argument('--message-level', type=str, required=False,
                        help='Message printing level')

    upload_parser = subparsers.add_parser("upload", help="Upload results to DefectDojo")
    upload_parser.add_argument('--config', type=str, required=True,
                        help='Configuration file for upload')
    upload_parser.add_argument('--auth-key', type=str, required=True,
                        help='Auth key for DefectDojo uploading')
    upload_parser.add_argument('--message-level', type=str, required=False,
                        help='Message printing level')
    
    args = parser.parse_args()
    command_args = vars(args)

    return command_args


# Main
def main():
    command_args = parse()
    command = command_args["command"]

    if "message_level" in command_args:
        utils.set_message_level(command_args["message_level"])

    if command == "orchestrator":

        config = toml.loads(open(command_args["config"]).read())

        orchestrator.setup()
        
        runs = orchestrator.get_runs(config)
        utils.print_config(runs)

        to_clean = orchestrator.run_tasks(runs, command_args["input_dir_host"], command_args["output_dir_host"], command_args["config_dir_host"])

        orchestrator.finish(to_clean, command_args["keep_images"])

    if command == 'filtrate':

        filtrate.update_sarif_reports()
    
    if command == "report":

        report.produce_sarif_reports(command_args["type"])

    if command == "upload":

        config = toml.loads(open(command_args["config"]).read())
        auth_key = command_args["auth_key"]
        utils.print_config(config)

        if not upload.create_dojo_engagement(config, auth_key):
            return

        if config["file"]:
            upload.upload_file(config, auth_key, "{input_dir}/{file}".format(input_dir=utils.INPUT_DIR_DOCKER,file=config["file"]))
        else:
            upload.upload_dir(config, auth_key)

if __name__ == "__main__":
    main()
