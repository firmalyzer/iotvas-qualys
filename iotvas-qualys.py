import sys
import argparse

from nmap_probe import probe_targets
from iotvas.apis import DeviceApi, FirmwareApi
from qualys_am import add_iotvas_tags
from iotvas_tags import gen_device_tag_names, gen_firmware_tag_names, gen_uname_tags, gen_crypto_key_tags, \
gen_weak_key_tags, gen_weak_certalg_tags
from utils import logging, get_logger, get_iotvas_client

iotvas_client = get_iotvas_client()
device_api = DeviceApi(iotvas_client)
firmware_api = FirmwareApi(iotvas_client)

from utils import logging,get_logger
from config import app_config
logger = get_logger(__name__, logging.INFO, app_config['log_dir'])


def get_firmware_risk(sha2):
    try:
        risk = firmware_api.get_risk(sha2)
        return risk
    except iotvas.rest.ApiException:
        logger.error("failed to fetch firmware risk for {0}".format(sha2), exc_info=True)


def parse_features_table(tbl):
    features = {
        "snmp_sysdescr": "",
        "snmp_sysoid": "",
        "ftp_banner": "",
        "telnet_banner": "",
        "hostname": "",
        "http_response": "",
        "https_response": "",
        "upnp_response": "",
        "nic_mac": ""
    }
    for elem in tbl.findall('elem'):
        key = elem.get('key')
        if key in features.keys() and elem.text:
            features[key] = elem.text
    return features


def parse_hosts_features(dom):
    for host in dom.findall("host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            if not ip:
                continue
        for hostscript in host.findall("hostscript"):
            for script in hostscript.findall("script"):
                _id = script.get("id")
                if _id == "iotvas-features":
                    tbl = script.find("table")
                    features = parse_features_table(tbl)
                    device_info = device_api.detect_device(features)
                    if not (device_info.manufacturer and device_info.model_name):
                        logger.info("device maker and model not found for {0}".format(ip))
                        continue
                    tag_names = gen_device_tag_names(device_info)
                    add_iotvas_tags(ip, tag_names)
                    firmware_info = device_info.firmware_info
                    is_latest_fw = False
                    if not firmware_info:
                        firmware_info = device_info.latest_firmware_info
                        is_latest_fw = True
                    if firmware_info:
                        sha2 = firmware_info['sha2']
                        tag_names = gen_firmware_tag_names(sha2, is_latest_fw)
                        add_iotvas_tags(ip, tag_names)
                        tag_users = gen_uname_tags(sha2, is_latest_fw)
                        add_iotvas_tags(ip, tag_users)
                        tag_pkeys = gen_crypto_key_tags(sha2, is_latest_fw)
                        add_iotvas_tags(ip, tag_pkeys)
                        tag_wkeys = gen_weak_key_tags(sha2, is_latest_fw)
                        add_iotvas_tags(ip, tag_wkeys)
                        tag_wcerts = gen_weak_certalg_tags(sha2, is_latest_fw)
                        add_iotvas_tags(ip, tag_wcerts)


def get_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--targets-file", action="store", dest="targets_file", \
        help="path to the target list file", metavar="TARGETS_LIST_FILE")
    parser.add_argument("-e", "--exclude-targets", action="store", dest="excludes", \
        help="path to the nmap excluded targets file", metavar="NMAP_EXCLUDES_FILE")

    return parser


def main(argv):
    parser = get_argparser()
    if len(argv) ==  1:
        parser.print_help(sys.stderr)
        exit(1)
    args = parser.parse_args()
    nmap_cmd = "-sSU -p U:161,T:- --top-ports 1000 --script iotvas-features.nse"
    if args.targets_file:
        targets = []
        with open(args.targets_file, "r") as fp:
            line = fp.readline()
            while line:
                targets.append(line.strip().rstrip('\n'))
                line = fp.readline()
        if args.excludes:
            nmap_cmd = nmap_cmd + " --excludefile " + args.excludes

        dom = probe_targets(targets, nmap_cmd)
        if dom:
            parse_hosts_features(dom)

if __name__ == "__main__":
  main(sys.argv)

