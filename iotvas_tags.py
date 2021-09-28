from datetime import datetime
from utils import get_iotvas_client
import iotvas
from iotvas.apis import DeviceApi, FirmwareApi

iotvas_client = get_iotvas_client()
device_api = DeviceApi(iotvas_client)
firmware_api = FirmwareApi(iotvas_client)

from utils import logging,get_logger
from config import app_config
logger = get_logger(__name__, logging.INFO, app_config['log_dir'])


def gen_device_tag_names(info):
    tags = []
    tags.append("Vendor: " + info.manufacturer)
    tags.append("Model: " + info.model_name)
    if info.firmware_version:
        tags.append("FW_Version: " + info.firmware_version)
    if info.latest_firmware_info and info.latest_firmware_info['version']:
        tags.append("LFW_Version: " + info.latest_firmware_info['version'])
    if info.is_discontinued:
        tags.append("Discontinued")
    if info.device_type:
        tags.append("Type: " + info.device_type)
    if info.firmware_info and info.latest_firmware_info and \
        info.firmware_info['release_date'] and info.latest_firmware_info['release_date']:
            try:
                fw_rel_date  = datetime.strptime(info.firmware_info['release_date'], "%Y-%m-%d")
                latest_fw_rel_date  = datetime.strptime(info.latest_firmware_info['release_date'], "%Y-%m-%d")
                if fw_rel_date < latest_fw_rel_date:
                    tags.append("Outdated_FW")
            except ValueError as e:
                logger.warning(e, exc_info=True)
                pass

    for cve in info.cve_list:
        tags.append(cve.cve_id)

    return tags

def gen_uname_tags(sha2, is_latest):
    prefix = "FW_Acct: "
    if is_latest:
        prefix = "L" + prefix
    try:
        usernames = []
        accounts = firmware_api.get_accounts(sha2)
        for account in accounts:
            if account.pwd_hash and account.pwd_hash != '*':
                usernames.append(prefix + account.name)
        return usernames
    except iotvas.rest.ApiException:
        logger.error("failed to fetch default accounts for {0}".format(sha2), exc_info=True)

def gen_crypto_key_tags(sha2, is_latest):
    prefix = "FW_Pkey: "
    if is_latest:
        prefix = "L" + prefix
    try:
        keys = []
        pkeys = firmware_api.get_private_keys(sha2)
        for key in pkeys:
            if key.algorithm and key.bits:
                keys.append("{0} {1}/{2}".format(prefix, key.algorithm, key.bits))
        return keys
    except iotvas.rest.ApiException:
        logger.error("failed to fetch private keys for {0}".format(sha2), exc_info=True)

def gen_weak_key_tags(sha2, is_latest):
    prefix = "FW_WKey: "
    if is_latest:
        prefix = "L" + prefix
    try:
        keys = []
        pkeys = firmware_api.get_weak_keys(sha2)
        for key in pkeys:
            if key.algorithm and key.bits:
                keys.append("{0} {1}/{2}".format(prefix, key.algorithm, key.bits))
        return keys
    except iotvas.rest.ApiException:
        logger.error("failed to fetch weak keys for {0}".format(sha2), exc_info=True)

 
def gen_weak_certalg_tags(sha2, is_latest):
    prefix = "FW_WCert: "
    if is_latest:
        prefix = "L" + prefix
    algs = []
    try:
        certs = firmware_api.get_weak_certs(sha2)
        for cert in certs:
            if cert.sign_algorithm:
                algs.append(prefix + cert.sign_algorithm)
        return algs
    except iotvas.rest.ApiException:
        logger.error("failed to fetch weak certs for {0}".format(sha2), exc_info=True)


def gen_firmware_tag_names(sha2, is_latest):
    tags = []
    prefix = "FW_"
    if is_latest:
        prefix = "L" + prefix
    try:
        risk = firmware_api.get_risk(sha2)
        summary = risk.risk_summary
        for key in summary:
            if summary[key] != 'None':
                tags.append(prefix + key + ": " + summary[key])

        prefix = "FW"
        if is_latest:
            prefix = "L" + prefix
        for compo in risk.vulnerable_components:
            for vuln in compo.vulnerabilities:
                tags.append(prefix + ": " + vuln.cve_id)

    except iotvas.rest.ApiException:
        logger.error("failed to fetch firmware risk for {0}".format(sha2), exc_info=True)

    return tags