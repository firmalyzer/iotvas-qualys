from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from config import app_config
from utils import logging, get_logger
import xml.etree.ElementTree as ET

logger = get_logger(__name__, logging.INFO, app_config['log_dir'])


def parse_nmap_xml(xml):
    dom = ET.fromstring(xml)
    return dom
    
def nmap_callback(nmap_proc):
    nmaptask = nmap_proc.current_task
    if nmaptask:
        logger.info("Task {0} ({1}): ETC: {2} DONE: {3}%".format(\
            nmaptask.name, nmaptask.status, nmaptask.etc, nmaptask.progress))

def probe_targets(targets, options):
    nm = NmapProcess(targets, options, event_callback=nmap_callback)
    logger.info("Starting nmap scan: {0}".format(nm.command))
    rc = nm.run()
    if rc != 0:
        logger.error("Nmap failed to start: {0}".format(nm.stderr))
    else:
        logger.info("Nmap scan completed")
        xml = nm.stdout
        return parse_nmap_xml(xml)