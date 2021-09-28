import requests
from requests import Request, Session, auth
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape
from utils import logging,get_logger

from config import app_config

logger = get_logger(__name__, logging.INFO, app_config['log_dir'])

session = Session()
session.auth = auth.HTTPBasicAuth(app_config['qualys_username'], app_config['qualys_password'])
base_url = app_config['qualys_api_base']

# dict of name:id to cache qualys tag_name:tag_id
iotvas_tags = {}

def get_tag_id(tag_name):
    try:
        body = '''<?xml version="1.0" encoding="UTF-8" ?>
                <ServiceRequest>
                    <filters>
                        <Criteria field="name" operator="EQUALS">{0}</Criteria>
                    </filters>
                </ServiceRequest>'''.format(escape(tag_name))
        res = session.post(base_url + '/qps/rest/2.0/search/am/tag', data=body)
        dom = ET.fromstring(res.content)
        tag_count = int(dom.find('count').text)
        if tag_count == 1:
            tag = dom.find('data/Tag')
            if tag:
                return tag.find('id').text
    except requests.exceptions.RequestException:
        logger.error("Error while searching for tag name {0}".format(tag_name), exc_info=True)

def create_tag(tag_name):
    try:
        body = '''<?xml version="1.0" encoding="UTF-8" ?>
                <ServiceRequest>
                    <data>
                        <Tag>
                            <TagSimple><name>{0}</name>
                            </TagSimple>
                        </Tag>
                    </data>
                </ServiceRequest>'''.format(escape(tag_name))
        res = session.post(base_url + '/qps/rest/2.0/create/am/tag', data=body)
        dom = ET.fromstring(res.content)
        data = dom.find('data')
        if data:
            tag = data.find('Tag')
            if tag:
                return tag.find('id').text
    except requests.exceptions.RequestException:
        logger.error("Error while creating tag name {0}".format(tag_name), exc_info=True)


# id of the parent tag containg all iotvas tags
parent_tag_name = app_config['qualys_parent_tag_name']
parent_tag_id = get_tag_id(parent_tag_name)
if not parent_tag_id:
    parent_tag_id = create_tag(parent_tag_name)
if not parent_tag_id:
    raise ValueError('Failed to create IoTVAS parent tag', parent_tag_name)
logger.info("IoTVAS parent tag id is {0}".format(parent_tag_id))


def tag_asset(asset_id, tag_id, tag_name):
    try:
        body = '''<?xml version="1.0" encoding="UTF-8" ?>
                    <ServiceRequest>
                        <data>
                            <HostAsset>
                                <tags>
                                    <add>
                                        <TagSimple><id>{0}</id></TagSimple>
                                    </add>
                                </tags>
                            </HostAsset>
                        </data>
                    </ServiceRequest>'''.format(tag_id)
        res = session.post(base_url + '/qps/rest/2.0/update/am/hostasset/' + asset_id, data = body)
        logger.info("Added tag {0} to asset id {1}".format(tag_name, asset_id))
    except requests.exceptions.RequestException:
        logger.error("Error while adding tag name {0} to asset id {1}".format(tag_name, asset_id), exc_info=True)


def create_iotvas_tag(tag_name):
    # first create the child tag
    child_id = create_tag(tag_name)
    if not child_id:
        logger.error("Error creating child tag name {0}".format(tag_name))
        return
    # put it under the parent tag
    try:
        body = '''<?xml version="1.0" encoding="UTF-8" ?>
                    <ServiceRequest>
                    <data>
                        <Tag>
                            <children>
                                <add>
                                    <TagSimple><id>{0}</id></TagSimple>
                                </add>
                            </children>
                        </Tag>
                    </data>
                    </ServiceRequest>'''.format(child_id)
        session.post(base_url + '/qps/rest/2.0/update/am/tag/' + parent_tag_id, data=body)
        return child_id
    except requests.exceptions.RequestException:
        logger.error("Error while creating iotvas tag name {0}".format(tag_name), exc_info=True)


def get_iotvas_tag(tag_name):
    if tag_name in iotvas_tags:
        return iotvas_tags[tag_name]
    # otherwise get from qualys
    tag_id = get_tag_id(tag_name)
    if tag_id:
        # cache this id
        iotvas_tags[tag_name] = tag_id
    return tag_id

def remove_asset_tag(asset_id, tag_id):
    try:
        body = '''<?xml version="1.0" encoding="UTF-8" ?>
                    <ServiceRequest>
                    <data>
                        <HostAsset>
                            <tags>
                                <remove>
                                <TagSimple><id>{0}</id></TagSimple>
                                </remove>
                            </tags>
                        </HostAsset>
                    </data>
                </ServiceRequest>'''.format(tag_id)
        session.post(base_url + '/qps/rest/2.0/update/am/hostasset/' + asset_id, data=body)
    except requests.exceptions.RequestException:
        logger.error("Failed to remove tag id {0} for asset id {1}".format(tag_id, asset_id), exc_info=True)


def find_asset(ip):
    try:
        asset_id = None
        tags = None
        body = '''<?xml version="1.0" encoding="UTF-8" ?>
                <ServiceRequest>
                     <filters>
                        <Criteria field="address" operator="EQUALS">{0}</Criteria>
                    </filters>
                </ServicdeRequest>'''.format(ip)
        res = session.post(base_url + '/qps/rest/2.0/search/am/hostasset',data=body)
        dom = ET.fromstring(res.content)
        data = dom.find('data')
        if data:
            host_asset = data.find('HostAsset')
            if host_asset:
                asset_id = host_asset.find('id').text
                tags = {}
                tags_list = host_asset.find('tags/list')
                if tags_list:
                    for tag in tags_list:
                        tag_name = tag.find('name').text
                        tag_id = tag.find('id').text
                        tags[tag_name] = tag_id
    except requests.exceptions.RequestException:
        logger.error("Errror while searching asset with ip {0}".format(asset_id), exc_info=True)
    return (asset_id, tags)

def add_iotvas_tags(ip, tags):
    asset_id, curr_tags  = find_asset(ip)
    if not asset_id:
        logger.warning("No qualys asset was found for discovered host {0}".format(ip))
        return
    for tag_name in tags:
        if tag_name in curr_tags:
            continue
        new_prefix = tag_name.split(':')[0]
        for key in curr_tags:
            curr_prefix = key.split(':')[0]
            if new_prefix == curr_prefix:
                logger.info("Updating tag {0} on {1}".format(key, ip))
                remove_asset_tag(asset_id, curr_tags[key])
                break
        tag_id = get_iotvas_tag(tag_name)
        if not tag_id:
            tag_id = create_iotvas_tag(tag_name)
        if tag_id:
            tag_asset(asset_id, tag_id, tag_name)
        else:
            logger.warning("Failed to add tags for ip: {0}".format(ip))