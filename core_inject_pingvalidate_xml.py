'''
@author: Jaime Acosta
@date: 2025-07-07
@description:
This script processes an XML file to add a UserDefined service to each device.
It also generates a bash script for each device that pings all other devices in the network.
'''

import lxml.etree as ET
import logging

def add_service_to_userdefined(xml_file, nodeip_map, output_file):
    logging.info("Starting to process XML file: %s", xml_file)
    # Parse the XML
    parser = ET.XMLParser(strip_cdata=False)
    tree = ET.parse(xml_file, parser=parser)
    root = tree.getroot()

    # Find all <device> tags
    logging.debug("Finding all <device> tags in the XML.")
    devices = root.findall(".//device")

    for device in devices:
        logging.debug("Processing device: %s", device)
        device_id = device.get("id")
        if not device_id:
            logging.debug("Found <device> without 'id' attribute. Skipping.")
            continue

        logging.debug(f"Processing device with id: {device_id}")
        #get the service and check if the UserDefined tag exists
        services = device.findall(".//service")
        if services != None:
            contains_userdefined = False
            logging.debug(f"Checking for <UserDefined> tag in services for device id: {device_id}")
            for service in services:
                if 'name' in service.attrib and service.attrib['name'] == "UserDefined":
                    contains_userdefined = True
                    break
            if contains_userdefined == False:
                logging.debug(f"No <UserDefined> tag found for device id {device_id}. Adding it.")
                services.append(ET.Element("UserDefined", id=device_id))

        # Find <UserDefined> tag with matching id
        logging.debug(f"Finding <service_configurations> for device id: {device_id}")
        service_configurations = root.find(f".//service_configurations")
        if service_configurations is None:
            logging.debug("No <service_configuration> found in the XML. Skipping device.")
            continue
        userdefined = service_configurations.find(f".//service[@name='UserDefined'][@node='{device_id}']")
        if userdefined is not None:
            logging.debug(f"Found matching <UserDefined> for device id {device_id}")

            # Create a new <startup> tag
            startups = userdefined.find(f".//startups")
            if startups is None:
                logging.debug(f"No <startups> found in <UserDefined> for device id {device_id}. Creating it.")
                startups = ET.SubElement(userdefined, "startups")
            else:
                logging.debug(f"Found <startups> in <UserDefined> for device id {device_id}")
            #create the startup command to run the pings
            logging.debug(f"Creating startup command for device id {device_id}")
            pcmd = ET.Element("startup")
            pcmd.text = f"/bin/bash pings_{device_id}.sh"
            startups.append(pcmd)

            # Create a new <file> tag
            logging.debug(f"Creating <files> section for device id {device_id}")
            files = userdefined.find(f".//files")
            if files is None:
                logging.debug(f"No <files> found in <UserDefined> for device id {device_id}. Creating it.")
                files = ET.SubElement(userdefined, "files")
            else:
                logging.debug(f"Found <files> in <UserDefined> for device id {device_id}")
            file = ET.Element("file")
            filetext = f"#!/bin/bash\n"
            logging.debug(f"Creating ping commands for device id {device_id}")
            for mapping in nodeip_map:
                if mapping == device_id:
                    continue
                #create the file that has pings to all other nodes
                for ipv4 in nodeip_map[mapping]:
                    logging.debug(f"Adding ping command for {mapping} with IPv4 {ipv4}")
                    filetext += f"ping {ipv4} -c 60 | grep ' bytes from ' | wc -l >> /tmp/{device_id}_to_{mapping}___{ipv4}.txt &"
                    filetext += "\n"
            file.attrib['name'] = f"pings_{device_id}.sh"
            file.text = ET.CDATA(filetext)
            files.append(file)
        else:
            logging.debug(f"No matching <UserDefined> found for device id {device_id}")

    # Write updated XML to output file
    logging.info("Writing updated XML to output file: %s", output_file)
    tree.write(output_file, encoding="utf-8", xml_declaration=True, pretty_print=True)
    logging.info(f"Updated XML written to {output_file}")

def get_nodes_ipv4(xml_file):
    logging.info("Starting to extract IPv4 addresses from XML file: %s", xml_file)
    # Parse the XML
    parser = ET.XMLParser(strip_cdata=False)
    tree = ET.parse(xml_file, parser=parser)
    root = tree.getroot()
    nodeip_map = {}
    # Find all <device> tags
    logging.debug("Finding all <links> tags in the XML.")
    links = root.findall(".//links/link")

    for link in links:
        logging.debug(f"Processing link: {link}")
        nodeipv4 = None
        if "node1" in link.attrib:
            nodeid = link.get("node1")
            iface1 = link.find(".//iface1")
            if iface1 != None:
                if 'ip4' in iface1.attrib:
                    logging.debug(f"Node {nodeid} has IPv4 address: {iface1.attrib['ip4']}")
                    nodeipv4 = iface1.attrib['ip4']
                    if nodeid not in nodeip_map:
                        nodeip_map[nodeid] = set()
                    nodeip_map[nodeid].add(nodeipv4)
        if "node2" in link.attrib:
            nodeid = link.get("node2")
            iface2 = link.find(".//iface2")
            if iface2 != None:
                if 'ip4' in iface2.attrib:
                    logging.debug(f"Node {nodeid} has IPv4 address: {iface2.attrib['ip4']}")
                    nodeipv4 = iface2.attrib['ip4']
                    if nodeid not in nodeip_map:
                        nodeip_map[nodeid] = set()
                    nodeip_map[nodeid].add(nodeipv4)
    return nodeip_map

if __name__ == "__main__":
    logger = logging.getLogger()
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    input_xml = "sample.xml"    # Path to input XML file
    output_xml = "output.xml"  # Path to output XML file
    nodeip_map = get_nodes_ipv4(input_xml)
    add_service_to_userdefined(input_xml, nodeip_map, output_xml)
