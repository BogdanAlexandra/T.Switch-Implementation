#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def is_unicast(dst):
   return dst.lower() != 'ff:ff:ff:ff:ff:ff'

def is_bdpu_multicast(dst):
   return dst.lower() == '01:80:c2:00:00:00'

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id


def create_bpdu(root_bridge_ID, root_path_cost, sender_bridge_ID, port_ID):
    sw_mac = get_switch_mac()
    BPDU_MULTICAST = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])
    
    bpdu = add_mac_addresses(BPDU_MULTICAST, sw_mac)
    bpdu += add_llc_length()
    bpdu += add_llc_header()
    bpdu += add_protocol_identifiers()
    bpdu += add_bpdu_config(root_bridge_ID, root_path_cost, sender_bridge_ID, port_ID)
    bpdu += add_final_params()

    return bpdu

def add_mac_addresses(destination, source):
    return struct.pack('!6s', destination) + struct.pack('!6s', source)

def add_llc_length():
    LLC_LEN = bytes([0x00, 0x26])
    return struct.pack('!2s', LLC_LEN)

def add_llc_header():
    LLC_HEADER = bytes([0x42, 0x42, 0x03])
    return struct.pack('!3s', LLC_HEADER)

def add_protocol_identifiers():
    PROTO_IDENTIFIERS = bytes([0x00, 0x00, 0x00, 0x00, 0x00])
    return struct.pack('!5s', PROTO_IDENTIFIERS)

def add_bpdu_config(root_bridge_ID, root_path_cost, sender_bridge_ID, port_ID):
    return struct.pack('!QIQH', root_bridge_ID, root_path_cost, sender_bridge_ID, port_ID)

def add_final_params():
    FINAL_PARAMS = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return struct.pack('!8s', FINAL_PARAMS)

def build_vlan(data, vlan_id):
    return data[0:12] + create_vlan_tag(int(vlan_id)) + data[12:]

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec(switch_data, interfaces):
   while True:
        # TODO Send BDPU every second if necessary
        if switch_data['root_bridge_ID'] == switch_data['own_bridge_ID']:

            for i in interfaces:
                if switch_data[get_interface_name(i)] == 'T':
                    root_bridge_id = switch_data['root_bridge_ID']
                    own_bridge_id = switch_data['own_bridge_ID']
                    root_path_cost = switch_data['root_path_cost']
                    updated_bpdu = create_bpdu(root_bridge_id, own_bridge_id, root_path_cost, i)

                    # Sending the BPDU frame
                    send_to_link(i, updated_bpdu, 52)

        time.sleep(1)

def main():

    Table = {}
    switch_data = {}
    port_state = {}
    port_types = {}
    bpdu_data = {}

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    configuration_file = "configs/switch" + switch_id + ".cfg"

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    with open(configuration_file, 'r') as config_file:
        priority = config_file.readline().strip()

        switch_data['root_bridge_ID'] = int(priority)
        switch_data['own_bridge_ID'] = switch_data['root_bridge_ID']
        switch_data['root_path_cost'] = 0

        line = config_file.readline().strip()
        while line:
            INTERFACE_NAME, vlan = line.split(maxsplit=1)
            switch_data[INTERFACE_NAME] = vlan
            if vlan != 'T':
                    port_state[INTERFACE_NAME] = 'LISTENING'       
            else:       
                    port_state[INTERFACE_NAME] = 'BLOCKING'
                    if switch_data['root_bridge_ID']  == switch_data['own_bridge_ID']:
                        port_types[INTERFACE_NAME] = 'DESIGNATED_PORT'
                    else :
                        port_types[INTERFACE_NAME] = 'BLOCKED_PORT'
    
            
            line = config_file.readline().strip()



    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(switch_data, interfaces))
    t.start()

    while True:

        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        priority_check = vlan_id
        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)
        
        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        Table[src_mac] = interface
        
        if vlan_id == -1:
            vlan_id = switch_data[get_interface_name(interface)]
            if switch_data[get_interface_name(interface)] != 'T':
                tagged_frame = build_vlan(data, vlan_id)
                untagged_frame = data
        else:
            tagged_frame = data            
            untagged_frame = data[0:12] + data[16:]


        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

       
        if(is_bdpu_multicast(dest_mac)):

            bpdu = data
            bpdu_data['root_bridge_ID'] = bpdu[29]
            bpdu_data['sender_path_cost'] = bpdu[33]
            bpdu_data['sender_bridge_ID'] = bpdu[41]
       

            if bpdu_data['root_bridge_ID'] < switch_data['root_bridge_ID']:
                switch_data['root_bridge_ID'] = bpdu_data['root_bridge_ID']
                switch_data['root_path_cost'] = bpdu_data['sender_path_cost'] + 10
                root_name = get_interface_name(interface)
                port_types[get_interface_name(interface)] = 'ROOT_PORT'

                if switch_data['root_bridge_ID'] == switch_data['own_bridge_ID']:
                    for i in interfaces:
                        name = get_interface_name(i)
                        if i != interface:
                            if switch_data[name] == 'T':
                                port_state[name] = 'BLOCKING'
                                port_types[name] = 'BLOCKED_PORT'

                if port_state[root_name] == 'BLOCKING':
                    port_state[root_name] = 'LISTENING'

                for i in interfaces:
                    name = get_interface_name(i)
                    if i != interface:
                        if switch_data[name] == 'T':
                            root_bridge_id = switch_data['root_bridge_ID']
                            own_bridge_id = switch_data['own_bridge_ID']
                            root_path_cost = switch_data['root_path_cost']
                            updated_bpdu = create_bpdu(root_bridge_id, own_bridge_id, root_path_cost, i)
                            send_to_link(i, updated_bpdu, 52)

            elif bpdu_data['root_bridge_ID'] == switch_data['root_bridge_ID']:
                if port_types[root_name] == 'ROOT_PORT':
                    if bpdu_data['sender_path_cost'] + 10 < switch_data['root_path_cost']:
                        switch_data['root_path_cost'] = bpdu_data['sender_path_cost'] + 10
                elif port_types[root_name] != 'ROOT_PORT' and bpdu_data['sender_bridge_ID'] > switch_data['root_path_cost']:
                        if port_types[root_name] != 'DESIGNATED_PORT':
                            port_types[root_name] = 'DESIGNATED_PORT'
                            port_state[root_name] = 'LISTENING'

            elif bpdu_data['sender_bridge_ID'] == switch_data['own_bridge_ID']:
                port_types[root_name] = 'BLOCKED_PORT'

            else:
                pass

            if switch_data['root_bridge_ID'] == switch_data['own_bridge_ID']:
                for i in interfaces:
                    name = get_interface_name(i)
                    if switch_data[name] == 'T':
                        switch_data[name] = 'LISTENING'
                        port_types[name] = 'DESIGNATED_PORT'
                

        elif(is_unicast(dest_mac)):
            if(dest_mac in Table):
                vlan_dest = switch_data[get_interface_name(Table[dest_mac])]
                if(vlan_dest == 'T'):
                    to_send = Table[dest_mac]
                    send_to_link(to_send, tagged_frame, length + 4)
                else:
                     to_send = Table[dest_mac]
                     send_to_link(to_send, untagged_frame, length - 4)

            else:
                for i in interfaces:
                    if(i != interface):
                        name = get_interface_name(i)
                        if(switch_data[name] == 'T'):
                            send_to_link(i, tagged_frame, length + 4)
                        elif switch_data[name] == str(vlan_id):
                             send_to_link(i, untagged_frame, length - 4)

        else:
                for i in interfaces:
                    if(i != interface):  
                        name = get_interface_name(i)
                        if(switch_data[name] == 'T'):
                            send_to_link(i, tagged_frame, length + 4)
                        elif switch_data[name] == str(vlan_id):
                             send_to_link(i, untagged_frame, length - 4)
    
        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
