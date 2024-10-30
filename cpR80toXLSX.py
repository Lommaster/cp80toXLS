import json
import tarfile
import xlsxwriter
import sys
import argparse



def format_hits(hits_count):        ####### Humanize procedure
    for unit in ['', 'K', 'M', 'G', 'T']:
        if hits_count < 1000 or unit == 'T':
            break
        hits_count /= 1000
    return f"{hits_count:.0f}{unit}"



def create_dict_obj(obj_json_file): ####### Create dictionary of objects
    global dict_obj
    dict_obj = {} # Dictionary of objects
        
    # Parsing object json-file and write data in dictionary
    for item_obj in obj_json_file:
        if item_obj["type"] == "checkpoint-host": dict_obj[item_obj["uid"]] = item_obj["name"] + " / " + item_obj["ipv4-address"]
        if item_obj["type"] == "simple-cluster": dict_obj[item_obj["uid"]] = item_obj["name"] + " / " + item_obj["ipv4-address"]
        if item_obj["type"] == "CpmiClusterMember": dict_obj[item_obj["uid"]] = item_obj["name"] + " / " + item_obj["ipv4-address"]
        if item_obj["type"] == "simple-gateway": dict_obj[item_obj["uid"]] = item_obj["name"] + " / " + item_obj["ipv4-address"]
        if item_obj["type"] == "CpmiAnyObject": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "service-tcp": dict_obj[item_obj["uid"]] = "tcp" + "/" + item_obj["port"]
        if item_obj["type"] == "service-udp": dict_obj[item_obj["uid"]] = "udp" + "/" + item_obj["port"]
        if item_obj["type"] == "service-other": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "service-icmp": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "service-dce-rpc": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "host": dict_obj[item_obj["uid"]] = item_obj["name"] + " / " + item_obj["ipv4-address"]
        if item_obj["type"] == "network": dict_obj[item_obj["uid"]] = item_obj["name"] + " / " + item_obj["subnet4"] + "/" + str(item_obj["mask-length4"])
        if item_obj["type"] == "RulebaseAction": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "Track": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "vpn-community-meshed": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "Global": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "time": dict_obj[item_obj["uid"]] = item_obj["end"]["date"] + " " + item_obj["end"]["iso-8601"].partition('T')[2][0:5]
        if item_obj["type"] == "threat-profile": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "ThreatExceptionRulebase": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "address-range": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "LegacyUserAtLocation": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "vpn-community-remote-access": dict_obj[item_obj["uid"]] = item_obj["name"]
        if item_obj["type"] == "access-role": dict_obj[item_obj["uid"]] = item_obj["name"]

        if item_obj["type"] == "group":
            if args.group:
                dict_obj[item_obj["uid"]] = item_obj["name"]
            else:
                dict_obj[item_obj["uid"]] = ''
                for item_group in item_obj["members"]:
                    if item_group["type"] == "host": dict_obj[item_obj["uid"]] += item_group["name"] + " / " + item_group["ipv4-address"] + "\n"
                    if item_group["type"] == "network": dict_obj[item_obj["uid"]] += item_group["name"] + " / " + item_group["subnet4"] + "/" + str(item_group["mask-length4"]) + "\n"
                dict_obj[item_obj["uid"]] = dict_obj[item_obj["uid"]][:-1]
            
        if item_obj["type"] == "service-group": 
            dict_obj[item_obj["uid"]] = ''
            for item_service_group in item_obj["members"]:
                if item_service_group["type"] == "service-tcp": dict_obj[item_obj["uid"]] += "tcp" + "/" + item_service_group["port"] + "\n"
                if item_service_group["type"] == "service-udp": dict_obj[item_obj["uid"]] += "udp" + "/" + item_service_group["port"] + "\n"
                if item_service_group["type"] == "service-other": dict_obj[item_obj["uid"]] += item_service_group["name"] + "\n"
                if item_service_group["type"] == "service-icmp": dict_obj[item_obj["uid"]] += item_service_group["name"] + "\n"
            dict_obj[item_obj["uid"]] = dict_obj[item_obj["uid"]][:-1]

    print('Dictionary of objects is complete...\n')

            

def fw_rules(worksheet, json_file):        ####### Worksheet rules create
    
    # Setup width column
    worksheet.set_column('A:A', 5)
    worksheet.set_column('B:B', 7)
    worksheet.set_column('C:C', 20)
    worksheet.set_column('D:D', 40)
    worksheet.set_column('E:E', 40)
    worksheet.set_column('F:F', 15)
    worksheet.set_column('G:G', 20)
    worksheet.set_column('H:H', 10)
    worksheet.set_column('I:I', 6)
    worksheet.set_column('J:J', 15)
    worksheet.set_column('K:K', 30)
    worksheet.set_column('L:L', 40)

    # Create Title
    worksheet.freeze_panes(1, 0)
    worksheet.write('A1', '№', title_format)
    worksheet.write('B1', 'Hits', title_format)
    worksheet.write('C1', 'Name', title_format)
    worksheet.write('D1', 'Source', title_format)
    worksheet.write('E1', 'Destination', title_format)
    worksheet.write('F1', 'VPN', title_format)
    worksheet.write('G1', 'Service', title_format)
    worksheet.write('H1', 'Action', title_format)
    worksheet.write('I1', 'Track', title_format)
    worksheet.write('J1', 'Time', title_format)
    worksheet.write('K1', 'Install on', title_format)
    worksheet.write('L1', 'Comment', title_format)

    row = 1
    negated_text_up = "---Negated---\n"
    negated_text_down = "------------------"

    for item_rule in json_file:
        # if section title --------
        if item_rule["type"] == "access-section":
            worksheet.merge_range(row, 0, row, 11, item_rule["name"], section_format)

        # if place-holder title --------
        if item_rule["type"] == "place-holder":
            worksheet.merge_range(row, 0, row, 11, item_rule["name"], holder_format)
            
        # if rule -----------------
        if item_rule["type"] == "access-rule":

            # Format setup for access-rule
            cell_format = cell_format1
            if not item_rule["enabled"]:
                cell_format = cell_format2
            elif not dict_obj[item_rule["time"][0]] == "Any":
                cell_format = cell_format3

            # Outlines
            worksheet.set_row(row, None, None, {"level": 1})
        
            # Rule number
            worksheet.write(row, 0, str(item_rule["rule-number"]), cell_format)

            # Hits
            worksheet.write(row, 1, format_hits(item_rule["hits"]["value"]), cell_format)

            # Name
            try:
                worksheet.write(row, 2, item_rule["name"], cell_format)
            except KeyError: worksheet.write(row, 2, '', cell_format)

            # Source
            temp_list = ''
            for item_source in item_rule["source"]:
                temp_list += dict_obj[item_source] + "\n"
            if not item_rule["source-negate"]:
                worksheet.write(row, 3, temp_list[:-1], cell_format)
            else:
                worksheet.write_rich_string(row, 3, red_text, negated_text_up, black_text, temp_list, red_text, negated_text_down, cell_format)
                        
            # Destination
            temp_list = ''
            for item_dest in item_rule["destination"]:
                temp_list += dict_obj[item_dest] + "\n"
            if not item_rule["destination-negate"] :
                worksheet.write(row, 4, temp_list[:-1], cell_format)
            else:
                worksheet.write_rich_string(row, 4, red_text, negated_text_up, black_text, temp_list, red_text, negated_text_down, cell_format)
            
            # VPN
            worksheet.write(row, 5, dict_obj[item_rule["vpn"][0]], cell_format)
            
            # Service
            temp_list = ''
            for item_service in item_rule["service"]:
                temp_list += dict_obj[item_service] + "\n"
            if not item_rule["destination-negate"]:
                worksheet.write(row, 6, temp_list[:-1], cell_format)
            else:
                worksheet.write_rich_string(row, 6, red_text, negated_text_up, black_text, temp_list, red_text, negated_text_down, cell_format)
            
            # Action
            worksheet.write(row, 7, dict_obj[item_rule["action"]], cell_format)
            
            # Track
            worksheet.write(row, 8, dict_obj[item_rule["track"]["type"]], cell_format)
            
            # Time
            temp_list = ''
            for item_time in item_rule["time"]:
                temp_list += dict_obj[item_time] + "\n"
            worksheet.write(row, 9, temp_list[:-1], cell_format)
            
            # Install on
            temp_list = ''
            for item_target in item_rule["install-on"]:
                temp_list += dict_obj[item_target] + "\n"
            worksheet.write(row, 10, temp_list[:-1], cell_format)
            
            # Comment
            worksheet.write(row, 11, item_rule["comments"], cell_format)
            
        row += 1



def nat_rules(worksheet, json_file):          ####### NAT rules worksheet create
    # Setup width column
    worksheet.set_column('A:A', 5)
    worksheet.set_column('B:B', 40)
    worksheet.set_column('C:C', 40)
    worksheet.set_column('D:D', 20)
    worksheet.set_column('E:E', 40)
    worksheet.set_column('F:F', 40)
    worksheet.set_column('G:G', 20)
    worksheet.set_column('H:H', 30)
    worksheet.set_column('I:I', 40)

    # Create Title
    worksheet.freeze_panes(1, 0)
    worksheet.write('A1', '№', title_format)
    worksheet.write('B1', 'Original Source', title_format)
    worksheet.write('C1', 'Original Destination', title_format)
    worksheet.write('D1', 'Original Services', title_format)
    worksheet.write('E1', 'Translated Source', title_format)
    worksheet.write('F1', 'Translated Destination', title_format)
    worksheet.write('G1', 'Translated Services', title_format)
    worksheet.write('H1', 'Install on', title_format)
    worksheet.write('I1', 'Comment', title_format)

    row=1

    for item_rule in json_file:
        # if section title --------
        if item_rule["type"] == "nat-section":
            worksheet.merge_range(row, 0, row, 8, item_rule["name"], section_format)

        # if rule -----------------
        if item_rule["type"] == "nat-rule":
            
            # Format setup for access-rule
            cell_format = cell_format1
            if not item_rule["enabled"]:
                cell_format = cell_format2

            # Outlines
            worksheet.set_row(row, None, None, {"level": 1})

            # Rule number
            worksheet.write(row, 0, str(item_rule["rule-number"]), cell_format)

            # Original Source
            worksheet.write(row, 1, dict_obj[item_rule["original-source"]], cell_format)

            # Original Destination
            worksheet.write(row, 2, dict_obj[item_rule["original-destination"]], cell_format)

            # Original Services
            worksheet.write(row, 3, dict_obj[item_rule["original-service"]], cell_format)

            # Translated Source
            worksheet.write(row, 4, dict_obj[item_rule["translated-source"]], cell_format)

            # Translated Destination
            worksheet.write(row, 5, dict_obj[item_rule["translated-destination"]], cell_format)

            # Translated Services
            worksheet.write(row, 6, dict_obj[item_rule["translated-service"]], cell_format)

            # Install on
            temp_list = ''
            for item_target in item_rule["install-on"]:
                temp_list += dict_obj[item_target] + "\n"
            worksheet.write(row, 7, temp_list[:-1], cell_format)

            # Comment
            worksheet.write(row, 8, item_rule["comments"], cell_format)

        row += 1



#####################
# ----- BEGIN ----- #
#####################



parser = argparse.ArgumentParser(prog='cpR80toXLSX', description='Conversion output show_policy util from Check Point R80 to excel-file')
parser.add_argument("gztarfile", help="archive file of FW policy Check Point R80")
parser.add_argument("-gr", "--group", help="DON'T expand group composition", action="store_true")
parser.add_argument("-gl", "--glb", help="include global rules from policy", action="store_true")
parser.add_argument("-nt", "--nat", help="include nat rules from policy", action="store_true")

args = parser.parse_args()

targzfile = args.gztarfile

print('cpR80toXLSX ver. 2.1')
print('https://github.com/Lommaster/cpR80toXLSX\n')

with tarfile.open(targzfile, "r:gz") as tar:
    index_file_byte = tar.extractfile("index.json").read()
    index_json_file = json.loads(index_file_byte)

    # Parsing index.json for filename and change extention from html to json
    objects_file = index_json_file["policyPackages"][0]["objects"]["htmlObjectsFileName"].replace('.html', '.json')
    global_network_file = index_json_file["policyPackages"][0]["accessLayers"][0]["htmlFileName"].replace('.html', '.json')
    network_file = index_json_file["policyPackages"][0]["accessLayers"][1]["htmlFileName"].replace('.html', '.json')
    nat_file = index_json_file["policyPackages"][0]["natLayer"]["htmlFileName"].replace('.html', '.json')
    package_name = index_json_file["policyPackages"][0]["packageName"] + ".xlsx"

    #----------- Create Dictionary Objects
    # Open object file
    obj_file_byte = tar.extractfile(objects_file).read()
    obj_json_file = json.loads(obj_file_byte)

    # Call procedure to create dictionary of objects
    create_dict_obj(obj_json_file) 

    # Open local FW file
    network_file_byte = tar.extractfile(network_file).read()
    network_json_file = json.loads(network_file_byte)

    # Open Excel-file

    ### ???? Проверить если файл существует открыть с другим именем или вывести предупреждение

    # Create excel-file
    workbook = xlsxwriter.Workbook(package_name)
    
    # Setup formats
    title_format = workbook.add_format({
        'bold':     True,
        'align':    'center',
        'valign':   'vcenter',
        'fg_color': '#003153',
        'color':    '#FFFFFF',
        'font_size': 12,
    })

    section_format = workbook.add_format({
        'bold':     True,
        'align':    'center',
        'valign':   'vcenter',
        'fg_color': '#F0E68C',
        'border':   1,
    })

    holder_format = workbook.add_format({
        'bold':     True,
        'valign':   'vcenter',
        'fg_color': '#AFEEEE',
        'border':   1,
    })

    red_text = workbook.add_format({'color': 'red'})
    black_text = workbook.add_format({'color': 'black'})

    # Format for Enabled rules
    cell_format1 = workbook.add_format()
    cell_format1.set_text_wrap()
    cell_format1.set_align('left')
    cell_format1.set_valign('top')
    cell_format1.set_border()

    # Format for Disabled rules
    cell_format2 = workbook.add_format()
    cell_format2.set_text_wrap()
    cell_format2.set_align('left')
    cell_format2.set_valign('top')
    cell_format2.set_border()
    cell_format2.set_fg_color('#B5B8B1')

    # Format for Timed rules
    cell_format3 = workbook.add_format()
    cell_format3.set_text_wrap()
    cell_format3.set_align('left')
    cell_format3.set_valign('top')
    cell_format3.set_border()
    cell_format3.set_fg_color('#AFEEEE')

    # Format of cells
    cell_format = workbook.add_format()

    # Create worksheet for Local Rules
    ws_lcl_rls = workbook.add_worksheet('Local RULES')
    ws_lcl_rls.outline_settings(True, False, True, True)
    # Call procedure to create worksheet for Local Rules
    fw_rules(ws_lcl_rls, network_json_file)
    
    if args.glb:
        # Open global FW file
        global_network_file_byte = tar.extractfile(global_network_file).read()
        global_network_json_file = json.loads(global_network_file_byte)
        # Create worksheet for Global Rules
        ws_glb_rls = workbook.add_worksheet('Global RULES')
        ws_glb_rls.outline_settings(True, False, True, True)
        # Call procedure to create worksheet for Global Rules
        fw_rules(ws_glb_rls, global_network_json_file)

    if args.nat:
        # Open NAT FW file
        nat_file_byte = tar.extractfile(nat_file).read()
        nat_json_file = json.loads(nat_file_byte)
        # Create worksheet for NAT Rules
        ws_nat_rls = workbook.add_worksheet('NAT RULES')
        ws_nat_rls.outline_settings(True, False, True, True)
        # Call procedure to create worksheet for NAT Rules
        nat_rules(ws_nat_rls, nat_json_file)

    workbook.close()

# Close tar.gz-file
tar.close()

# End program
print("Conversion complete.\n")
