import pyshark
from collections import defaultdict
from datetime import datetime
import subprocess 



def filter_tcp_handshake_and_termination(packets):
    result=[]
    tcpconn = {}
    krbconn = {}
    smbconn={}
    httpconn={}
    
    
    ip1 = packets[0].ip.src
    ip2 = packets[0].ip.dst
    
    for packet in packets:
        # print(packet.summary())
        
        # Handling Kerberos (if relevant)
        # if 'Kerberos' in packet:
        #     print(packet['Kerberos'].show(dump=True))
        try:
            if 'TCP' in packet:
                
                flags = packet.tcp.flags
                
                
                # Check for SYN (TCP Handshake Step 1)
                if flags == '0x0002':  # SYN
                    tcpconn[str(packet.sniff_time)] = ['S']
                    continue

                # Check for SYN-ACK (TCP Handshake Step 2)
                elif flags == '0x0012':  # SYN-ACK
                    for key in tcpconn.keys():
                        if 'S' in tcpconn[key] and 'SA' not in tcpconn[key]:
                            tcpconn[key].append('SA')
                            break

                # Check for ACK (TCP Handshake Step 3)
                elif flags == '0x0010':  # ACK
                    for key in tcpconn.keys():
                        if 'S' in tcpconn[key] and 'SA' in tcpconn[key] and 'A' not in tcpconn[key]:
                            tcpconn[key].append('A')
                            tcpconn[str(packet.sniff_time)]= tcpconn.pop(key)
                            if packet.ip.src==ip1:
                                result.append(f"TCP Connection initiated by IP A established.")
                            elif packet.ip.src==ip2:
                                result.append(f"TCP Connection initiated by IP B established.")
                            break

                # Check for FIN (TCP Termination)
                elif flags == '0x0011':  # FIN
                    for key in tcpconn.keys():
                        if 'S' in tcpconn[key] and 'SA' in tcpconn[key] and 'A' in tcpconn[key] and 'FA' not in tcpconn[key]:
                            tcpconn[key].append('FA')
                            break

                # Check for ACK (Post-TCP Handshake)
                if flags == '0x0010':  # ACK
                    for key in tcpconn.keys():
                        if 'S' in tcpconn[key] and 'SA' in tcpconn[key] and 'A' in tcpconn[key] and 'FA' in tcpconn[key] and tcpconn[key][-1] != 'A':
                            tcpconn[key].append(str(packet.sniff_time))
                            tcpconn[key].append('A')
                            if packet.ip.dst==ip1:
                                result.append(f"TCP Connectoin terminated(FA_A) by IP A.")
                            elif packet.ip.dst==ip2:
                                result.append(f"TCP Connectoin terminated(FA_A) by IP B.")
                            break

                # Check for RST ACK (TCP Termination)
                if flags == '0x0014':  # RST-ACK (Reset)
                    for key in tcpconn.keys():
                        if 'S' in tcpconn[key] and 'SA' in tcpconn[key] and 'A' in tcpconn[key] and'RA' not in tcpconn[key]:
                            tcpconn[key].append(str(packet.sniff_time))
                            tcpconn[key].append('RA')
                            if packet.ip.src==ip1:
                                result.append(f"TCP Connection reset(RST_ACK) by IP A.")
                            elif packet.ip.src==ip2:
                                result.append(f"TCP Connection reset(RST_ACK) by IP B.")
                            break
            if 'kerberos' in packet:
                # Access the Kerberos layer and its message type
                kerberos_layer = packet['kerberos']
                msg_type = kerberos_layer.msg_type 
                print(f"msmg type of kerberos {msg_type}")
                print(type(msg_type))
                if(str(msg_type) =='10'):
                    krbconn[str(packet.sniff_time)] = ['AS_REQ']
                    continue
                elif(str(msg_type) ==str(11)):
                    for key in krbconn.keys():
                        if 'AS_REQ' in krbconn[key] and 'AS_REP' not in krbconn[key]:
                            crealm=kerberos_layer.crealm
                            krbconn[key].append('AS_REP')
                            krbconn[key].append(crealm)
                            krbconn[str(packet.sniff_time)]=krbconn.pop(key)
                            if packet.ip.dst==ip1:
                                result.append(f"TGT assigned under the crealm:{str(crealm)} to IP A.")
                            elif packet.ip.dst==ip2:
                                result.append(f"TGT assigned under the crealm:{str(crealm)} to IP B.")
                            break
                elif(str(msg_type)=='12'):
                    krbconn[str(packet.sniff_time)]=['TGS_REQ']
                    continue
                elif(str(msg_type)=='13'):
                    for key in krbconn.keys():
                        if 'TGS_REQ' in krbconn[key] and 'TGS_REP' not in krbconn[key]:
                            krbconn[key].append('TGS_REP')
                            krbconn[str(packet.sniff_time)]=krbconn.pop(key)
                            if packet.dst.ip==ip1:
                                result.append("TGS assigned a Service Ticket to IP A")
                            elif packet.dst.ip==ip2:
                                result.append("TGS assigned a Service Ticket to IP B")
                            break
            if 'smb2' in packet:
                print("smbb")
                smb_layer = packet["smb2"]
                smbcmd = smb_layer.cmd
                smbflag=smb_layer.flags
                fieldnames=smb_layer.field_names
            
                # ntstatus=smb_layer.nt_status

                if str(smbcmd) == '0' and str(smbflag)=='0x00000000':  # protocol negotiation req
                    smbconn[str(packet.sniff_time)] = {'PN':['PNR']}
                    continue
                elif str(smbcmd)=='0' and str(smbflag)=='0x00000001':
                    ntstatus=smb_layer.nt_status
                    if str(ntstatus)=="0x00000000":
                        for key in smbconn.keys():
                            if 'PNRP' not in smbconn[key]['PN']:
                                smbconn[key]["PN"].append('PNRP')
                                result.append("Protocol Negotiation completed for smb2 connection.")
                                break
                
                # session setup
                elif str(smbcmd) == '1' and str(smbflag)=='0x00000000':  # sess-setup req
                    for key in smbconn.keys():
                        if 'PN' in smbconn[key].keys()and 'SS' not in smbconn[key].keys() and 'PNRP' in smbconn[key]['PN'] :
                            smbconn[key]['SS']=['SSR']
                            continue
                    
                elif str(smbcmd)=='1' and str(smbflag)=='0x00000009':
                    
                    ntstatus=smb_layer.nt_status
                    if str(ntstatus)=="0x00000000":
                        
                        for key in smbconn.keys():
                            if 'SSRP' not in smbconn[key]['SS']:
                                smbconn[key]["SS"].append('SSRP')
                                if packet.ip.dst==ip1:
                                    result.append("SMB session requested by IP A established.")
                                elif packet.ip.dst==ip2:
                                    result.append("SMB session requested by IP B established")
                                break
                        
                elif str(smbcmd)=='3' and 'tc_flags' in fieldnames:
                    for key in smbconn.keys():
                        if 'TC' not in smbconn[key].keys():
                            smbconn[key]['TC']={}
                            smbconn[key]['TC']['0x00000000']=['CR',str(smb_layer.tree)]
                        else:
                            smbconn[key]['TC']['0x00000000']=['CR',str(smb_layer.tree)]
                elif str(smbcmd)=='3' and 'share_flags' in fieldnames:
                    for key in smbconn.keys():
                        for t in smbconn[key]['TC'].keys():
                            if(t=='0x00000000'):
                                smbconn[key]['TC'][t].append('CRP')
                                smbconn[key]['TC'][t].append({})
                                smbconn[key]['TC'][str(smb_layer.tid)]=smbconn[key]['TC'].pop(t)
                                result.append(f"Tree Connection established at {str(smbconn[key]['TC'][str(smb_layer.tid)][1])}.")
                                break


                elif str(smbcmd)=='5' and 'nt_status' not in fieldnames:
                    
                    for key in smbconn.keys():
                        for t in smbconn[key]['TC'].keys():
                            if t ==str(smb_layer.tid):
                                if 'C' not in smbconn[key]['TC'][t][-1].keys():
                                    smbconn[key]['TC'][t][-1]['C']=[]
                                    smbconn[key]['TC'][t][-1]['C'].append(['CR',str(smb_layer.filename)])
                                    break
                                else:
                                    smbconn[key]['TC'][t][-1]['C'].append(['CR',str(smb_layer.filename)])
                                    break

                elif str(smbcmd)=='5' and 'nt_status' in fieldnames:
                    
                        for key in smbconn.keys():
                            for t in smbconn[key]['TC'].keys():
                                if t ==str(smb_layer.tid):
                                    if 'C' in smbconn[key]['TC'][t][-1].keys():
                                        for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                            if smbconn[key]['TC'][t][-1]['C'][i][-1]!='CRP' and len(smbconn[key]['TC'][t][-1]['C'][i])!=3:
                                                if str(smb_layer.nt_status)=='0x00000000':
                                                    smbconn[key]['TC'][t][-1]['C'][i].append(str(smb_layer.fid))
                                                    smbconn[key]['TC'][t][-1]['C'][i].append('CRP')
                                                    result.append(f"File {str(smbconn[key]['TC'][t][-1]['C'][i][1])} Created Successfully.")
                                                    break
                                                else:
                                                    
                                                    smbconn[key]['TC'][t][-1]['C'][i].append(str(smb_layer.nt_status))

                elif str(smbcmd)=='8' and 'nt_status' not in fieldnames:
                    for key in smbconn.keys():
                        for t in smbconn[key]['TC'].keys():
                            if t ==str(smb_layer.tid):
                                if 'R' not in smbconn[key]['TC'][t][-1].keys():
                                    smbconn[key]['TC'][t][-1]['R']=[]
                                    for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                        if smbconn[key]['TC'][t][-1]['C'][i][2]==str(smb_layer.fid):
                                            smbconn[key]['TC'][t][-1]['R'].append(['RR',smbconn[key]['TC'][t][-1]['C'][i][1]])
                                            break
                                else:
                                    for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                        if smbconn[key]['TC'][t][-1]['C'][i][2]==str(smb_layer.fid):
                                            smbconn[key]['TC'][t][-1]['R'].append(['RR',smbconn[key]['TC'][t][-1]['C'][i][1]])
                                            break

                elif str(smbcmd)=='8' and 'nt_status' in fieldnames:
                    for key in smbconn.keys():
                        for t in smbconn[key]['TC'].keys():
                            if t ==str(smb_layer.tid):
                                if 'C' in smbconn[key]['TC'][t][-1].keys():
                                    for i in range(len(smbconn[key]['TC'][t][-1]['R'])):
                                        if smbconn[key]['TC'][t][-1]['R'][i][-1]!='RRP':
                                            smbconn[key]['TC'][t][-1]['R'][i].append('RRP')
                                            result.append(f"File {str(smbconn[key]['TC'][t][-1]['R'][i][1])} Read Successfully.")
                                            break
                
                elif str(smbcmd)=='6' and 'nt_status' not in fieldnames:
                    
                    for key in smbconn.keys():
                        for t in smbconn[key]['TC'].keys():
                            if t ==str(smb_layer.tid):
                                if 'CL' not in smbconn[key]['TC'][t][-1].keys():
                                    smbconn[key]['TC'][t][-1]['CL']=[]
                                    for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                        if smbconn[key]['TC'][t][-1]['C'][i][2]==str(smb_layer.fid):
                                            smbconn[key]['TC'][t][-1]['CL'].append(['CLR',smbconn[key]['TC'][t][-1]['C'][i][1]])
                                            break
                                else:
                                    for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                        if smbconn[key]['TC'][t][-1]['C'][i][2]==str(smb_layer.fid):
                                            smbconn[key]['TC'][t][-1]['CL'].append(['CLR',smbconn[key]['TC'][t][-1]['C'][i][1]])
                                            break       
            
                elif str(smbcmd)=='6' and 'nt_status' in fieldnames:
                    
                        for key in smbconn.keys():
                            for t in smbconn[key]['TC'].keys():
                                if t ==str(smb_layer.tid):
                                    if 'CL' in smbconn[key]['TC'][t][-1].keys():
                                        for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                            if smbconn[key]['TC'][t][-1]['CL'][i][-1]!='CLRP' and len(smbconn[key]['TC'][t][-1]['C'][i])!=3:
                                                if str(smb_layer.nt_status)=='0x00000000':
                                                    smbconn[key]['TC'][t][-1]['CL'][i].append('CLRP')
                                                    result.append(f"File {str(smbconn[key]['TC'][t][-1]['CL'][i][1])} Closed Successfully.")
                                                    break
                                                else:
                                                    
                                                    smbconn[key]['TC'][t][-1]['CL'][i].append(str(smb_layer.nt_status))

                elif str(smbcmd)=='16' and 'nt_status' not in fieldnames:
                    
                    for key in smbconn.keys():
                        for t in smbconn[key]['TC'].keys():
                            if t ==str(smb_layer.tid):
                                if 'GI' not in smbconn[key]['TC'][t][-1].keys():
                                    smbconn[key]['TC'][t][-1]['GI']=[]
                                    for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                        if smbconn[key]['TC'][t][-1]['C'][i][2]==str(smb_layer.fid):
                                            smbconn[key]['TC'][t][-1]['GI'].append(['GIR',smbconn[key]['TC'][t][-1]['C'][i][1]])
                                            break
                                else:
                                    for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                        if smbconn[key]['TC'][t][-1]['C'][i][2]==str(smb_layer.fid):
                                            smbconn[key]['TC'][t][-1]['GI'].append(['GIR',smbconn[key]['TC'][t][-1]['C'][i][1]])
                                            break       
            
                elif str(smbcmd)=='16' and 'nt_status' in fieldnames:
                    
                        for key in smbconn.keys():
                            for t in smbconn[key]['TC'].keys():
                                if t ==str(smb_layer.tid):
                                    if 'GI' in smbconn[key]['TC'][t][-1].keys():
                                        for i in range(len(smbconn[key]['TC'][t][-1]['C'])):
                                            if smbconn[key]['TC'][t][-1]['GI'][i][-1]!='GIRP' and len(smbconn[key]['TC'][t][-1]['GI'][i])!=3:
                                                if str(smb_layer.nt_status)=='0x00000000':
                                                    smbconn[key]['TC'][t][-1]['GI'][i].append('GIRP')
                                                    result.append(f"GET_INFO executed Successfully.")
                                                    break
                                                else:
                                                    
                                                    smbconn[key]['TC'][t][-1]['GI'][i].append(str(smb_layer.nt_status))

            if 'http' in packet:
                http_layer = packet["http"]
                fieldnames=http_layer.field_names

                
                if 'request_method' in fieldnames and "GET"==str(http_layer.request_method):
                    now = datetime.now()
                    httpconn['GR'+str(now)]=str(http_layer.request_uri)
                    if packet.ip.src==ip1:
                        result.append(f"IP A sent a GET request to {str(http_layer.request_uri)}.")
                    else:
                        result.append(f"IP B sent a GET request to {str(http_layer.request_uri)}.")
                elif 'request_method' in fieldnames and "POST"==str(http_layer.request_method):
                    httpconn['PR'+str(datetime.now())]=str(http_layer.request_uri)
                    if packet.ip.src==ip1:
                        result.append(f"IP A sent a POST request to {str(http_layer.request_uri)}.")
                    else:
                        result.append(f"IP B sent a POST request to {str(http_layer.request_uri)}.")
                elif 'request_method' in fieldnames and "PUT" == str(http_layer.request_method):
                    httpconn['PUTR'+str(datetime.now())] = str(http_layer.request_uri)
                    if packet.ip.src==ip1:
                        result.append(f"IP A sent a PUT request to {str(http_layer.request_uri)}.")
                    else:
                        result.append(f"IP B sent a PUT request to {str(http_layer.request_uri)}.")

                # Handle DELETE Request
                elif 'request_method' in fieldnames and "DELETE" == str(http_layer.request_method):
                    httpconn['DR'+str(datetime.now())] = str(http_layer.request_uri)
                    if packet.ip.src==ip1:
                        result.append(f"IP A sent a DELETE request to {str(http_layer.request_uri)}.")
                    else:
                        result.append(f"IP B sent a DELETE request to {str(http_layer.request_uri)}.")

                # Handle OPTIONS Request
                elif 'request_method' in fieldnames and "OPTIONS" == str(http_layer.request_method):
                    httpconn['OPR'+str(datetime.now())] = str(http_layer.request_uri)
                    if packet.ip.src==ip1:
                        result.append(f"IP A sent a OPTIONS request to {str(http_layer.request_uri)}.")
                    else:
                        result.append(f"IP B sent a OPTIONS request to {str(http_layer.request_uri)}.")

                elif 'response_version' in fieldnames and 'response_phrase' in fieldnames:
                    if 'RP' not in httpconn.keys():
                        httpconn['RP'] = []
                    
                    # Always include the response phrase
                    httpconn['RP'].append(str(http_layer.response_phrase))
                    
                    # Include content type if it exists, otherwise append "N/A"
                    if 'content_type' in fieldnames:
                        httpconn['RP'].append(str(http_layer.content_type))
                        if(packet.ip.src==ip1):
                            result.append(f"IP A responded {str(http_layer.response_phrase)} with Content-Type:{str(http_layer.content_type)}.")
                        else:
                            result.append(f"IP B responded {str(http_layer.response_phrase)} with Content-Type:{str(http_layer.content_type)}.")


                    else:
                        httpconn['RP'].append("N/A")
                        if(packet.ip.src==ip1):
                            result.append(f"IP A responded {str(http_layer.response_phrase)}.")
                        else:
                            result.append(f"IP B responded {str(http_layer.response_phrase)}.")
        except Exception as e:
            print( f"Error processing packet at {str(packet.sniff_time)}: {str(e)}")

    return result

            





def analyze_pcap(pcap_file):
    
    """
    Analyze a pcap file and group packets into conversations irrespective of direction.
    """
    connections = defaultdict(list)

    # Use Pyshark to parse the full packets
    with pyshark.FileCapture(pcap_file) as capture:
        for packet in capture:
            try:
                if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
                    # Extract necessary fields
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    # Create a normalized bidirectional key
                    connection_key = tuple(sorted([f'{src_ip}:{src_port}', f'{dst_ip}:{dst_port}']))

                    # Group packets into the conversation
                    connections[connection_key].append(packet)
            except AttributeError:
                # Skip packets without required attributes
                print("skipping")
                continue

    return dict(connections)


def display_conversation(pcap_file):
    """
    Display all conversations with packet counts and filter TCP handshake/termination for each.
    """
    # Analyze the pcap file and group conversations
    connection_data = analyze_pcap(pcap_file)
    print("otside analyze")
    # Convert connection_data keys to a list for indexing
    connection_keys = list(connection_data.keys())

    # Display all conversation names and packet counts
    print("Conversations and Packet Counts:")
    for idx, connection_key in enumerate(connection_keys):
        print(f"{idx + 1}: {connection_key} - {len(connection_data[connection_key])} packets")

    # Iterate through each conversation and pass its packets to the filter function
    final_result={}
    i=1
    for connection_key, packets in connection_data.items():
        final_result[i]=[str(connection_key[0]),str(connection_key[1]),str(len(packets)),filter_tcp_handshake_and_termination(packets)]
        i+=1

    return final_result



if __name__ == "__main__":
    pcap_file = "capture.pcap"  # Replace with the path to your pcap file
    print(display_conversation(pcap_file))
