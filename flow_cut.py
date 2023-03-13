# -*- coding: utf-8 -*-

"""
pcapngs路径：../data/pcapngs/

@ 对于正常流量：
在该目录下，将所有的pcapng文件切分五元组流
并依据*.pcapng新建文件夹"../data/flows/*"
将pcap文件放入该文件夹中

@ 对于异常流量
pcapng文件开头为"cs"
新建文件夹"../data/flows/cs"
将pcap文件放入该文件夹中

"""

import dpkt
import socket
import os

# 定义切分流函数
def flow_cut(pcap_path, save_path):
    """
    @ pacp_path: pcap文件的路径 
    @ save_path: 流存储目录
    """
    pcap_ana(pcap_path, save_path)


def pcap_ana(pcap_path, save_path):
    """
    read pcap file and record flow
    in order to open once and write many times a flow.pcap file
    """
    with open(pcap_path, 'rb') as f:
        capture = dpkt.pcapng.Reader(f)
        flow_record = {}
        for ts, pkt in capture:
            # 划分五元组
            eth = dpkt.ethernet.Ethernet(pkt)

            # 符合IP规范才往下解析
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                # 只考虑TCP和UDP，否则下一个pkt
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tproto = "TCP"
                elif isinstance(ip.data, dpkt.udp.UDP):
                    tproto = "UDP"
                else:
                    continue
            
                trsm = ip.data
                sport = trsm.sport
                dport = trsm.dport
                flow = socket.inet_ntoa(ip.src) + '_' + str(sport) + '_' + socket.inet_ntoa(ip.dst) + '_' + str(dport) + '_' + tproto
                flow_rvs = socket.inet_ntoa(ip.dst) + '_' + str(dport) + '_' + socket.inet_ntoa(ip.src) + '_' + str(sport) + '_' + tproto

                # flow_record = {flow: [[pky, ts], ...], ...}
                if flow in flow_record.keys():
                    flow_record[flow].append([pkt, ts])
                elif flow_rvs in flow_record.keys():
                    flow_record[flow_rvs].append([pkt, ts])
                else:
                    flow_record[flow] = []
                    flow_record[flow].append([pkt, ts])
        # 正常流量输出每类数量
        # print(len(flow_record))
    
    flow_ana(flow_record, save_path)


def flow_ana(flow_record, save_path):
    """
    write pcap file according to flow_record dict
    """
    print('切分得到的五元组流数量：%d' % len(flow_record.keys()))
    for key in flow_record:
        flow_path = save_path + key + '.pcap'
        file = open(flow_path, 'ab')
        writer = dpkt.pcap.Writer(file)

        for record in flow_record[key]:
            eth = record[0]
            tist = record[1]
            writer.writepkt(eth, ts=tist)
            
        file.flush()
        file.close()


print("开始了开始了")

# 开始切分流
pcapngs_dir = "../data/pcapngs/"

# 正常流量处理
# for f in os.listdir(pcapngs_dir):
#     folder_name = f.split('.')[0]
#     pcaps_dir = "../data/flows/" + folder_name + "/"
#     if not os.path.exists(pcaps_dir):
#         os.makedirs(pcaps_dir)
#     print(folder_name)
#     flow_cut(pcapngs_dir + f, pcaps_dir)

f = 'wechat.pcapng'
pcaps_dir = '../data/flows/fivetuplestream/wechat/'
if not os.path.exists(pcaps_dir):
    os.makedirs(pcaps_dir)
flow_cut(pcapngs_dir + f, pcaps_dir)
 
# pcaps_dir = "../data/flows/cs/"
# if not os.path.exists(pcaps_dir):
#     os.makedirs(pcaps_dir)
# for f in os.listdir(pcapngs_dir):
#     if(f.startswith("http")):
#         print(f)
#         flow_cut(pcapngs_dir + f, pcaps_dir)

print("终于跑完了！")


        



