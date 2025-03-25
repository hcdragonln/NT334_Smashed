from scapy.all import sniff, wrpcap
import pyshark
import time
import csv
import collections
import argparse
import threading
import queue
import datetime
import signal
import sys
def capture_packets(interface, output_file, packet_count=1000):
    """
    Bắt gói tin trên card mạng và lưu thành file PCAP.
    """
    print(f"Bắt đầu bắt {packet_count} gói tin trên giao diện {interface}...")
    packets = sniff(iface=interface, count=packet_count)
    wrpcap(output_file, packets)
    print(f"Đã lưu {len(packets)} gói tin vào file {output_file}")
def extract_features_by_ip_pairs(pcap_file):
    """
    Trích xuất các vector đặc trưng từ file PCAP, tính toán dựa trên cặp IP nguồn - IP đích,
    bao gồm thống kê về cổng.
    """

    print(f"Phân tích file {pcap_file} để trích xuất đặc trưng theo cặp IP...")
    cap = pyshark.FileCapture(pcap_file, tshark_path="G:/Wireshark/tshark.exe")
    ip_pair_features = {}

    for packet in cap:
        try:
            # Kiểm tra gói tin lớp IP
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                pair = tuple(sorted([src_ip, dst_ip]))

                # Khởi tạo cấu trúc lưu đặc trưng nếu chưa tồn tại
                if pair not in ip_pair_features:
                    ip_pair_features[pair] = {
                        'packets': 0,
                        'bytes': 0,
                        'ports': {'src_ports': collections.Counter(), 'dst_ports': collections.Counter()},
                        'syn_flows': 0,
                        'ack_flows': 0,
                        'ackpush_flows': 0,
                        'rst_flows': 0,
                        'fin_flows': 0,
                        'other_flows': 0,
                        'request_flows': 0,
                        'last_seen': time.time(),
                        'last_exported': time.time(),
                    }

                # Tăng số lượng gói và byte
                ip_pair_features[pair]['packets'] += 1
                ip_pair_features[pair]['bytes'] += int(packet.length)

                # Lưu thông tin cổng nếu là TCP hoặc UDP
                if 'TCP' in packet or 'UDP' in packet:
                    proto = 'tcp' if 'TCP' in packet else 'udp'
                    src_port = int(packet[proto].srcport)
                    dst_port = int(packet[proto].dstport)

                    # Đếm tần suất cổng
                    if src_port==pair[0]:
                        ip_pair_features[pair]['ports']['src_ports'][src_port] += 1
                        ip_pair_features[pair]['ports']['dst_ports'][dst_port] += 1
                    else:
                        ip_pair_features[pair]['ports']['dst_ports'][src_port] += 1
                        ip_pair_features[pair]['ports']['src_ports'][dst_port] += 1
                    # Đếm số lượng request flows (source port > destination port)
                    if src_port > dst_port:
                        ip_pair_features[pair]['request_flows'] += 1

                # Xử lý cờ TCP nếu có
                if 'TCP' in packet:
                    flags = packet.tcp.flags
                    if 'ACK' in flags and 'PUSH' in flags:
                        ip_pair_features[pair]['ackpush_flows'] += 1
                    elif 'ACK' in flags:
                        ip_pair_features[pair]['ack_flows'] += 1
                    elif 'SYN' in flags:
                        ip_pair_features[pair]['syn_flows'] += 1
                    elif 'RST' in flags:
                        ip_pair_features[pair]['rst_flows'] += 1
                    elif 'FIN' in flags:
                        ip_pair_features[pair]['fin_flows'] += 1
                    else:
                        ip_pair_features[pair]['other_flows'] += 1

                # Cập nhật thời gian gói tin cuối cùng
                ip_pair_features[pair]['last_seen'] = time.time()
        except AttributeError:
            # Bỏ qua các gói tin không đầy đủ thông tin
            continue

    # Tính toán thêm các đặc trưng tổng hợp cho từng cặp IP
    for pair, features in ip_pair_features.items():
        flows = (
            features['ack_flows'] +
            features['ackpush_flows'] +
            features['other_flows']
        )
        features['flows'] = flows
        if features['packets'] > 0 and flows > 0:
            features['bpp'] = features['bytes'] // features['packets']  # Bytes per packet
            features['ppf'] = features['packets'] // flows  # Packets per flow
        else:
            features['bpp'] = 0
            features['ppf'] = 0

        active_time = features['last_seen'] - features['last_exported']
        features['ppm'] = -1 if active_time < 5 else int(features['packets'] / (active_time / 60.0))

        # Tính toán req/all
        if features['flows'] > 0:
            features['req_all'] = features['request_flows'] / features['flows']
        else:
            features['req_all'] = 0

        # Tìm cổng phổ biến nhất
        features['top_src_port'] = features['ports']['src_ports'].most_common(1)[0][0] if features['ports']['src_ports'] else None
        features['top_dst_port'] = features['ports']['dst_ports'].most_common(1)[0][0] if features['ports']['dst_ports'] else None

    cap.close()
    return ip_pair_features

def compute_weka_tree(ip_pair_features):
    """
    Phân loại cặp IP là 'miner' hoặc 'notminer' dựa trên các đặc trưng bằng cây quyết định (weka tree).
    """

    results = {}
    for pair, features in ip_pair_features.items():
        try:
            
            # Lấy các giá trị đặc trưng
            ackpush_flows = features['ackpush_flows']
            flows = features['flows']
            bpp = features.get('bpp', 0)
            ppf = features.get('ppf', 0)
            ppm = features.get('ppm', -1)
            synSall = int((features['syn_flows'] / flows) * 100) if flows > 0 else 0
            rstSall = int((features['rst_flows'] / flows) * 100) if flows > 0 else 0
            finSall = int((features['fin_flows'] / flows) * 100) if flows > 0 else 0
            ackpushSall = int((ackpush_flows / flows) * 100) if flows > 0 else 0
            reqSall= features.get('req_all', 0)            
            # Áp dụng cây quyết định
            #print(f"{pair},{ackpushSall},{bpp},{ppf},{ppm},{reqSall},{synSall},{rstSall},{finSall}")
            if ppm <= 135:
                if bpp <= 70:
                    if ppm <= 12:
                        if rstSall <= 1:
                            if finSall <= 7:
                                if ppf <= 3:
                                    if bpp <= 59:
                                        if ackpushSall <= 86:
                                            results[pair] = "notminer"
                                        if ackpushSall > 86:
                                            if ppf <= 1:
                                                if bpp <= 54:
                                                    if ppm <= 5:
                                                        if synSall <= 1:
                                                            if ackpushSall <= 95:
                                                                results[pair] = "notminer"
                                                            if ackpushSall > 95:
                                                                if ppm <= 1:
                                                                    results[pair] = "miner"
                                                                if ppm > 1:
                                                                    if ackpushSall <= 97:
                                                                        results[pair] = "notminer"
                                                                    if ackpushSall > 97:
                                                                        if finSall <= 0:
                                                                            if ackpushSall <= 99:
                                                                                if ppm <= 4:
                                                                                    results[pair] = "notminer"
                                                                                if ppm > 4:
                                                                                    results[pair] = "miner"
                                                                            if ackpushSall > 99:
                                                                                results[pair] = "miner"
                                                                        if finSall > 0:
                                                                            results[pair] = "notminer"
                                                        if synSall > 1:
                                                            if finSall <= 6:
                                                                results[pair] = "notminer"
                                                            if finSall > 6:
                                                                results[pair] = "miner"
                                                    if ppm > 5:
                                                        results[pair] = "notminer"
                                                if bpp > 54:
                                                    results[pair] = "notminer"
                                            if ppf > 1:
                                                if ppf <= 2:
                                                    if synSall <= 6:
                                                        if rstSall <= 0:
                                                            if bpp <= 55:
                                                                if finSall <= 3:
                                                                    if ackpushSall <= 93:
                                                                        if ppm <= 5:
                                                                            results[pair] = "notminer"
                                                                        if ppm > 5:
                                                                            results[pair] = "miner"
                                                                    if ackpushSall > 93:
                                                                        if bpp <= 52:
                                                                            if ppm <= 6:
                                                                                if ackpushSall <= 99:
                                                                                    if finSall <= 0:
                                                                                        results[pair] = "notminer"
                                                                                    if finSall > 0:
                                                                                        if bpp <= 43:
                                                                                            results[pair] = "miner"
                                                                                        if bpp > 43:
                                                                                            if synSall <= 0:
                                                                                                results[pair] = "miner"
                                                                                            if synSall > 0:
                                                                                                results[pair] = "notminer"
                                                                                if ackpushSall > 99:
                                                                                    results[pair] = "miner"
                                                                            if ppm > 6:
                                                                                results[pair] = "notminer"
                                                                        if bpp > 52:
                                                                            if ppm <= 3:
                                                                                if ackpushSall <= 97:
                                                                                    results[pair] = "notminer"
                                                                                if ackpushSall > 97:
                                                                                    results[pair] = "miner"
                                                                            if ppm > 3:
                                                                                if ackpushSall <= 98:
                                                                                    if bpp <= 54:
                                                                                        results[pair] = "miner"
                                                                                    if bpp > 54:
                                                                                        if ackpushSall <= 94:
                                                                                            results[pair] = "miner"
                                                                                        if ackpushSall > 94:
                                                                                            results[pair] = "notminer"
                                                                                if ackpushSall > 98:
                                                                                    results[pair] = "notminer"
                                                                if finSall > 3:
                                                                    results[pair] = "notminer"
                                                        if bpp > 55:
                                                            if ppm <= 8:
                                                                if ppm <= 1:
                                                                    results[pair] = "notminer"
                                                                if ppm > 1:
                                                                    if ackpushSall <= 99:
                                                                        if ackpushSall <= 94:
                                                                            if ppm <= 4:
                                                                                results[pair] = "notminer"
                                                                            if ppm > 4:
                                                                                if bpp <= 56:
                                                                                    results[pair] = "miner"
                                                                                if bpp > 56:
                                                                                    if ackpushSall <= 89:
                                                                                        results[pair] = "miner"
                                                                                    if ackpushSall > 89:
                                                                                        results[pair] = "notminer"
                                                                        if ackpushSall > 94:
                                                                            results[pair] = "notminer"
                                                                    if ackpushSall > 99:
                                                                        results[pair] = "miner"
                                                            if ppm > 8:
                                                                results[pair] = "notminer"
                                                    if rstSall > 0:
                                                        if bpp <= 56:
                                                            if ackpushSall <= 96:
                                                                if bpp <= 40:
                                                                    results[pair] = "miner"
                                                                if bpp > 40:
                                                                    if ppm <= 6:
                                                                        results[pair] = "notminer"
                                                                    if ppm > 6:
                                                                        results[pair] = "miner"
                                                            if ackpushSall > 96:
                                                                results[pair] = "notminer"
                                                        if bpp > 56:
                                                            results[pair] = "notminer"
                                                if synSall > 6:
                                                    results[pair] = "notminer"
                                            if ppf > 2:
                                                if ackpushSall <= 99:
                                                    results[pair] = "notminer"
                                                if ackpushSall > 99:
                                                    if ppm <= 5:
                                                        if ppm <= 3:
                                                            results[pair] = "notminer"
                                                        if ppm > 3:
                                                            results[pair] = "miner"
                                                    if ppm > 5:
                                                        results[pair] = "notminer"
                                    if ppf > 3:
                                        if ackpushSall <= 99:
                                            results[pair] = "notminer"
                                        if ackpushSall > 99:
                                            if bpp <= 57:
                                                results[pair] = "notminer"
                                            if bpp > 57:
                                                if ppm <= 6:
                                                    results[pair] = "notminer"
                                                if ppm > 6:
                                                    if ppf <= 10:
                                                        if ppm <= 10:
                                                            if bpp <= 67:
                                                                if ppf <= 8:
                                                                    if bpp <= 58:
                                                                        results[pair] = "miner"
                                                                    if bpp > 58:
                                                                        results[pair] = "notminer"
                                                                if ppf > 8:
                                                                    results[pair] = "miner"
                                                            if bpp > 67:
                                                                results[pair] = "notminer"
                                                        if ppm > 10:
                                                            results[pair] = "notminer"
                                                    if ppf > 10:
                                                        results[pair] = "notminer"
                                if finSall > 7:
                                    results[pair] = "notminer"
                        if rstSall > 1:
                            if finSall <= 97:
                                if synSall <= 2:
                                    if ppf <= 5:
                                        results[pair] = "notminer"
                                    if ppf > 5:
                                        results[pair] = "miner"
                                if synSall > 2:
                                    results[pair] = "notminer"
                            if finSall > 97:
                                if ppf <= 6:
                                    results[pair] = "notminer"
                                if ppf > 6:
                                    results[pair] = "miner"
                    if ppm > 12:
                        results[pair] = "notminer"
                if bpp > 70:
                    if ppm <= 70:
                        if reqSall <= 75:
                            results[pair] = "miner"
                        if reqSall > 75:
                            results[pair] = "notminer"
                    if ppm > 70:
                        if ackpushSall <= 99:
                            results[pair] = "notminer"
                        if ackpushSall > 99:
                            if bpp <= 105:
                                results[pair] = "notminer"
                            if bpp > 105:
                                results[pair] = "miner"
            if ppm > 135:
                if bpp <= 103:
                    results[pair] = "notminer"
                if bpp > 103:
                    if bpp <= 108:
                        if ppf <= 230:
                            results[pair] = "miner"
                        if ppf > 230:
                            results[pair] = "notminer"
                    if bpp > 108:
                        results[pair] = "notminer"
        

        except ZeroDivisionError:
            results[pair] = "unknown"
        except KeyError:
            results[pair] = "unknown"

    return results

def compute_weka_tree_from_csv(csv_file_path):
    """
    Phân loại cặp IP là 'miner' hoặc 'notminer' dựa trên các đặc trưng từ CSV bằng cây quyết định (weka tree).
    """

    results = {}
    comparisons = []
    # Đọc dữ liệu từ CSV
    with open(csv_file_path, mode='r') as file:
        reader = csv.reader(file)
        
        for index, row in enumerate(reader):
            try:
                # Lấy các giá trị đặc trưng từ CSV
                ackpushSall = float(row[0])
                bpp = float(row[1])
                ppf = float(row[2])
                ppm = float(row[3])
                reqSall = float(row[4])
                synSall = float(row[5])
                rstSall = float(row[6])
                finSall = float(row[7])
                
                # Tính toán các tỷ lệ phần trăm
#                total_flows = 100  # Giả sử tổng số flows là 1, có thể điều chỉnh dựa trên cách tính tổng flows trong dữ liệu thực tế
#                ackpushSall = int((ackpush_all / total_flows) * 100) if total_flows > 0 else 0
#                synSall = int((syn_all / total_flows) * 100) if total_flows > 0 else 0
#                rstSall = int((rst_all / total_flows) * 100) if total_flows > 0 else 0
#                finSall = int((fin_all / total_flows) * 100) if total_flows > 0 else 0

                # Áp dụng cây quyết định
                if ppm <= 135:
                    if bpp <= 70:
                        if ppm <= 12:
                            if rstSall <= 1:
                                if finSall <= 7:
                                    if ppf <= 3:
                                        if bpp <= 59:
                                            if ackpushSall <= 86:
                                                results[index] = "notminer"
                                            if ackpushSall > 86:
                                                if ppf <= 1:
                                                    if bpp <= 54:
                                                        if ppm <= 5:
                                                            if synSall <= 1:
                                                                if ackpushSall <= 95:
                                                                    results[index] = "notminer"
                                                                if ackpushSall > 95:
                                                                    if ppm <= 1:
                                                                        results[index] = "miner"
                                                                    if ppm > 1:
                                                                        if ackpushSall <= 97:
                                                                            results[index] = "notminer"
                                                                        if ackpushSall > 97:
                                                                            if finSall <= 0:
                                                                                if ackpushSall <= 99:
                                                                                    if ppm <= 4:
                                                                                        results[index] = "notminer"
                                                                                    if ppm > 4:
                                                                                        results[index] = "miner"
                                                                                if ackpushSall > 99:
                                                                                    results[index] = "miner"
                                                                            if finSall > 0:
                                                                                results[index] = "notminer"
                                                            if synSall > 1:
                                                                if finSall <= 6:
                                                                    results[index] = "notminer"
                                                                if finSall > 6:
                                                                    results[index] = "miner"
                                                        if ppm > 5:
                                                            results[index] = "notminer"
                                                    if bpp > 54:
                                                        results[index] = "notminer"
                                                if ppf > 1:
                                                    if ppf <= 2:
                                                        if synSall <= 6:
                                                            if rstSall <= 0:
                                                                if bpp <= 55:
                                                                    if finSall <= 3:
                                                                        if ackpushSall <= 93:
                                                                            if ppm <= 5:
                                                                                results[index] = "notminer"
                                                                            if ppm > 5:
                                                                                results[index] = "miner"
                                                                        if ackpushSall > 93:
                                                                            if bpp <= 52:
                                                                                if ppm <= 6:
                                                                                    if ackpushSall <= 99:
                                                                                        if finSall <= 0:
                                                                                            results[index] = "notminer"
                                                                                        if finSall > 0:
                                                                                            if bpp <= 43:
                                                                                                results[index] = "miner"
                                                                                            if bpp > 43:
                                                                                                if synSall <= 0:
                                                                                                    results[index] = "miner"
                                                                                                if synSall > 0:
                                                                                                    results[index] = "notminer"
                                                                                    if ackpushSall > 99:
                                                                                        results[index] = "miner"
                                                                                if ppm > 6:
                                                                                    results[index] = "notminer"
                                                                            if bpp > 52:
                                                                                if ppm <= 3:
                                                                                    if ackpushSall <= 97:
                                                                                        results[index] = "notminer"
                                                                                    if ackpushSall > 97:
                                                                                        results[index] = "miner"
                                                                                if ppm > 3:
                                                                                    if ackpushSall <= 98:
                                                                                        if bpp <= 54:
                                                                                            results[index] = "miner"
                                                                                        if bpp > 54:
                                                                                            if ackpushSall <= 94:
                                                                                                results[index] = "miner"
                                                                                            if ackpushSall > 94:
                                                                                                results[index] = "notminer"
                                                                                    if ackpushSall > 98:
                                                                                        results[index] = "notminer"
                                                                    if finSall > 3:
                                                                        results[index] = "notminer"
                                                            if bpp > 55:
                                                                if ppm <= 8:
                                                                    if ppm <= 1:
                                                                        results[index] = "notminer"
                                                                    if ppm > 1:
                                                                        if ackpushSall <= 99:
                                                                            if ackpushSall <= 94:
                                                                                if ppm <= 4:
                                                                                    results[index] = "notminer"
                                                                                if ppm > 4:
                                                                                    if bpp <= 56:
                                                                                        results[index] = "miner"
                                                                                    if bpp > 56:
                                                                                        if ackpushSall <= 89:
                                                                                            results[index] = "miner"
                                                                                        if ackpushSall > 89:
                                                                                            results[index] = "notminer"
                                                                            if ackpushSall > 94:
                                                                                results[index] = "notminer"
                                                                        if ackpushSall > 99:
                                                                            results[index] = "miner"
                                                                if ppm > 8:
                                                                    results[index] = "notminer"
                                                        if rstSall > 0:
                                                            if bpp <= 56:
                                                                if ackpushSall <= 96:
                                                                    if bpp <= 40:
                                                                        results[index] = "miner"
                                                                    if bpp > 40:
                                                                        if ppm <= 6:
                                                                            results[index] = "notminer"
                                                                        if ppm > 6:
                                                                            results[index] = "miner"
                                                                if ackpushSall > 96:
                                                                    results[index] = "notminer"
                                                            if bpp > 56:
                                                                results[index] = "notminer"
                                                    if synSall > 6:
                                                        results[index] = "notminer"
                                                if ppf > 2:
                                                    if ackpushSall <= 99:
                                                        results[index] = "notminer"
                                                    if ackpushSall > 99:
                                                        if ppm <= 5:
                                                            if ppm <= 3:
                                                                results[index] = "notminer"
                                                            if ppm > 3:
                                                                results[index] = "miner"
                                                        if ppm > 5:
                                                            results[index] = "notminer"
                                        if ppf > 3:
                                            if ackpushSall <= 99:
                                                results[index] = "notminer"
                                            if ackpushSall > 99:
                                                if bpp <= 57:
                                                    results[index] = "notminer"
                                                if bpp > 57:
                                                    if ppm <= 6:
                                                        results[index] = "notminer"
                                                    if ppm > 6:
                                                        if ppf <= 10:
                                                            if ppm <= 10:
                                                                if bpp <= 67:
                                                                    if ppf <= 8:
                                                                        if bpp <= 58:
                                                                            results[index] = "miner"
                                                                        if bpp > 58:
                                                                            results[index] = "notminer"
                                                                    if ppf > 8:
                                                                        results[index] = "miner"
                                                                if bpp > 67:
                                                                    results[index] = "notminer"
                                                            if ppm > 10:
                                                                results[index] = "notminer"
                                                        if ppf > 10:
                                                            results[index] = "notminer"
                                    if finSall > 7:
                                        results[index] = "notminer"
                            if rstSall > 1:
                                if finSall <= 97:
                                    if synSall <= 2:
                                        if ppf <= 5:
                                            results[index] = "notminer"
                                        if ppf > 5:
                                            results[index] = "miner"
                                    if synSall > 2:
                                        results[index] = "notminer"
                                if finSall > 97:
                                    if ppf <= 6:
                                        results[index] = "notminer"
                                    if ppf > 6:
                                        results[index] = "miner"
                        if ppm > 12:
                            results[index] = "notminer"
                    if bpp > 70:
                        if ppm <= 70:
                            if reqSall <= 75:
                                results[index] = "miner"
                            if reqSall > 75:
                                results[index] = "notminer"
                        if ppm > 70:
                            if ackpushSall <= 99:
                                results[index] = "notminer"
                            if ackpushSall > 99:
                                if bpp <= 105:
                                    results[index] = "notminer"
                                if bpp > 105:
                                    results[index] = "miner"
                if ppm > 135:
                    if bpp <= 103:
                        results[index] = "notminer"
                    if bpp > 103:
                        if bpp <= 108:
                            if ppf <= 230:
                                results[index] = "miner"
                            if ppf > 230:
                                results[index] = "notminer"
                        if bpp > 108:
                            results[index] = "notminer"
            
                
            except ValueError:  # Xử lý trường hợp lỗi khi chuyển đổi dữ liệu
                results[index] = "unknown"
                comparisons.append(False)
            except KeyError:  # Xử lý trường hợp thiếu thông tin
                results[index] = "unknown"
                comparisons.append(False)

    return results
                                    
def Xuat(features,classification_results):
   for pair in classification_results:
        src_port = (
            features[pair]["ports"]["src_ports"].most_common(1)[0][0]
            if features[pair]["ports"]["src_ports"]
            else None
        )
        dst_port = (
            features[pair]["ports"]["dst_ports"].most_common(1)[0][0]
            if features[pair]["ports"]["dst_ports"]
            else None
        )
        print(
            f"{pair} : {classification_results[pair]} : {src_port} : {dst_port}"
        )

stop_flag = False
def signal_handler(sig, frame):
    global stop_flag
    print("Chương trình đang xử lý hãy đợi 1 lát")
    stop_flag = True

# Gắn tín hiệu Ctrl+C
signal.signal(signal.SIGINT, signal_handler)


def main():
    """
    Chương trình chính để thực thi toàn bộ quy trình.
    """
    # Sử dụng argparse để lấy các tùy chọn đầu vào
    parser = argparse.ArgumentParser(description="Chương trình phát hiện miner.")
    parser.add_argument(
        "-i", "--interface",
        type=str,
        help="Tên giao diện mạng để bắt gói tin (mặc định: Wi-Fi).",
        default="Wi-Fi"
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Đường dẫn tới file (mặc định: traffic.pcap).",
        default="traffic.pcap"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        help="Số lượng gói tin để bắt (mặc định: 100).",
        default=100
    )
    parser.add_argument(
        "--use-default",
        action="store_true",
        help="Sử dụng giá trị mặc định nếu không có tham số đầu vào."
    )
    parser.add_argument(
        "-T", "--type",
        type=int,
        choices=[1, 2, 3],
        help="1: Bắt gói tin và phân tích, 2: Phân tích PCAP, 3: Phân tích CSV.",
        default=1
    )

    args = parser.parse_args()

    if args.type == 1:
        global stop_flag
        while not stop_flag:
               capture_packets(args.interface, args.file, args.count) 
               if stop_flag:
                  break 
               features = extract_features_by_ip_pairs(args.file)
               if stop_flag:
                  break  
               classification_results = compute_weka_tree(features)
               Xuat(features,classification_results)
        print("Chương trình đã dừng")
    elif args.type == 2:
        # Phân tích file PCAP
        print("Phân tích file PCAP:", args.file)
        features = extract_features_by_ip_pairs(args.file)
        classification_results = compute_weka_tree(features)
        Xuat(features,classification_results)
    elif args.type == 3:
        # Phân tích file CSV
        print("Phân tích file CSV:", args.file)
        results= compute_weka_tree_from_csv(args.file)
        for row_index, classification in results.items():
          print(f"Dòng {row_index + 1}: {classification}")

    
if __name__ == "__main__":
    main()