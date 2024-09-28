import pyshark
import binascii
import time
import ffmpeg
import os
import cv2
import subprocess
from tqdm import tqdm
import shutil
import json

def reset_folder(folder):
    if not os.path.exists(folder):
        os.mkdir(folder)
    else:
        shutil.rmtree(folder)
        os.mkdir(folder)

def get_video_duration(video_path):
    # 使用 ffprobe 获取视频时长
    command = [
        'ffprobe', 
        '-v', 'error', 
        '-select_streams', 'v:0', 
        '-show_entries', 'format=duration', 
        '-of', 'json', 
        video_path
    ]
    
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    info = json.loads(result.stdout)
    
    return float(info['format']['duration'])

def save_last_frame_ffmpeg(h264_file, output_image):
    # 使用 ffmpeg 提取最后一帧并保存为 .jpg
    # ffmpeg_command = [
    #     'ffmpeg', '-sseof', '-1', '-i', h264_file, '-vsync', 'vfr', '-q:v' '2' , '-frames:v', '1', output_image
    # ]
    duration = get_video_duration(h264_file)
    ffmpeg_command = [
        'ffmpeg', 
        '-sseof', f'-{duration}',  # 从视频结束倒数3秒开始
        '-i', h264_file,  # 输入文件
        '-vsync', 'vfr',
        '-q:v', '2',  # 图像质量（2 表示高质量，范围 1-31）
        '-frames:v', '1',  # 提取 1 帧
        output_image  # 输出文件
    ]

    subprocess.run(ffmpeg_command)
    print(f"最后一帧已通过 ffmpeg 提取并保存为: {output_image}")

def video2img(video_path,output_folder,sei_output_file_split,log_output):
    # video_path = '/Users/liugenjia/Desktop/v2x_realworld_project/Baidu/video_parse/output/output_video.mp4'
    # output_folder = '/Users/liugenjia/Desktop/v2x_realworld_project/Baidu/video_parse/output/images_from_video'

    with open(sei_output_file_split, 'r') as file:
        # 逐行读取文件，并将每行保存到列表中
        lines = [line.strip() for line in file]
    timestamps = [line.split(':')[1] for line in lines if line.startswith('SEI')]

    # 确保保存图像的文件夹存在
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # 打开视频文件
    video = cv2.VideoCapture(video_path)

    frame_number = 0

    success, frame = video.read()

    # 循环读取视频的每一帧
    while True:
        success, frame = video.read()  # 读取一帧
        if not success:
            break  # 如果没有读取到帧，则跳出循环

        # 保存帧为图像文件
        frame_filename = os.path.join(output_folder, f'{timestamps[frame_number]}.jpg')
        cv2.imwrite(frame_filename, frame)

        frame_number += 1

    # 释放视频文件
    video.release()

    with open(log_output, 'a') as f_log:
        f_log.write(f'frames write to jpg: {frame_number}')
        print(f"视频已转换为 {frame_number} 张图像，并保存在 '{output_folder}' 文件夹中。")

def extract_sei_timestamp(payload):
    """
    提取 SEI 帧中的时间戳信息
    :param payload: RTP 包的负载
    :return: 如果找到时间戳，返回时间戳；否则返回 None
    """
    sei_payload = binascii.hexlify(payload).decode('utf-8')  # 将 payload 转换为十六进制字符串
    if '06f032' in sei_payload:
        # print(f"找到 SEI 时间戳字段：06f032，在 SEI 数据中：{sei_payload}")
        # 假设时间戳紧跟在 06f032 后，可以根据你的协议解析出时间戳信息
        sei_index = sei_payload.find('06f032') + 6
        ascii_hex = sei_payload[sei_index:sei_index + 26]  # 假设时间戳是 4 字节（8 位十六进制）
        # timestamp = int(timestamp_hex, 16)  # 将时间戳从十六进制转换为整数
        # 将十六进制表示的 ASCII 转换为实际数字
        timestamp_ascii = bytes.fromhex(ascii_hex).decode('ascii')  # 转为 ASCII 字符串，例如 '172'
        timestamp_number = int(timestamp_ascii)  # 将 ASCII 字符串转换为实际数字
        # print(f"提取的时间戳数字: {timestamp_number}")
        return timestamp_number
    return None

def is_keyframe(fu_header):
    """
    判断分片是否为关键帧（IDR 帧）
    :param fu_header: FU header 字节
    :return: 如果是关键帧，返回 True；否则返回 False
    """
    nalu_type = fu_header & 0x1F  # 取 NALU 类型
    return nalu_type == 5  # NALU 类型 5 表示 IDR 帧（关键帧）

class Pcap_Parser:
    def __init__(self, pcap_file, output_dir):
        self.cap = pyshark.FileCapture(pcap_file, display_filter='rtp') # , use_json=True, include_raw=True
        for i, _ in enumerate(self.cap):
            self.total_pac = i
        self.pac_now = 0
        self.num_split = 0
        self.output_dir = output_dir
    def extract_h264_and_sei_with_timestamp(self):
        """
        Recurrently load from self.cap and skip the lost packets
        """
        while self.pac_now <= self.total_pac:
            os.makedirs(os.path.join(self.output_dir,f'split_{self.num_split}'),exist_ok=True)
            print(f'------Processing split {self.num_split}!---------')
            self.extract_h264_and_sei_with_timestamp_split()
            self.num_split += 1
        self.cap.close()

    def extract_h264_and_sei_with_timestamp_split(self):
        """
        从 RTP 包中提取 H.264 负载，确保从关键帧开始，并重组 FU-A 分片
        :param pcap_file: 包含 RTP 包的 pcap 文件路径
        :param output_h264: 输出的 H.264 文件路径
        """
        cap = self.cap
        h264_output_file = os.path.join(self.output_dir,f'split_{self.num_split}','video.h264')
        sei_output_file = os.path.join(self.output_dir,f'split_{self.num_split}','sei_timestamps.txt')
        log_output_file = os.path.join(self.output_dir,f'split_{self.num_split}','logs.txt')

        keyframe_found = False  # 标记是否找到关键帧
        current_nalu = b''  # 用于存储当前 NALU 分片的拼接数据
        sps_data = b''  # 缓存 SPS 数据
        pps_data = b''  # 缓存 PPS 数据

        num_28 = 0
        num_0 = 0
        num_6 = 0
        num_7 = 0
        num_8 = 0
        num_1 = 0
        num_write_28 = 0
        num_start_key = 0
        num_IDR = 0
        total_packets = 0
        previous_seq = None
        missing_packets = 0
        missing_times = 0
        num_before_start = 0
        num_time_stamp = 0
        num_other_type = 0

        with open(h264_output_file, 'wb') as f_out, open(sei_output_file, 'w') as sei_out, open(log_output_file, 'w') as f_log:
            for packet_id in tqdm(range(self.pac_now,self.total_pac+1)):
                packet = cap[packet_id]
                for layer in packet:
                    if layer._layer_name != 'rtp':
                        continue
                    rtp_layer = layer
                    # rtp_layer = packet.rtp
                    if not hasattr(rtp_layer, 'payload'):
                        continue
                    rtp_payload = rtp_layer.payload.binary_value
                    if len(rtp_payload) == 0:
                        print('rtp_payload==0!')
                        continue

                    # 检查是否丢帧
                    seq_num = int(rtp_layer.seq)

                    if not keyframe_found:
                        num_before_start += 1

                    total_packets += 1
                    if previous_seq is not None:
                        # 计算序列号差异
                        diff = seq_num - previous_seq
                        if diff > 1 and keyframe_found:
                            missing_packets += (diff - 1)
                            print(f"Warning: {diff - 1} packet(s) missing between sequence {previous_seq} and {seq_num}")
                            f_log.write(f"Warning: {diff - 1} packet(s) missing between sequence {previous_seq} and {seq_num}\n")
                            f_log.flush()
                            missing_times += 1
                            self.pac_now = packet_id+1
                            f_log.write(f"num_writed_NALU_28:{num_write_28}, num_time_stamp:{num_time_stamp}," + 
                                            f"num_28:{num_28}," + 
                                            f"num_6:{num_6}," + 
                                            f"num_7:{num_7}," + 
                                            f"num_1:{num_1}," + 
                                            f"num_8:{num_8}," + 
                                            f"num_0:{num_0}," + 
                                            f"num_other_type:{num_other_type}," + 
                                            f"num_IDR:{num_IDR}," + 
                                            f"num_before_start:{num_before_start}," + 
                                            f"num_recorded:{num_28+num_7+num_6+num_8+num_0+num_1+num_before_start+num_other_type}," + 
                                            f"Total packets: {total_packets}," + 
                                            f"Missing packets: {missing_packets}," + 
                                            f"Missing times: {missing_times}\n")
                            return
                    # 更新上一个序列号
                    previous_seq = seq_num

                    nalu_header = rtp_payload[0]  # 获取 FU indicator
                    nalu_type = nalu_header & 0x1F  # 提取 NALU 类型
                    forbidden_flag = nalu_header & 0x80

                    # 如果是无效的 NALU 类型，跳过
                    if nalu_type == 0:
                        if keyframe_found:
                            num_0 += 1
                        print("无效的 NALU 单元，跳过")
                    # 如果是 SPS (NALU type 7)，缓存 SPS 数据
                    elif nalu_type == 7:
                        if keyframe_found:
                            num_7 += 1
                        sps_data = b'\x00\x00\x00\x01' + rtp_payload
                        # print("缓存 SPS 帧")
                    # 如果是 PPS (NALU type 8)，缓存 PPS 数据
                    elif nalu_type == 8:
                        if keyframe_found:
                            num_8 += 1
                        pps_data = b'\x00\x00\x00\x01' + rtp_payload
                        # print("缓存 PPS 帧")
                    elif nalu_type == 5:
                        num_IDR += 1
                        keyframe_found = True
                        # 在写入关键帧之前，先写入 SPS 和 PPS 数据（如果存在）
                        if sps_data:
                            f_out.write(sps_data)
                            # print("写入 SPS 帧")
                        if pps_data:
                            f_out.write(pps_data)
                            # print("写入 PPS 帧")
                        nalu = b'\x00\x00\x00\x01' + rtp_payload
                        f_out.write(nalu)
                    # 如果遇到 SEI 帧 (NALU type 6)，检查时间戳
                    elif nalu_type == 6 and keyframe_found:
                        num_6 += 1
                        timestamp = extract_sei_timestamp(rtp_payload)
                        if timestamp:
                            num_time_stamp += 1
                            sei_out.write(f"SEI 时间戳:{timestamp}\n")
                            sei_out.flush()
                            # save_last_frame_ffmpeg(output_h264, os.path.join(images_with_time_folder,'{}.jpg'.format(timestamp)))
                    elif nalu_type == 1 and keyframe_found:
                        if current_nalu != b'':
                            print('find')
                        num_1 += 1
                        nalu = b'\x00\x00\x00\x01' + rtp_payload
                        f_out.write(nalu)
                    # 检查是否为 FU-A 分片
                    elif nalu_type == 28:
                        if keyframe_found:
                            num_28 += 1
                        fu_header = rtp_payload[1]  # 获取 FU header
                        start_bit = fu_header & 0x80  # 检查 S bit 是否为 1
                        end_bit = fu_header & 0x40  # 检查 E bit 是否为 1
                        nalu_type_fu = fu_header & 0x1F  # 原始 NALU 类型

                        # print('num_start_key:',num_start_key)
                        # print('num_writed_28:',num_write_28)
                        # 如果是分片的第一个 RTP 包
                        if start_bit:
                            if keyframe_found:
                                num_start_key += 1

                            # 检查是否为 IDR 帧（关键帧）
                            if is_keyframe(fu_header):
                                num_IDR += 1
                                if not keyframe_found:
                                    num_start_key += 1
                                keyframe_found = True
                                # print("找到关键帧，开始组装...")

                                # 在写入关键帧之前，先写入 SPS 和 PPS 数据（如果存在）
                                if sps_data:
                                    f_out.write(sps_data)
                                    # print("写入 SPS 帧")
                                if pps_data:
                                    f_out.write(pps_data)
                                    # print("写入 PPS 帧")
                            else:
                                # 如果未找到关键帧，跳过该 NALU
                                if not keyframe_found:
                                    continue

                            # 添加起始码并开始新的 NALU 数据（重新构建 NALU 头）
                            nalu_header = bytes([nalu_header & 0xE0 | nalu_type_fu])  # 重建 NALU 头
                            current_nalu = b'\x00\x00\x00\x01' + nalu_header + rtp_payload[2:]

                        # 如果是分片的中间或最后部分
                        else:
                            current_nalu += rtp_payload[2:]

                        # 如果这是最后一个分片，写入数据
                        if end_bit and keyframe_found:
                            num_write_28 += 1
                            f_out.write(current_nalu)
                            current_nalu = b''  # 重置 NALU 拼接缓冲区
                            if num_write_28 % 500==0 and num_write_28 > 0:
                                print('write {} frames'.format(num_write_28))
                                print('write {} timestamps'.format(num_time_stamp))
                                f_log.write(f'write {num_write_28} frames\n')
                                f_log.write(f'write {num_time_stamp} timestamps\n')
                                f_log.write(f"num_writed_NALU_28:{num_write_28}, num_time_stamp:{num_time_stamp}," + 
                                                f"num_28:{num_28}," + 
                                                f"num_6:{num_6}," + 
                                                f"num_7:{num_7}," + 
                                                f"num_1:{num_1}," + 
                                                f"num_8:{num_8}," + 
                                                f"num_0:{num_0}," + 
                                                f"num_other_type:{num_other_type}," + 
                                                f"num_IDR:{num_IDR}," + 
                                                f"num_before_start:{num_before_start}," + 
                                                f"num_recorded:{num_28+num_7+num_6+num_8+num_0+num_1+num_before_start+num_other_type}," + 
                                                f"Total packets: {total_packets}," + 
                                                f"Missing packets: {missing_packets}," + 
                                                f"Missing times: {missing_times}\n")
                                f_log.flush()
                    elif keyframe_found:
                        num_other_type += 1
                        
            f_log.write(f"num_writed_NALU_28:{num_write_28}, num_time_stamp:{num_time_stamp}," + 
                            f"num_28:{num_28}," + 
                            f"num_6:{num_6}," + 
                            f"num_7:{num_7}," + 
                            f"num_1:{num_1}," + 
                            f"num_8:{num_8}," + 
                            f"num_0:{num_0}," + 
                            f"num_other_type:{num_other_type}," + 
                            f"num_IDR:{num_IDR}," + 
                            f"num_before_start:{num_before_start}," + 
                            f"num_recorded:{num_28+num_7+num_6+num_8+num_0+num_1+num_before_start+num_other_type}," + 
                            f"Total packets: {total_packets}," + 
                            f"Missing packets: {missing_packets}," + 
                            f"Missing times: {missing_times}\n")
        self.pac_now = self.total_pac+1
        return

# 示例用法
# 输入：捕获的PCAP文件
pcap_file = '/Users/liugenjia/Desktop/v2x_realworld_project/Baidu/video_parse/data/172.21.173.137.pcapng'

# 输出：保存的H.264文件
output_name = 'test_0927_6'
output_dir = os.path.join('/Users/liugenjia/Desktop/v2x_realworld_project/Baidu/video_parse/output',output_name)
reset_folder(output_dir)
# reset_folder(images_with_time_folder)

## *.pcapng -> *.h264
print("=================== pcapng -> h264 + timestamp ======================")
pcap_parser = Pcap_Parser(pcap_file, output_dir)
pcap_parser.extract_h264_and_sei_with_timestamp()

print("=================== h264 -> mp4 ======================")
## *.h264 -> *.mp4
# ffmpeg.input(output_file_h264).output(output_file_mp4).run()
for split in range(pcap_parser.num_split):
    h264_file_split = os.path.join(output_dir,f'split_{split}','video.h264')
    mp4_output_file_split = os.path.join(output_dir,f'split_{split}','video.mp4')
    subprocess.run(['ffmpeg', '-i', h264_file_split, '-c:v', 'copy', mp4_output_file_split])

# ## *.mp4 -> *.jpg
print("=================== mp4 + timestamp -> jpg ======================")
for split in range(pcap_parser.num_split):
    mp4_output_file_split = os.path.join(output_dir,f'split_{split}','video.mp4')
    img_folder_split = os.path.join(output_dir,f'split_{split}','images')
    sei_output_file_split = os.path.join(output_dir,f'split_{split}','sei_timestamps.txt')
    log_output = os.path.join(output_dir,f'split_{split}','logs.txt')
    os.makedirs(img_folder_split, exist_ok=True)
    video2img(mp4_output_file_split,img_folder_split,sei_output_file_split,log_output)
