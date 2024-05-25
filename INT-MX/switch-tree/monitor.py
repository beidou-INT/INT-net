import json
import re
import sys
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests

class TailFileHandler(FileSystemEventHandler):
    def __init__(self, file_path):
        self.file_path = file_path
        self.previous_size = 0

    def parse_scapy_string(self, s):
        def underscorize_to_camelcase(s):
            # 下划线转驼峰
            parts = s.split('_')
            return parts[0] + ''.join(word.capitalize() for word in parts[1:])
        
        def trans_key(s):
            dic = {
                'copy_flag': 'copyFlag',
                'traceid': 'traceId',
                'timestamp': 'timebias',
                'swid': 'dpid'
            }
            if s in dic.keys():
                return dic[s]
            return s

        # 使用正则表达式匹配键值对
        matches = re.findall(r'(\w+)=([^,\[\]>\s]+)', s)
        
        # 将匹配结果转换为字典
        parsed_dict = {}
        for key, value in matches:
            key = trans_key(key)
            parsed_dict[key] = value
        
        return parsed_dict

    def on_modified(self, event):
        if event.src_path == self.file_path and event.event_type == 'modified':
            current_size = os.path.getsize(self.file_path)
            if current_size > self.previous_size:
                with open(self.file_path, 'r') as f:
                    f.seek(self.previous_size)
                    new_data = f.read(current_size - self.previous_size)
                    rawStrs = new_data.split('==================================================')
                    pkts = []
                    for rawStr in rawStrs:
                        if len(rawStr.strip())==0:
                            continue
                        tmp = rawStr.split('----------------------------------------------------------')
                        hex = tmp[0]
                        ip_options = tmp[1]

                        pkt = self.parse_scapy_string(ip_options)
                        pkt['content'] = hex

                        pkts.append(pkt)
                    self.upload(pkts)
                self.previous_size = current_size

    def upload(self, pkts):
        url = 'http://192.168.31.80:10615/package/addINTPackages'
        response  = requests.post(
            url, 
            data=json.dumps(pkts), 
            headers = {"content-type":"application/json"}
        )
        if response.status_code == 200:
            # 请求成功，可以处理响应内容
            print("上传成功")
        else:
            print(f"请求失败，状态码：{response.status_code}, 信息为: {response.text}")
        sys.stdout.flush()

if __name__ == "__main__":
    path_to_watch = './collect.log'  # 替换为你要监控的文本文件的完整路径
    handler = TailFileHandler(path_to_watch)

    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(path_to_watch), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()