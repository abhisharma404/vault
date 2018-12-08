import scanner
import json

class LFI():
    def __init__(self,url,payload_path)
    self.url=url
    with open(payload_path, 'r') as f:
        self.payload_data = json.load(f)
    

    def startScanner():
        engine = scanner.Scanner(url, self.payload_data)
        engine.scan()