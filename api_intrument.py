'''
Author: Kevin Yuan
Date: 2022-08-18 15:17:05
LastEditTime: 2022-11-07 13:55:27
LastEditors: Kevin Yuan
Description: 
FilePath: \APLC2.0_DataCheckc:\Program Files\Python310\Lib\api_intrument.py
'''


import os
import re
import lime
import inspect
from datetime import datetime


LOG_LEVEL_INFO = 0
LOG_LEVEL_WARN = 1
LOG_LEVEL_ERROR = 2
LOG_LEVEL_DEBUG = 3

LOG_LEVEL_DIC = {
    LOG_LEVEL_INFO:     "INFO",
    LOG_LEVEL_WARN:     "WARN",
    LOG_LEVEL_ERROR:    "ERROR",
    LOG_LEVEL_DEBUG:    "DEBUG",
}


class tester:
    def __init__(self, ip, log_name, timeout=5000) -> None:
        self.log_name = log_name
        self.conn = None
        self.ip = ip
        if lime.opt == None or self.conn == None:
            lime.initLime()

            try:
                self.conn = lime.connect(ip)
                self.conn.timeout = timeout
                self.WriteLog(f"Connected to tester {ip}")
            except:
                self.WriteLog(f"Failed to connect tester {ip}")
                self.conn = None


    def WriteLog(self,content, caller=None, level=LOG_LEVEL_INFO, in_log=True, show_console=True):
        log_level = f"[{LOG_LEVEL_DIC[level]}]"
        caller = inspect.stack()[1][3] if caller == None else caller
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        content = f"{stamp} {log_level} [{self.ip}]\t{content}"
        
        if in_log and len(self.log_name) > 0:
            temp = content + "\n" if content[-1] != "\n" else content
            with open(self.log_name, "a") as f:
                f.writelines(temp)

        if show_console:
            print(content)


    def Disconnect(self):
        if self.conn != None:
            self.conn.disconnect()


    def Send(self, cmd:str):
        self.WriteLog(f"--> {cmd}")
        self.conn.scpi_exec(cmd)

    def Query(self, cmd:str, time_limit=3):
        duration = datetime.now()
        
        self.WriteLog(f"--> {cmd}")
        res = self.conn.queryStr(cmd)
        self.WriteLog(f"<-- {res}")
        
        duration = (datetime.now() - duration).total_seconds()
        if duration > time_limit:
            self.WriteLog(f"{duration:.3f}s for {cmd}", level=LOG_LEVEL_ERROR)

        return res

    def QueryList(self, cmd:str, sym=",", time_limit=3):
        self.WriteLog(f"--> {cmd}")
        res = self.conn.queryStr(cmd).split(sym)
        for i,r in enumerate(res, start=0):
            self.WriteLog(f"<-- [{i}] {r}")

        return res

    def QueryStatus(self, check_cmd="*WAI;ERR:ALL?", time_limit=3):        
        duration = datetime.now()
        res = self.QueryList("*WAI;ERR:ALL?",sym="\",")
        duration = (datetime.now() - duration).total_seconds()
        if duration > time_limit:
            self.WriteLog(f"{duration:.3f}s for {check_cmd}", level=LOG_LEVEL_ERROR)
        return res

    def SendAndQuery(self, cmd:str):
        self.Send(cmd)
        self.QueryStatus(cmd)

    def QueryInt(self, cmd:str):
        temp = self.Query(cmd).split(",")
        res = int(temp[0]) if len(temp) > 0 else -999
        return res

    def QuerySeqTimeStamp(self):
        cmd = "SYS;FORM:READ:DATA ASC;SEQ:EXEC:TST?"
        self.WriteLog(f"--> {cmd}")
        byarray = self.conn.query0d(cmd)
        res = byarray.decode("utf-8").split("\n")[:-1]
        for i,r in enumerate(res, start=0):
            self.WriteLog(f"<-- [{i}] {r}")

    def ExecSequence(self, cmd:str):
        res = self.Query(f"SYS;SEQ:EXEC:IMM:HSN? \"SEQ:EXEC:TST:STAT ON;{cmd}\"")
        self.QuerySeqTimeStamp()
        return res


    def CheckBaseInfo(self):
        if not self.conn:
            self.WriteLog("No tester connect")
            return
        
        idn_info = self.QueryList("SYS;*IDN?")
        sys_midn = self.QueryList("SYS;MIDN?")
        bp_midn  = self.QueryList("BP;MIDN?")
        mac_info = self.QueryList("SYS;SOCK:MAC?")
        
        self.WriteLog(f"SN:              {idn_info[2]}")
        self.WriteLog(f"Firmware Ver:    {idn_info[3]}")
        self.WriteLog(f"OS Ver:          {sys_midn[4][4:]}")
        self.WriteLog(f"BIOS Ver:        {sys_midn[7][3:]}")
        self.WriteLog(f"PN:              {sys_midn[8][3:]}")
        self.WriteLog(f"Product Name:    {bp_midn[4][4:]}")
        self.WriteLog(f"Hardware Ver:    {bp_midn[5][6:]}")
        self.WriteLog(f"Cal. Date:       {bp_midn[6][3:]}")
        self.WriteLog(f"Configure Ver:   {bp_midn[7][3:]}")
        self.WriteLog(f"Driver Ver:      {bp_midn[11][3:]}")
        self.WriteLog(f"MAC:             {mac_info[0][1:-1]}")
        
        temp = self.Query("MMEM:CAT?")
        space_info = temp.split(",", 2)
        space_use_MB = float(space_info[0]) / 1048576
        space_rem_MB = float(space_info[1]) / 1048576
        self.WriteLog(f"Space used {space_use_MB:.3f}MB, left {space_rem_MB:.3f}MB")
        
        
        if space_rem_MB < 1024:
            dirs_info_raw = re.findall(r"\"(.*?)\"", temp)
            dirs_info = {}
            for i in dirs_info_raw:
                dir_info = i.split(",")
                t = dir_info[1] if dir_info[1] else "FILE"
                dirs_info[dir_info[0]] = (t, dir_info[2])

            max_file_name = max([len(x) for x in dirs_info])
            self.WriteLog("Name" + (max_file_name - 4) * " " + "   Type   Size")
            for i in dirs_info:
                dir_info = f"{i}" + (max_file_name - len(i)) * " " + "   "
                dir_info += f"{dirs_info[i][0]}" + (4 - len(dirs_info[i][0])) * " " + "   "
                dir_info += f"{dirs_info[i][1]}"
                self.WriteLog(dir_info)


    def DownloadFile(self, file_name, file_dir, dst_dir):
        if not os.path.isdir(dst_dir):
            os.makedirs(dst_dir)

        self.SendAndQuery(f"SYS;MMEM:CDIR \"\\{file_dir}\"")

        # check file exist
        exist = self.QueryInt(f"SYS;MMEM:FEX? \"{file_name}\"")
        if exist == 1:
            file_path = os.path.join(dst_dir, file_name)
            ext = os.path.splitext(file_name)[1]
            if ext == ".iqvsa":
                self.conn.setBinAsChar(False)
                fileContent = self.conn.query0d(f"SYS;MMEM:DATA? \"{file_name}\"")
                wfile = open(file_path, "wb")
            else:
                self.conn.setBinAsChar(True)
                self.Send(f"SYS;MMEM:FOP \"{file_name}\",\"r\"")
                fileContent = self.Query('SYS;MMEM:FRE?')
                self.Send('SYS;MMEM:FCL')
                wfile = open(file_path, "w")

            wfile.write(fileContent)
            wfile.flush()
            wfile.close()
        else:
            self.WriteLog(f"{file_name} not found", level=LOG_LEVEL_ERROR)
        
        self.SendAndQuery(f"SYS;MMEM:CDIR \"\\\"")

