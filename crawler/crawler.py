#!/usr/bin/env python

import requests, time

def request(url):
    try:
        return requests.get("http://" + url)
    except (requests.exceptions.ConnectionError, requests.exceptions.InvalidURL):
        pass

def gen_url(sub, url):
    sub = sub.rstrip()
    if sub:
        return sub + "." + url
    else:
        return url

def unique_filter(file):
    with open(file, "r") as from_to:
        with open("new-" + file, "w") as to_from:
            list = []
            for f in from_to:
                list.append(f)
            list = set(list)
            to_from.write("".join(list))

measure = 0
count = 0
# point = 0
# subdom_len = 114552
# dir_len = 1273943*1
# iter_count = subdom_len * dir_len

target_url = "192.168.0.100/mutillidae"
# print("Max iterations: " + str(iter_count) + " / Min iterations: " + str(subdom_len))
with open("result_urls.txt", mode="w") as result_urls_file:
    with open("subdomains-small.txt", mode="r") as subdomains_file:
        start = time.time()
        for subdomain in subdomains_file:
            sub_url = gen_url(subdomain, target_url)
            response = request(sub_url)
            count += 1
            measure = time.time() - start
            # point += 1
            # print("Time passed: " + str(measure) + " (sec) / " + str((100*point)/subdom_len) + "% is done.")
            if response:
                result_urls_file.write(sub_url + "\n")
                result_urls_file.flush()
                with open("directories-small.txt", mode="r") as directories_file:
                    for directory in directories_file:
                        dir_url = sub_url + "/" + directory.rstrip()
                        response = request(dir_url)
                        count += 1
                        if response:
                            result_urls_file.write(dir_url + "\n")
                            result_urls_file.flush()
                            # for second_directory in directories_file:
                            #     second_directory = second_directory.rstrip()
                            #     second_dir_url = dir_url + "/" + second_directory
                            #     response = request(second_dir_url)
                            #     count += 1
                            #     if response:
                            #         result_urls_file.write(second_dir_url + "\n")
                            #         result_urls_file.flush()
                            #         for third_directory in directories_file:
                            #             third_directory = third_directory.rstrip()
                            #             third_dir_url = second_dir_url + "/" + third_directory
                            #             response = request(third_dir_url)
                            #             count += 1
                            #             if response:
                            #                 result_urls_file.write(third_dir_url + "\n")
                            #                 result_urls_file.flush()
                            #                 for fourth_directory in directories_file:
                            #                     fourth_directory = fourth_directory.rstrip()
                            #                     fourth_dir_url = third_dir_url + "/" + fourth_directory
                            #                     response = request(fourth_dir_url)
                            #                     count += 1
                            #                     if response:
                            #                         result_urls_file.write(fourth_dir_url + "\n")
                            #                         result_urls_file.flush()

print("\r\nDone. All iterations: " + str(count) + " / Time: " + str(measure))
