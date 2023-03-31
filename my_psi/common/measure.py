import subprocess
import threading
from random import seed, randint
from datetime import datetime
from subprocess import Popen, PIPE
from time import sleep
from os import remove, killpg, getpgid
from os.path import exists
from signal import SIGTERM
import re

def read_and_delete_file(fname):
    f = open(fname, 'r')
    line1 = f.readline()
    time = line1.split()[1]
    line2 = f.readline()
    cpu_time = line2.split()[1]
    line3 = f.readline()
    comp = line3.split()[1]
    f.close()
    remove(fname)
    return time, cpu_time, comp

def read_stdout(s):
    lines = s.split(separator='\n')
    result = 0
    for line in lines:
        if line.startswith("Total Sent /Rcv"):
            comms = re.findall(r'\d+', line)
            if len(comms) == 2:
                result += int(comms[0])
    return result

def experiment(num_eles, num_bins, out, srv_seed=10, cli_seed=100, num_bits=16):
    # subprocess.run("./my_psi", "-r", 0, "-n", num_eles, "-b", num_bits, "-m", num_bins, "-s", seed)
    timeout_s = 60*5

    try:
        process0 = Popen([str(x) for x in ['./my_psi', "-r", 0, "-n", num_eles, "-b", num_bits, "-m", num_bins, "-s", srv_seed]], stdout=PIPE, stderr=PIPE)
        process1 = Popen([str(x) for x in ['./my_psi', "-r", 1, "-n", num_eles, "-b", num_bits, "-m", num_bins, "-s", cli_seed]], stdout=PIPE, stderr=PIPE)
        process0.wait(timeout=timeout_s)
        process1.wait(timeout=10)
    except subprocess.TimeoutExpired:
        killpg(getpgid(process0.pid), SIGTERM)
        killpg(getpgid(process1.pid), SIGTERM)
        raise
    
    print("experiment successfully executed.")

    lines0 = process0.stdout.read()
    lines1 = process1.stdout.read()

    srv_comm = read_stdout(line0)
    cli_comm = read_stdout(line1)

    srv_time, srv_cpu_time, srv_comp = read_and_delete_file(f"0{srv_seed}.txt")
    cli_time, cli_cpu_time, cli_comp = read_and_delete_file(f"1{cli_seed}.txt")

    time = round((float(srv_time) + float(cli_time)) / 2, 4)

    print(f"neles: {num_eles},\tnbins: {num_bins},\ttime: {time},\tsrv cpu time: {srv_cpu_time},\tcli cpu time: {cli_cpu_time}\tcomp: {srv_comp}")

    out.write(f"{num_eles}, {num_bins}, {time}, {srv_cpu_time}, {cli_cpu_time}, {srv_comp}, {srv_comm + cli_comm}\n")

seed(datetime.now())

count=1

run_num=0
while (exists(f"run{run_num}.csv")):
    run_num += 1

out_filename = f"run{run_num}.csv"

outfile = open(out_filename, 'w')
outfile.close()

runs = 1
num_eles_l = [1000,1500,2000]
num_bins_l = [2,4,8,16]
num_bits = 16

for run in range(1, runs+1):

    print(f"start measuring run #{run}")
    
    for num_eles in num_eles_l:
        for num_bins in num_bins_l:
            outfile = open(out_filename, 'a')
            s_seed = randint(1,500) * 10 + count
            c_seed = randint(501, 1000) * 10 + count
            print (f"#{run}: server seed {s_seed} and client seed {c_seed}")
            sleep(1)
            try:
                experiment(num_eles, num_bins, outfile, srv_seed=s_seed, cli_seed=c_seed, num_bits=num_bits)
            except:
                print(f"An exception occurred with server seed {s_seed} and client seed {c_seed}")
            outfile.close()
            count += 1