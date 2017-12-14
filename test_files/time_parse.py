import sys
import subprocess
from time import sleep

before_total = 0
before_num = 0
after_total = 0
after_num = 0
vanilla = False
path = ""

def parse_from_loc(path):
    global before_total
    global before_num
    global after_total
    global after_num

    with open(path, 'r') as f:
        print("Parsing")
        for line in f:
            if "Before" in line:
                #handle before
                var_par = line.split(":")
                before_total += float(var_par[-1].replace(" ", ""))
                before_num += 1
            elif "After" in line:
                #handle after
                var_par = line.split(":")
                after_total += float(var_par[-1].replace(" ", ""))
                after_num += 1
    return 

def main(argv):
    global before_total
    global before_num
    global after_total
    global after_num
    global vanilla
    global path

    py_iter = 0
    c_iter = 0
    last_iter = 0
    iterations = 0
    test_val = -1

    test_dict = {"socket": 0, "connect": 2, "listen": 4, "bind": 6, "data": 8} 

    if len(argv) < 3:
        print("usage: python time_parse.py <test> <iterations>")
        exit(0)
    
    test = sys.argv[1]
    iterations = int(sys.argv[2])
    if iterations < 1:
        print("invalid iterations")
        exit(0)
    if test not in test_dict.keys():
        print("invalid test")
        exit(0)
    test_val = test_dict[test]   

    if iterations < 100:
        c_iter = iterations
    else:
        c_iter = 100
        py_iter = (iterations // 100)
        last_iter = iterations % 100

    for i in range(0, 2):
        subprocess.call("rm results.txt", shell=True)
        before_total = 0
        before_num = 0
        after_total = 0
        after_num = 0
        for j in range (0, py_iter + 1):
            print("Running iter: %i" % (j))
            subprocess.call("./tests %i %i >> results.txt" % ((test_val + i), (c_iter if ((j + 1) != py_iter) else last_iter)), shell=True)
        parse_from_loc("results.txt")

        if before_num != after_num:
            print("Unequal number of results\nBefore: %i\nAfter: %i" % (before_num, after_num))
            exit(0)
        if before_num == 0:
            print("No results found")
            exit(0)

        print("Iterations: %i\nAverage Time %s: %f\n" % (before_num, "Baseline" if not i else "Benchmark", (after_total / float(after_num)) - (before_total / float(before_num))))

if __name__ == "__main__":
    main(sys.argv)
