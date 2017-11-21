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

    if len(argv) == 1:
        vanilla = True
    else:
        path += argv[1]

    subprocess.call("rm results.txt", shell=True)
#    if len(path):
#        subprocess.call("rm " + path, shell=True)
#        subprocess.call("touch " + path, shell=True)

    for i in range(0, 100000):
        print("Running iter: %i" % (i))
        subprocess.call("./tests >> results.txt", shell=True)

    parse_from_loc("results.txt")

    if (not vanilla):
        parse_from_loc(path)
       
    if before_num != after_num:
        print("Unequal number of results\nBefore: %i\nAfter: %i" % (before_num, after_num))
        exit(0)

    print("Iterations: %i\nAverage Time: %f\n" % (before_num, (after_total / float(after_num)) - (before_total / float(before_num))))
    pass

if __name__ == "__main__":
    main(sys.argv)
