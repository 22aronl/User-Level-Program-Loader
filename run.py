import subprocess
import time
import sys

var1, var2 = sys.stdin.readline().strip().split()
start = time.time()

subprocess.run([var1, var2])

end = time.time()
duration = end - start
duration_micro = int(duration * 1000000)

print(f"Execution time: {duration_micro} microseconds")