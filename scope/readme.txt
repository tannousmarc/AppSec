First argument is the traces filename to use. (e.g. python attack.py
traces100.dat would use the traces found in traces100.dat)

Second argument is the max number of samples to iterate through to find
the maximum correlation (e.g. python attack.py traces100.dat 10000)
would only go through the first 10000 samples and return the maximum value out
of those. For my implementation, only going through the first 10000 samples
retrieves the correct key and is faster. Running the attack without a 
second argument defaults to iterating through all the samples.
