# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of
# which can be found via http://creativecommons.org (and should be included as
# LICENSE.txt within the associated archive or repository).

import numpy as np
import struct, sys, time
from multiprocessing import Pool
from contextlib import closing
import picoscope.ps2000a as ps2000a, sys, time
import matplotlib.pyplot as plt

import argparse, binascii, select, serial, socket, sys, os

def board_open() :
  fd = serial.Serial( port = '/dev/scale-board', baudrate = 9600, bytesize = serial.EIGHTBITS, parity = serial.PARITY_NONE, stopbits = serial.STOPBITS_ONE, timeout = None )
  time.sleep(1)
  return fd

def board_close( fd ) :
  fd.close()


def board_rdln( fd    ) :
  r = ''

  while( True ):
    t = fd.read( 1 )

    if( t == '\x0D' ) :
      break
    else:
      r += t

  return r

def board_wrln( fd, x ) :
  fd.write( x + '\x0D' ) ; fd.flush()


PS2000A_RATIO_MODE_NONE      = 0 # Section 3.18.1
PS2000A_RATIO_MODE_AGGREGATE = 1 # Section 3.18.1
PS2000A_RATIO_MODE_DECIMATE  = 2 # Section 3.18.1
PS2000A_RATIO_MODE_AVERAGE   = 4 # Section 3.18.1

def get_traces(numTraces):
  try :


    scope = ps2000a.PS2000a()

    global scope_adc_max, scope_adc_min
    scope_adc_min = scope.getMinValue()
    scope_adc_max = scope.getMaxValue()

    scope.setChannel( channel = 'A', enabled = True, coupling = 'DC', VRange =   5.0E-0 )
    scope_range_chan_a =   5.0e-0
    scope.setChannel( channel = 'B', enabled = True, coupling = 'DC', VRange = 500.0E-3 )
    scope_range_chan_b = 500.0e-3

    ( _, samples, samples_max ) = scope.setSamplingInterval( 4.0E-9, 4.0E-4 )

    scope.setSimpleTrigger( 'A', threshold_V = 2.0E-0, direction = 'Rising', timeout_ms = 0 )

    traces = numTraces
    M = np.zeros((traces, 16), dtype = np.uint8)
    C = np.zeros((traces, 16), dtype = np.uint8)
    T = np.zeros((traces, samples), dtype = np.int16)

    fd = board_open()

    print("Acquiring traces")

    for i in range(traces):
        scope.runBlock()

        plaintext = "10:" + os.urandom(16).encode("hex")
        board_wrln(fd, "01:01")
        board_wrln(fd, plaintext)
        board_wrln(fd, "10:0000000000000000")
        ciphertext = board_rdln(fd)

        while ( not scope.isReady() ) : time.sleep( 1 )

        truncatedPlaintext = plaintext[3:]
        truncatedCiphertext = ciphertext[3:]

        for j in range(0, 32, 2):
            M[i, j/2] = int(truncatedPlaintext[j] + truncatedPlaintext[j+1], 16)
            C[i, j/2] = int(truncatedCiphertext[j] + truncatedCiphertext[j+1], 16)

        ( B, _, _ ) = scope.getDataRaw( channel = 'B', numSamples = samples, downSampleMode = PS2000A_RATIO_MODE_NONE )

        T[i] = B
        scope.stop()

    board_close(fd)
    scope.close()

    return traces, samples, M, C, T

  except Exception as e :
    raise e

def corr2_coeff(A,B):
    np.seterr(divide='ignore', invalid='ignore')
    A_mA = A - A.mean(1)[:,None]
    B_mB = B - B.mean(1)[:,None]

    # Sum of squares across rows
    ssA = (A_mA**2).sum(1);
    ssB = (B_mB**2).sum(1);

    # Finally get corr coeff
    return np.dot(A_mA,B_mB.T)/np.sqrt(np.dot(ssA[:,None],ssB[None]))

def singleByteAttack(currByte):
    print("Attacking byte " + str(currByte))
    H = np.zeros(shape=(t, 256))
    for i in range(0, t):
        for j in range(0, 256):
            H[i][j] = bin(rijndael_sbox[M[i][currByte] ^ j]).count('1')

    res = corr2_coeff(np.transpose(H), np.transpose(T))
    max = -1
    byteValue = -1


    for x in range(0,256):
        for y in range(0, s):
            if(abs(res[x][y]) > max):
                 max = abs(res[x][y])
                 byteValue = x
    return hex(byteValue)

def attack( argc, argv ):
    timeA = time.time()
    numTraces = 100


    parser = argparse.ArgumentParser()

    parser.add_argument( '--processes',   dest = 'processes',   type =  str, action = 'store', nargs='?', default=8)
    parser.add_argument( '--traces',   dest = 'traces',   type =  str, action = 'store', nargs='?', default=1000  )
    parser.add_argument( '--trimmedSamples',   dest = 'trimmedSamples',   type =  str, action = 'store', nargs='?', default=100000 )

    args = parser.parse_args()
    numTraces = int(args.traces)

    global t, s, M, C, T
    t, s, M, C, T = get_traces(numTraces)

    processes = int(args.processes)
    s = int(args.trimmedSamples)


    global rijndael_sbox
    rijndael_sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
    timeB = time.time()
    print("Traces gathered in " + str(timeB - timeA) + " seconds")
    expected = ['0x06', '0x5C', '0x86', '0x80', '0xA0', '0xE9', '0x5F', '0x8C', '0xDC', '0xF2', '0xFB', '0xC5', '0xD8', '0xCE', '0xF2', '0xF6']

    with closing(Pool(processes = processes)) as pool:
      results = pool.map(singleByteAttack, range(0, 16))
      print("")
      print("Recovered key")
      print("=============")
      print(results)
      print("Expected key")
      print("=============")
      print(expected)
      pool.terminate()
    timeC = time.time()
    print("")
    print("Attack terminated in " + str(timeC - timeB) + " seconds")



if ( __name__ == '__main__' ) :
  attack( len( sys.argv ), sys.argv )
