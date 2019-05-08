# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

import sys, subprocess, string

def interact( G ) :
  # send      G      to   attack target

  target_in.write( '%s\n' % ( G ) ) ; target_in.flush()

  # receive ( t, r ) from attack target

  t = int( target_out.readline().strip() )
  r = int( target_out.readline().strip() )

  return ( t, r )

def attack() :
  # select a hard-coded guess ...

  G = "x"
  passwordLength = 0
  for i in range(50):
    (t, r) = interact(G)
    if(t > 0):
      print("Length found. Password length: " + str(i + 1))
      passwordLength = i + 1
      break
    G = G + 'x'

  for i in range(passwordLength):
    (t, r) = interact(G)
    currGuess = t
    for char in string.ascii_lowercase:
      temp = list(G)
      temp[i] = char
      G = "".join(temp)
      print("Testing " + str(G))
      (t, r) = interact(G)
      if(t > currGuess):
        print("Letter on position " + str(i) + " is " + char)
        break

  print("Password found. Password is: " + str(G))

if ( __name__ == '__main__' ) :
  # produce a sub-process representing the attack target

  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # construct handles to attack target standard input and output

  target_out = target.stdout
  target_in  = target.stdin

  # execute a function representing the attacker

  attack()
