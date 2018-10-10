#!/bin/sh
set -e
for c in $*; do
	gcc -Wall -Werror -ansi -pedantic -O2 $c
	./a.out
	g++ -Wall -Werror -O2 $c
	./a.out
done
