#!/bin/sh

rm 'Alice_out.txt'&
rm 'Bob_out.txt'&
rm 'file_rcv.txt'
wait

python Bob.py &
sleep 1
python Alice.py &
wait
python Check.py

