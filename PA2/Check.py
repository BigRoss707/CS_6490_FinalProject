import time

file1 = open('file.txt').read()

file2 = open('file_rcv.txt').read()



if file1 == file2:
    print('Sent and received file matched')

else:
    print('Sent and received file did not match')
