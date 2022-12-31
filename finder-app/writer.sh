#!/bin/sh

#Exits with return value 1 error and print statements if any of the parameters above were not specified
if [ $# -ne 2 ]
then
	echo "Required two parameters"
	exit 1
fi

WRITE_FILE=$1
WRITE_STRING=$2
WRITE_FILE_DIR_NAME="$(dirname "/tmp/aeld-data/tkuchynsky@gmail.com1.txt")"

echo "WRITE_FILE: ${WRITE_FILE}"
echo "WRITE_STRING: ${WRITE_STRING}"
echo "WRITE_FILE_DIR_NAME: ${WRITE_FILE_DIR_NAME}"

if [ ! -z "${WRITE_FILE_DIR_NAME}" ] && [ ! -d "${WRITE_FILE_DIR_NAME}" ]
then
	mkdir -p "${WRITE_FILE_DIR_NAME}"
	if [ $? -ne 0 ]
	then
		echo "Cannot create directory ${WRITE_FILE_DIR_NAME }"
    	exit 1
	fi
fi

echo ${WRITE_STRING} > ${WRITE_FILE} 
if [ $? -ne 0 ]
then
	echo "Cannot modify file ${WRITE_FILE}"
	exit 1
fi