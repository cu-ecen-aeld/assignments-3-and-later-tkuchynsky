#!/bin/sh

#Accepts the following runtime arguments: the first argument is a path to a directory on the filesystem, 
#referred to below as filesdir; the second argument is a text string which will be searched within these files, referred to below as searchstr

#Exits with return value 1 error and print statements if any of the parameters above were not specified
if [ $# -ne 2 ]
then
	echo "Required two parameters"
	exit 1
fi

DIR_NAME=$1
MATCHING_STRING=$2

#Exits with return value 1 error and print statements if filesdir does not represent a directory on the filesystem
if [ ! -d "${DIR_NAME}" ]
then
	echo "Derectory ${DIR_NAME} is not found"
	exit 1
fi

NUMBER_OF_FILES="$(find "${DIR_NAME}" -type f | wc -l)"
NUMBER_OF_MATCHING_LINES="$(grep -r "${MATCHING_STRING}" "${DIR_NAME}" | wc -l)"

#Prints a message "The number of files are X and the number of matching lines are Y" where X is the number of files in the directory 
#and all subdirectories and Y is the number of matching lines found in respective files.
echo "The number of files are ${NUMBER_OF_FILES} and the number of matching lines are ${NUMBER_OF_MATCHING_LINES}"