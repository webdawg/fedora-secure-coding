#!/bin/bash

validate () {
    local value="$1"
    #+ Shell Input_Validation
    if [[ $value =~ ^-?[0-9]+$ ]] ; then
	echo value is an integer
    else
	echo "value is not an integer" 1>&2
	exit 1
    fi
    #-
}

check_validate () {
    local value="$1"
    local expected="$2"
    (
	validate "$value"
    ) >/dev/null 2>/dev/null
    result="$?"
    if ! test "$result" -eq "$expected" ; then
	echo "failure: validate \"$value\" $expected -> got $result"
    fi
}

check_validate "" 1
check_validate "0" 0
check_validate "9" 0
check_validate "-0" 0
check_validate "-9" 0
check_validate "10" 0
check_validate "19" 0
check_validate "-10" 0
check_validate "-19" 0
check_validate " 0" 1
check_validate "--1" 1
check_validate "1-" 1
check_validate "1 || 0" 1
check_validate '1$(kill -9 $PPID)' 1
check_validate '2$(id)' 1
