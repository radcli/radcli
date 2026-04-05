#!/bin/bash
# Common utilities for radcli tests.

have_port_finder() {
	for file in $(which ss 2> /dev/null) /*bin/ss /usr/*bin/ss /usr/local/*bin/ss;do
		if test -x "$file";then
			PFCMD="$file";return 0
		fi
	done

	if test -z "$PFCMD";then
	for file in $(which netstat 2> /dev/null) /bin/netstat /usr/bin/netstat /usr/local/bin/netstat;do
		if test -x "$file";then
			PFCMD="$file";return 0
		fi
	done
	fi

	if test -z "$PFCMD";then
		echo "neither ss nor netstat found"
		exit 1
	fi
}

check_if_port_in_use() {
	local PORT="$1"
	local PFCMD; have_port_finder
	$PFCMD -an 2>/dev/null|grep "[\:\.]$PORT" >/dev/null 2>&1
}

# run_test DESC CMD [expect_fail]
# Runs CMD, prints its output indented under a [ RUN ] / [ OK ] / [ FAIL ] banner.
# Pass a non-empty third argument when a non-zero exit code is the expected outcome.
# Returns 1 on unexpected result, 0 otherwise.  Output is captured in $TMPFILE.
run_test() {
	local desc="$1"
	local expect_fail="$3"

	printf "\n[ RUN  ] %s\n" "$desc"
	printf "         \$ %s\n" "$2"

	eval "$2" >$TMPFILE 2>&1
	local rc=$?

	if test -s $TMPFILE; then
		sed 's/^/         | /' $TMPFILE
	fi

	if test -n "$expect_fail"; then
		if test $rc = 0; then
			printf "[ FAIL ] %s (expected failure, got success)\n" "$desc"
			return 1
		fi
	else
		if test $rc != 0; then
			printf "[ FAIL ] %s (exit code %d)\n" "$desc" "$rc"
			return 1
		fi
	fi

	printf "[  OK  ] %s\n" "$desc"
	return 0
}

# Evaluate this snippet to set PORT to a random unused port number (2000-65000).
# Example: eval "$GETPORT"
GETPORT='
    rc=0
    unset myrandom
    while test $rc = 0; do
        if test -n "$RANDOM"; then myrandom=$(($RANDOM + $RANDOM)); fi
        if test -z "$myrandom"; then myrandom=$(date +%N | sed s/^0*//); fi
        if test -z "$myrandom"; then myrandom=0; fi
        PORT="$(((($$<<15)|$myrandom) % 63001 + 2000))"
        check_if_port_in_use $PORT;rc=$?
    done
'
