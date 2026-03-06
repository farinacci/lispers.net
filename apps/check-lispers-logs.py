#!/usr/bin/env python

#
# check-lispers-logs
#
# Search all logs/*log files in lispers.net directory for errors and tracebacks.
# Ignore the known cheroot SSL socket error in lisp-core.log. Display all other
# errors, warnings, and exceptions found in any log file.
#

import os
import sys
import glob

def find_cheroot_error_end(lines, index):
    #
    # Starting from index, find the end of the cheroot socket error traceback.
    # Returns the number of lines to skip (0 if not a cheroot error).
    #
    if (index >= len(lines)): return(0)

    line = (lines[index])

    #
    # Check if this is the start of the cheroot socket error.
    #
    if ("Exception in thread Thread" not in line): return(0)

    #
    # Look ahead to confirm this is the cheroot socket error.
    #
    lookahead = (" ".join(lines[index:min(index+15, len(lines))]))
    if ("_socket.socket" not in lookahead and \
        "_loopback_for_cert_thread" not in lookahead):
        return(0)
    #endif

    #
    # Skip forward until we find the next log entry (starts with timestamp).
    # Cheroot error blocks are typically 15-20 lines.
    #
    skip_count = (0)
    for i in range(index, min(index + 25, len(lines))):
        skip_count = (skip_count + 1)

        #
        # Check if we've reached the end of this traceback (next log line).
        # Log lines start with timestamp like "03/06/26 HH:MM:SS".
        #
        if (i > index and len(lines[i]) > 0):
            if (lines[i][0].isdigit() and ":" in lines[i]):
                return(skip_count - 1)
            #endif
        #endif
    #endfor

    return(skip_count)
#enddef

def filter_logs():
    #
    # Find all log files and search for errors, filtering out cheroot socket error.
    #
    log_dir = ("./logs")
    if (not os.path.isdir(log_dir)):
        print("Error: logs directory not found")
        return(1)
    #endif

    log_files = (glob.glob(os.path.join(log_dir, "*.log")))
    if (not log_files):
        print("No log files found in ./logs")
        return(0)
    #endif

    error_patterns = (
        "Error",
        "error",
        "Exception",
        "Traceback",
        "CRITICAL",
        "WARNING",
        "WARN"
    )

    total_errors = (0)

    for log_file in sorted(log_files):
        try:
            with open(log_file, 'r') as f:
                lines = (f.readlines())
            #endtry

            file_errors = (0)
            skip_next = (0)
            in_traceback = (False)
            error_counted = (False)

            for i, line in enumerate(lines):
                #
                # Skip lines we've already filtered.
                #
                if (skip_next > 0):
                    skip_next = (skip_next - 1)
                    continue
                #endif

                #
                # For lisp-core.log, check if this is the cheroot socket error.
                #
                if ("lisp-core.log" in log_file):
                    skip_count = (find_cheroot_error_end(lines, i))
                    if (skip_count > 0):
                        skip_next = (skip_count)
                        in_traceback = (False)
                        error_counted = (False)
                        continue
                    #endif
                #endif

                #
                # Check if this line starts a new error/traceback block.
                #
                is_error_start = ("Exception in thread" in line)

                if (is_error_start):
                    in_traceback = (True)
                    error_counted = (False)
                #endif

                #
                # Check if this line contains an error pattern.
                #
                has_error = (any(pattern in line for pattern in error_patterns))

                if (has_error):
                    #
                    # For "Exception in thread" lines, count once per exception.
                    # For "Traceback" lines that are part of an exception, don't count.
                    #
                    if ("Exception in thread" in line and not error_counted):
                        #
                        # This is a new exception, count it.
                        #
                        if (file_errors == 0):
                            print("\n" + "="*70)
                            print("File: " + log_file)
                            print("="*70)
                        #endif

                        print(line.rstrip())
                        file_errors = (file_errors + 1)
                        total_errors = (total_errors + 1)
                        error_counted = (True)
                    elif ("Traceback" in line and in_traceback):
                        #
                        # This is part of an exception traceback, just print.
                        #
                        print(line.rstrip())
                    elif (not in_traceback):
                        #
                        # Standalone error (not in traceback), count it.
                        #
                        if (file_errors == 0):
                            print("\n" + "="*70)
                            print("File: " + log_file)
                            print("="*70)
                        #endif

                        print(line.rstrip())
                        file_errors = (file_errors + 1)
                        total_errors = (total_errors + 1)
                    else:
                        #
                        # Error line within traceback, just print.
                        #
                        print(line.rstrip())
                    #endif
            #endfor
        except (IOError) as e:
            print("Error reading " + log_file + ": " + str(e))
        #endtry
    #endfor

    #
    # Summary.
    #
    print("\n" + "="*70)
    if (total_errors == 0):
        print("No errors found (cheroot socket errors filtered)")
    else:
        print("Total errors found: " + str(total_errors))
    #endif
    print("="*70)

    return(0)
#enddef

#
# Main entry point.
#
if (__name__ == "__main__"):
    sys.exit(filter_logs())
#endif
