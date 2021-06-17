#
# lispers.net .cshrc file that runs under /root in docker container.
#

#
# Quick linux OS related shortcuts.
#
alias sa     'source /root/.cshrc'
alias psg    'ps auxww | egrep \!* | egrep -v grep'
alias py     'python -O -u'
alias py3    'python3.8 -O -u'
alias ll     'ls -lag'
alias ld     'ls -lgd'
alias h      'history'            
alias t      'nice top -d 1'
alias aptget 'sudo apt-get -o Acquire::ForceIPv4=true install'
alias td     'sudo tcpdump -i any -n'    
alias tr     'traceroute'

#
# Handy restful calls to lispers.net.
#
alias ver    'curl --silent --insecure -u root: https://localhost:8080/lisp/api/data/system | jq .'
alias mcache  'curl --silent --insecure -u root: https://localhost:8080/lisp/api/data/map-cache | jq .'
alias db     'curl --silent --insecure -u root: https://localhost:8080/lisp/api/data/database-mapping | jq .'
alias packets './mc root@localhost | egrep "EID|packet-count"'

#
# Shortcut to command-line utilities.
#
alias lig         './lig'
alias rig         './rig'
alias ltr         './ltr'
alias mc          './mc'
alias pslisp      './pslisp'
alias log-packets './log-packets'
alias rl          './RL'
alias sl          './STOP-LISP'

#------------------------------------------------------------------------------

