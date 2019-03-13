#
# lispers.net .cshrc file that runs under /root in docker container.
#
alias sa     'source /root/.cshrc'
alias psg    'ps auxww | egrep \!* | egrep -v grep'
alias py     'python -O -u'
alias ll     'ls -lag'
alias ld     'ls -lgd'
alias h      'history'            
alias t      'nice top -d 1'
alias aptget 'sudo apt-get -o Acquire::ForceIPv4=true install'
alias td     'sudo tcpdump -i any -n'    

alias lig 'py lisp-lig.pyo'
alias rig 'py lisp-rig.pyo'
alias ltr 'py ltr.pyo'

alias db     'curl --silent --insecure -u root: https://localhost:8080/lisp/api/data/database-mapping | jq .'
alias mc     'curl --silent --insecure -u root: https://localhost:8080/lisp/api/data/map-cache | jq .'

        
