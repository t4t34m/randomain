#!/bin/sh
pwd=$(pwd)
header(){
  clear
  printf """\e[1;38;5;197mScan Random Subdomains ...\e[0m

 ███████                           ██\e[1;38;5;197m  ████\e[0m                 ██  ██
░██░░░░██                         ░██\e[1;38;5;197m █░░░██\e[0m               █░█ ░░
░██   ░██   ██████   ███████      ░██░\e[1;38;5;197m█  █░█\e[0m ██████████   █ ░█  ██ ███████
░███████   ░░░░░░██ ░░██░░░██  ██████░\e[1;38;5;197m█ █ ░█\e[0m░░██░░██░░██ ██████░██░░██░░░██
░██░░░██    ███████  ░██  ░██ ██░░░██░\e[1;38;5;197m██  ░█\e[0m ░██ ░██ ░██░░░░░█ ░██ ░██  ░██
░██  ░░██  ██░░░░██  ░██  ░██░██  ░██░\e[1;38;5;197m█   ░█\e[0m ░██ ░██ ░██    ░█ ░██ ░██  ░██
░██   ░░██░░████████ ███  ░██░░██████░ \e[1;38;5;197m████\e[0m  ███ ░██ ░██    ░█ ░██ ███  ░██
░░     ░░  ░░░░░░░░ ░░░   ░░  ░░░░░░  ░░░░  ░░░  ░░  ░░     ░  ░░ ░░░   ░░
"""
}
usage(){
  printf """
\e[1;38;5;197m#\e[0m\e[1;37mUsage \e[0m:

\e[1;37m[\e[0m\e[1;38;5;120m 1 \e[0m\e[1;37m]\e[0m \e[1;36m $0 2 100 com\e[0m
\e[1;37m[\e[0m\e[1;38;5;120m 2 \e[0m\e[1;37m]\e[0m \e[1;36m $0 3 1000 com\e[0m
\e[1;37m[\e[0m\e[1;38;5;120m 3 \e[0m\e[1;37m]\e[0m \e[1;36m $0 4 10000 com\e[0m

"""
}
if [ $# -lt "3" ]; then
  header
  usage
  exit 1
fi
header
inputme=$1
random=$2
d0main=$3
timeis=$(date '+%Y_%m_%d_%H-%M-%S')
timeis2=$(date '+%Y/%m/%d %H:%M:%S')
doOutput="$pwd/output"
doPath="$pwd/output/$d0main-$timeis"
if [ ! -d "$doOutput" ]; then mkdir $doOutput ; fi
if [ ! -d "$doPath" ]; then mkdir $doPath ; fi
printf """

[\e[1;37m + \e[0m] Date : $timeis2
[\e[1;37m + \e[0m] Target : $d0main
[\e[1;37m + \e[0m] Subs : $inputme
[\e[1;37m + \e[0m] Random : $random

"""
echo "[ + ] Date : $timeis2\n[ + ] Target domain : $d0main" >> "$doPath/all_result.txt"
for i in `seq 1 $random`;
do
  exec 3>&1;
  D=$(cat /dev/urandom | tr -dc 'a-z' | fold -w ${1:-$1} | head -n 1)
  X1="$D.$d0main"
  if
  s1=$( (resolveip -s $X1) 2>&1 )
  then
    cmd_curl_get_http_code=$(curl -sL -w "%{http_code}\n" "$s1" -o /dev/null)
    cmd_nmap_get_domain=$(nmap -sL -oG - $s1 | awk '$3~/\(.+\)/{print $3}' | tr -d '()')
    cmd_curl_ServerType=$(curl -s -i -v --url $s1 2> /dev/null | grep Server | head -n 1 | awk 'NF==2{print $2} NF!=2{exit}')
    cmd_nmap_open_port=$(nmap -vv $s1 | awk -F'[ /]' '/Discovered open port/{print $NF":"$4}')
    printf """\e[1;37m[ $cmd_curl_get_http_code ]\e[0m\e[1;37m $X1\e[0m\e[1;38;5;120m:\e[0m $s1 \e[1;38;5;120m|\e[0m $cmd_nmap_get_domain \e[1;38;5;120m|\e[0m Server: \e[1;37m$cmd_curl_ServerType\e[0m\n"""
    echo "[ $cmd_curl_get_http_code ]: $X1 : $s1 : $cmd_nmap_get_domain : $cmd_curl_ServerType" >> "$doPath/allinone.txt"
    echo "$cmd_curl_ServerType" >> "$doPath/servertype.txt"
    echo "$cmd_nmap_get_domain" >> "$doPath/datacenter.txt"
    echo "----[$X1]----\n$cmd_nmap_open_port\n" >> "$doPath/nmap_open_ports.txt"
    echo "$s1" >> "$doPath/ip.txt"
    echo "$X1" >> "$doPath/domain.txt"
  else
    printf """\e[1;38;5;197m[ XXX ]\e[0m\e[1;38;5;244m $X1 : not exist\n"""
    echo "$X1" >> "$doPath/not_found.txt"
  fi
done
if
cchheecckk=$( (cat "$doPath/datacenter.txt")  2>&1 )
then
  cat "$doPath/datacenter.txt" | sed '/^$/d;s/[[:blank:]|:]//g' | sed -e 's/[\t ]//g;/^$/d' >> "$doPath/datacenter.lst"
  cat "$doPath/servertype.txt" | sed '/^$/d;s/[[:blank:]|:]//g' | sed -e 's/[\t ]//g;/^$/d' >> "$doPath/servertype.lst"
  cat "$doPath/ip.txt" | sed '/^$/d;s/[[:blank:]|:]//g' | sed -e 's/[\t ]//g;/^$/d' >> "$doPath/ip.lst"
  cat "$doPath/domain.txt" | sed '/^$/d;s/[[:blank:]|:]//g' | sed -e 's/[\t ]//g;/^$/d' >> "$doPath/domain.lst"
  sleep 0.3
  rm -r "$doPath/datacenter.txt"
  rm -r "$doPath/servertype.txt"
  rm -r "$doPath/ip.txt"
  rm -r "$doPath/domain.txt"
  sleep 0.3
  CMD1wc=$(cat "$doPath/datacenter.lst" | wc -l)
  CMD2wc=$(cat "$doPath/servertype.lst" | wc -l)
  CMD3wc=$(cat "$doPath/ip.lst" | wc -l)
  CMD4wc=$(cat "$doPath/domain.lst" | wc -l)
  echo1=$(echo "[ + ] total DataCenter : $CMD1wc" >> "$doPath/all_result.txt")
  echo2=$(echo "[ + ] total Server type : $CMD2wc" >> "$doPath/all_result.txt")
  echo3=$(echo "[ + ] total ips : $CMD3wc" >> "$doPath/all_result.txt")
  echo3=$(echo "[ + ] total ips : $CMD4wc" >> "$doPath/all_result.txt")
  ADD1wc=$(cat "$doPath/allinone.txt")
  echo1=$(echo "\n$ADD1wc" >> "$doPath/all_result.txt")
  ADD2wc=$(cat "$doPath/nmap_open_ports.txt")
  echo2=$(echo "\n$ADD2wc" >> "$doPath/all_result.txt")
  sleep 0.3
  rm -r "$doPath/allinone.txt"
  echo "\n\ndone: $doPath"
else
  echo "Try again !!!"
fi
