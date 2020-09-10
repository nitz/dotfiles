#!/bin/bash
# Shared script functions and resources
# by WaLLy3K 19MAR16 (Updated 22DEC16) for DietPi
# via https://www.reddit.com/r/raspberry_pi/comments/5tqeb4/show_me_your_motd/ddohjyc/

cpu_mhz=$(/bin/cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)
cpu_info=$(/bin/echo "$(/bin/ps -eo pcpu,rss --no-headers)" | /bin/egrep -v "    0")
net_gateway=$(/bin/grep -m1 "gateway" /etc/network/interfaces | /usr/bin/cut -d' ' -f2)
router_up=$(/usr/bin/timeout 0.2 /bin/ping -c1 $net_gateway &>/dev/null; [ "$?" -eq 0 ] && /bin/echo $?)

# Primary Functions
calc(){ /usr/bin/awk "BEGIN {print $*}"; }
hrbits() { /bin/echo "$1" | /usr/bin/awk '{xin=$1;if(xin==0){print "0 Bps";}else{x=(xin<0?-xin:xin);s=(xin<0?-1:1);split("Bps Kbps Mbps Gbps Tbps Pbps",type);for(i=5;y < 1;i--){y=x/(10^(3*i));}printf "%.1f"type[i+2], y*s};}'; }
hrbytes() { /bin/echo "$1" | /usr/bin/awk '{xin=$1;if(xin==0){print "0 B";}else{x=(xin<0?-xin:xin);s=(xin<0?-1:1);split("B KB MB GB TB PB",type);for(i=5;y < 1;i--){y=x/(10^(3*i));}printf "%.f "type[i+2], y*s};}'; }
hrbytes1024() { /bin/echo "$1" | /usr/bin/awk '{xin=$1;if(xin==0){print "0 B";}else{x=(xin<0?-xin:xin);s=(xin<0?-1:1);split("B KB MB GB TB PB",type);for(i=5;y < 1;i--){y=x/(2^(10*i));}printf "%.f "type[i+2], y*s};}'; }
hrseconds() { d=$(($1/60/60/24)); h=$(($1/3600%24)); m=$((($1%3600)/60)); s=$(($1%60)); if [ $d -eq 0 ]; then n=""; elif [ $d -eq 1 ]; then n="$d day, "; else n="$d days, "; fi; /usr/bin/printf "$n%02d:%02d:%02d\n" $h $m $s; }

# Print messages to log or stdout depending on use
msg() {
  if [ -z "$2" ]; then t="NOTICE"; m="$1"; else t="$1"; m="$2"; fi
  [ -n "$msg_tag" ] && t="$msg_tag"
  if [ "$msg_silent" ]; then
    /usr/bin/test
  elif [ -t 1 ]; then
    /bin/echo "[$t]: $m"
  else
    /usr/bin/logger -st "[$t]" "$m"
  fi
}
error() { msg "✗ $1"; }
fatal() { msg "FATAL" "$1"; exit 1; }

# Get SSH session IP, resolve Hostname & provide login messages
_ssh() {
  ssh_ip=$(set $SSH_CONNECTION; /bin/echo $1)
  [ -n "$router_up" ] && ssh_user=$(ip=$(/usr/bin/timeout 1 /usr/bin/dig +short -x $ssh_ip 2> /dev/null); /bin/echo ${ip/./})
  [ -z "$ssh_user" -o "$ssh_user" = "3(NXDOMAIN" ] && ssh_user="Commander"
  
  # Provide different messages upon loading
  if [ "${#ssh_user}" -le "25" ]; then
    case "$(( (RANDOM %5) + 1 ))" in
      1) ssh_load="Initialising, please stand by..." ;;
      2) ssh_load="Transferring systems to ${ssh_user}'s control" ;;
      3) ssh_load="Control transferring to $ssh_user" ;;
      4) ssh_load="Transferring controls to manual operation" ;;
      5) ssh_load="Transferring power systems to $ssh_user" ;;
    esac
    case "$(( (RANDOM %3) + 1 ))" in
      1) ssh_intro="Welcome back, $ssh_user" ;;
      2) ssh_intro="Control initiated for $ssh_user, welcome back" ;;
      3) ssh_intro="It is good to have you back, $ssh_user" ;;
    esac
  fi
}

# Get system information
_sys() {
  sys_name=$(/bin/hostname)
  sys_uptime=$(hrseconds $(/usr/bin/cut -d. -f1 /proc/uptime))
  sys_loadavg=$(/usr/bin/cut -d' ' -f1,2,3 /proc/loadavg)
  sys_throttle=$(/usr/bin/sudo /usr/bin/vcgencmd get_throttled | /usr/bin/cut -dx -f2)
  
  if [ "$sys_throttle" != "0" ]; then # http://bit.ly/2gnunOo
    case `/bin/echo "$sys_throttle"` in
      *0001) type="${yellow}Low Power" ;;
      *0002) type="\e[1;35mArm Freq Cap" ;;
      *0003) type="${yellow}LP${grey},$def \e[1;35mAFC" ;;
      *0004) type="${red}Throttled" ;;
      *0005) type="${yellow}LP${grey},$def ${red}TT" ;;
      *0006) type="\e[1;35mAFC${grey},$def ${red}TT" ;;
      *0007) type="${yellow}LP${grey},$def \e[1;35mAFC${grey},$def ${red}TT" ;;
      1000*) type="${grey}Low Power" ;;
      2000*) type="${grey}Arm Freq Cap" ;;
      3000*) type="${grey}LP, AFC" ;;
      4000*) type="${grey}Throttled" ;;
      5000*) type="${grey}LP, TT" ;;
      6000*) type="${grey}AFC, TT" ;;
      7000*) type="${grey}LP, AFC, TT" ;;
    esac
    [ -n "$type" ] && throttle="[$type$def]"
  else
    throttle=""
  fi

  case `set $(/bin/grep Revision /proc/cpuinfo); /bin/echo "$3"` in
    0002|0003) sys_rev=" 1, Model B r1.0" ;;
    0004|0005|0006) sys_rev=" 1, Model B r2.0" ;;
    0007|0008|0009) sys_rev=" 1, Model A" ;;
    0010) sys_rev=" 1, Model B+" ;;
    0012) sys_rev=" 1, Model A+" ;;
    a01041|a21041) sys_rev=" 2, Model B" ;;
    900092) sys_rev=" Zero" ;;
    a02082|a22082) sys_rev=" 3, Model B" ;;
    *) sys_rev="" ;;
  esac
  sys_model="Raspberry Pi$sys_rev"
}

# Get CPU information
_cpu() {
  cpu_tasks=$(/bin/echo "$cpu_info" | /usr/bin/wc -l)
  # Remove processes using <1% CPU
  cpu_taskact=$(/bin/echo "$cpu_info" | /bin/sed -r '/(^ 0.)/d' | /usr/bin/wc -l)
  cpu_perc=$(/usr/bin/printf "%.f" $(/bin/echo "$cpu_info" | /usr/bin/awk '{sum+=$1} END {print sum/4}'))

  # cpu_mhz is called earlier, so as to not be throttled up by script
  [ "$cpu_mhz" -gt 999999 ] && cpu_freq="$(calc $cpu_mhz/1000000) Ghz" || cpu_freq="$(($cpu_mhz/1000)) MHz"
  cpu_volt=$(vc=$(/usr/bin/sudo /usr/bin/vcgencmd measure_volts core); /usr/bin/printf "%.1f" $(/bin/echo ${vc//[!0-9.]/}))
  cpu_temp=$(mt=$(/usr/bin/sudo /usr/bin/vcgencmd measure_temp); /bin/echo ${mt//[!0-9.CF]/})

  # Provide different shell colours for different temperatures
  case "${cpu_temp::2}" in
    1[0-9][0-9]|[7-9][0-9]) cpu_tcol="\e[39;41m" ;;
    6[0-9]) cpu_tcol="\e[31m" ;;
    5[0-9]) cpu_tcol="\e[93m" ;;
    4[0-9]) cpu_tcol="" ;;
    [0-9]*|[0-3][0-9]) cpu_tcol="\e[94m" ;;
    -*) cpu_tcol="\e[96m" ;;
  esac 
}

# Get RAM stats
_ram() {
  ram_info=$(/usr/bin/awk '/MemTotal:/{total=$2} /MemFree:/{free=$2} \ 
  /Buffers:/{buffers=$2} /^Cached:/{cached=$2} END { printf "%.f%% %.f %.f", \
  (total-free-buffers-cached)*100/total, (total-free-buffers-cached)*1024, \
  total*1024}' /proc/meminfo)
  ram_perc=$(set $ram_info; /bin/echo "$1")
  ram_used=$(set $ram_info; /bin/echo "$2")
  ram_total=$(set $ram_info; /bin/echo "$3")
}

# Get GPU stats
_gpu() {
  gpu_total=$(gt=$(/usr/bin/sudo /usr/bin/vcgencmd get_mem gpu); /bin/echo "$(( ${gt//[!0-9]/}*1000000 ))")
  gpu_used=$(/usr/bin/sudo /usr/bin/vcdbg reloc | /usr/bin/awk -F '[ ,]*' '/^\[/ {sum += $12} END {print sum}')
  [ -z "$gpu_used" ] && gpu_used="0" # Occurs during Framebuffer corruption
  gpu_free="$(($gpu_total-$gpu_used))"
  gpu_perc=$(/usr/bin/printf "%.f" `calc "$gpu_used/$gpu_total*100"`)
  [ `/usr/bin/sudo /usr/bin/tvservice -s | /bin/grep -c "off"` -eq 0 ] && gpu_info="Used: $(hrbytes $gpu_used) of $(hrbytes $gpu_total)" || gpu_info="HDMI service disabled"
}

# Get SD card stats
_sd() {
  sd_info=$(/bin/df -h | /usr/bin/awk '/root/{print $3,$2,$5}' | /bin/sed -e 's/M/ MB/g' -e 's/G/ GB/g')
  sd_total=$(set $sd_info; /bin/echo "$3")
  sd_total_unit=$(set $sd_info; /bin/echo "$4")
  sd_used=$(set $sd_info; /bin/echo "$1")
  sd_used_unit=$(set $sd_info; /bin/echo "$2")
  sd_perc=$(set $sd_info; /bin/echo "$5")
}

# Get USB device stats
_usb() {
  usb_info=$(/usr/bin/sudo /usr/bin/lsusb -vs 001:002 | /bin/grep "  Port ")
  usb_used=$(/bin/echo "$usb_info" | /bin/grep -c "enable")
  # -1 is for Ethernet
  usb_used="$(($usb_used-1))"
  [ "$usb_used" -lt 0 ] && usb_used="0"
  usb_total=$(/bin/echo "$usb_info" | /usr/bin/wc -l)
  usb_total="$(($usb_total-1))"
  if [ "$usb_used" -ne 0 ]; then
    # -4 is for Ethernet
    usb_pwr=$(/usr/bin/usb-devices | /usr/bin/awk -F '[=m]' '/MxPwr/ {sum+=$5} END {print sum-4 "mA"}')
  else
    usb_pwr="0mA"
  fi
}

# Get network information
_net() {
  net_hostip=$(/usr/bin/timeout 1 /usr/bin/dig +short my.pi.domain @8.8.8.8)
  net_wanip=$(/usr/bin/timeout 1 /usr/bin/dig +short myip.opendns.com @resolver1.opendns.com)
  net_fwanip=$(/bin/echo $net_wanip | /usr/bin/awk -F. '{print $1"."$2".XX."$4}')
  [ -z "$net_gateway" ] && net_gateway=$(/bin/grep -m1 "gateway" /etc/network/interfaces | /usr/bin/cut -d' ' -f2)
  net_host=$(/bin/hostname -I)
  net_lanip=$(set $net_host; /bin/echo $1)
  net_inf=$(/sbin/ifconfig | /bin/grep -B1 "$net_lanip" | /usr/bin/awk -F'[: ]' '{print $9;exit}')
  #export http_proxy="http://$net_gateway:81/proxy.pac"
}

_motd() {
  [ -t 1 ] && clear
  _ssh
  [ -t 1 -a -n "$ssh_load" ] && echo "$ssh_load"
  _sys;_cpu;_ram;_gpu;_sd;_usb;_net
  
  if [ -t 1 ]; then
    grey="\e[1;30m"
    def="\e[0m"
    white="\e[1;39m"
    green="\e[1;32m"
    red="\e[1;31m"
    yellow="\e[1;33m"
  else
    grey="<span style='color: gray;'>"
    def="</span>"
    white="<span style='font-weight: bold;'>"
    green="<span style='color: green;'>"
    red="<span style='color: red;'>"
    yellow="<span style='color: yellow;'>"
  fi
  
  # WAN
  if [ -z "$net_wanip" ]; then
    wan_info="${red}Offline ✗"
  elif [ "$net_wanip" ==  "$net_hostip" ]; then
    wan_info="${green}Online ✓ ${def}\t\t$grey(IP: $net_fwanip)"
  else
    wan_info="${yellow}Online ✓ ${def}\t\t$grey(Zone Record out of sync)"
  fi

  # LAN
  if [ "$net_inf" = "Ethernet" ]; then # Check output for WiFi
    lan_info="${green}$net_inf ✓ ${def}\t$grey(IP: $net_lanip$net_lanip2)"
  else
    [ -z "$net_inf" ] && net_inf="Error"
    lan_info="${yellow}$net_inf - ${def}\t$grey(IP: $net_lanip)"
  fi
  
  # DNS/Dnsmasq
  dm_pid=$(/bin/pidof dnsmasq)
  if [ -n "$dm_pid" ]; then
    dm_state="Online"
    [ -n "$(/usr/bin/timeout 1 /usr/bin/dig +short dnssec-failed.org)" ] && dm_dnssec="Disabled" || dm_dnssec="Enabled"
    dm_info2="\t\t$grey(DNSSEC: $dm_dnssec)"
    dm_info="${green}$dm_state ✓ ${def}$dm_info2"
  else
    dm_state="Disabled"
    dm_info="${red}$dm_state ✗"
  fi
  
  # Netstat Ports for future use
  nsp_info=$(/usr/bin/sudo /usr/bin/timeout 1 /bin/netstat -tp)
  
  # SOCKS
  sk_status=$(/bin/nc -z $net_gateway 8080; /bin/echo $?)
  if [ "$sk_status" -eq 0 ]; then
    sk_state="Online"
    sk_info="${green}$sk_state ✓"
  else
    sk_state="Disabled"
    sk_info="${red}$sk_state ✗"
  fi
  
  # Pi-hole
  ph_status=$(/usr/bin/sudo /usr/local/bin/pihole status web)
  if [ "$ph_status" -eq 1 ]; then
    ph_state="Online"
    ph_info2="\t$grey(Blocked: $(/usr/bin/wc -l < /etc/pihole/list.preEventHorizon | /bin/sed ':a;s/\B[0-9]\{3\}\>/,&/;ta') sites)"
    ph_info="${green}$ph_state ✓ ${def}$ph_info2"
  elif [ "$ph_status" -eq 0 ]; then
    ph_state="Disabled"
    ph_info="${red}$ph_state ✗"
  else
    ph_state="Starting"
    ph_info="${yellow}$ph_state -"
  fi

  # Lighttpd
  ww_pid=$(/bin/pidof lighttpd)
  if [ -n "$ww_pid" ]; then
    le_folder="/etc/letsencrypt/live"
    le_domain=$(/usr/bin/sudo /bin/ls -A $le_folder 2> /dev/null | /usr/bin/cut -d' ' -f1)
    le_cert=$(/bin/echo "/etc/letsencrypt/live/$le_domain/cert.pem")
    if [ -z "$le_domain" ]; then
      ww_cert=": Cert does not exist"
    else
      not_After=$(/usr/bin/sudo /usr/bin/openssl x509 -in $le_cert -noout -dates | /usr/bin/awk -F= 'END{print $NF}')
      days_Left=$(/bin/echo $(( ($(date --date="$not_After" +%s) - $(date +%s))/(60*60*24) )))
      [ "`/usr/bin/sudo /usr/bin/openssl x509 -in $le_cert -noout -issuer | /bin/grep -ic "fake"`" -ne 0 ] && ww_cert2="d, Fake LE" || ww_cert2=" days"
      ww_cert=" Exp: ${days_Left}$ww_cert2"
    fi
    ww_state="Idle"
    [ "$ww_cert" ] && ww_certinfo="\t$grey(SSL$ww_cert)"
    [ `/bin/echo "$nsp_info" | /bin/grep -c $ww_pid` -eq 1 ] && ww_state="Active"
    ww_info="${green}$ww_state ✓ ${def}$ww_certinfo"
  else
    ww_state="Disabled"
    ww_info="${red}$ww_state ✗"
  fi
  
  # PHP
  pp_pid=$(wc -w <<< /run/php5-fpm.pid)
  if [ "$pp_pid" -eq 0 ]; then
    pp_state="Disabled"
    pp_info="${red}$pp_state ✗"
  fi
  
  # Aria2
  a2_pid=$(/bin/pidof aria2c)
  if [ -n "$a2_pid" ]; then
    a2_state="Idle"
    [ `/bin/echo "$nsp_info" | /bin/grep -c $a2_pid` -eq 1 ] && a2_state="Active"
    a2_info="${green}$a2_state ✓"
  else
    a2_state="Disabled"
    a2_info="${red}$a2_state ✗"
  fi

  # Shairport
  sp_pid=$(/bin/pidof shairport-sync)
  if [ -n "$sp_pid" ]; then
    sp_state="Idle"
    sp_user=$(/bin/echo "$nsp_info" | /usr/bin/awk "/"$sp_pid"/ {print \$5}")
    if [ -n "$sp_user" ]; then
      sp_state="Active"
      # Remove :PORT after client name
      [ -z "$net_gateway" ] && _net
      sp_host=$(/usr/bin/timeout 1 /usr/bin/dig +short -x $(echo $sp_user | cut -d":" -f1) @$net_gateway)
      # %? remove last character
      sp_info2="\t$grey(Client: ${sp_host%?})"
    fi
    sp_info="${green}$sp_state ✓ ${def}$sp_info2"
  else
    sp_state="Disabled"
    sp_info="${red}$sp_state ✗"
  fi

  # Samba
  sb_pid=$(/bin/pidof smbd)
  if [ -n "$sb_pid" ]; then
    sb_state="Idle"
    [ `/bin/echo "$nsp_info" | /bin/grep -c "$sb_pid"` -ge 1 ] && sb_state="Active"
    sb_info="${green}$sb_state ✓"
  else
    sb_state="Disabled"
    sb_info="${red}$sb_state ✗"
  fi
  
  # Moonlight
  if [ "$tv_state" = "Enabled" ]; then
    ml_pid=$(/bin/pidof moonlight)
    if [ -n "$ml_pid" ]; then
      ml_state="Idle"
      ml_user=$(/bin/echo "$nsp_info" | /usr/bin/awk "/"$ml_pid"/ {print \$5}")
      if [ -n "$ml_user" ]; then
        ml_state="Active"
        ml_info2="\t$grey(Server: ${ml_user%:*})"
      fi
      ml_info="${green}$ml_state ✓ $ml_info2"
    else
      ml_state="Disabled"
      ml_info="${red}$ml_state ✗"
    fi
  fi

  # DietPi Update
  if [ -f "/DietPi/dietpi/.update_available" ]; then
    dp_vers=$(/bin/cat /DietPi/dietpi/.version)
    dp_update=$(/bin/cat /DietPi/dietpi/.update_available)

    if [ "$dp_update" -gt 0 ]; then
      dp_info="Update available"
      dp_help="Run dietpi-update to get the latest version."
    elif [ "$dp_update" -eq -1 ]; then
      dp_info="Image available"
      dp_update="?"
      dp_help="An updated DietPi image is available."
    fi
  fi

  # Root Security
  if [ `which dropbear` ]; then
    root_disabled=$(/usr/bin/sudo /bin/grep -c "EXTRA_ARGS=\"-w" /etc/default/dropbear)
  else
    root_disabled=$(/usr/bin/sudo /bin/grep -c "^PermitRootLogin no" /etc/ssh/sshd_config)
  fi
  
  if [ "$root_disabled" -eq 0 ]; then
    rd_info="Notice: Root login over SSH has been enabled"
  fi
  
  # DietPi Config Check
  if [ ! -s "/DietPi/dietpi.txt" ]; then
    dc_info="DietPi config not found!"
  fi
  
  [ -t 1 ] && clear
  [ -t 1 ] && /bin/echo -e "$grey $ssh_intro$def"
  [ -t 1 ] && /bin/echo -e "$grey ============================================================$def"
  [ -t 1 ] && tcol="$cpu_tcol"
    /bin/echo -e "  Now Entering $white$sys_name$def [${green}$sys_model$def]$throttle"
    /bin/echo -e "  ${red}Uptime: $sys_uptime"
    /bin/echo -e "  Task load: $sys_loadavg\t$def$grey(Active: $cpu_taskact of $cpu_tasks tasks)$def"
    /bin/echo -e "  CPU usage: $cpu_perc% \t\t$def$grey($tcol${cpu_temp,,}$def$grey, $cpu_freq, ${cpu_volt}v)$def"
    /bin/echo -e "  RAM usage: $ram_perc \t\t$def$grey(Used: $(hrbytes1024 $ram_used) of $(hrbytes1024 $ram_total))$def"
    /bin/echo -e "  GPU usage: $gpu_perc% \t\t$def$grey($gpu_info)$def"
    /bin/echo -e "  mSD usage: $sd_perc \t\t$def$grey(Used: $sd_used $sd_used_unit of $sd_total $sd_total_unit)$def"
    /bin/echo -e "  USB usage: $usb_pwr \t\t$def$grey(Used: $usb_used of $usb_total ports)$def"
    /bin/echo -e "  WAN state: $wan_info $def"
    /bin/echo -e "  LAN state: $lan_info $def"
    /bin/echo -e "  DNS state: $dm_info $def"
    /bin/echo -e "  Aria2 state: $a2_info $def"
    /bin/echo -e "  Samba state: $sb_info $def"
    /bin/echo -e "  SOCKS state: $sk_info $def"
    /bin/echo -e "  Pi-hole state: $ph_info $def"
    /bin/echo -e "  Lighttp state: $ww_info $def"
    [ -n "$pp_info" ] && /bin/echo -e "  PHP-FPM state: $pp_info $def"
    /bin/echo -e "  Shairport state: $sp_info $def"
    [ -n "$ml_info" ] && /bin/echo -e "  Moonlight state: $ml_info $def"
  [ -t 1 ] && /bin/echo -e "$grey ============================================================$def"
    if [ -n "$dp_info" ]; then
      /bin/echo -e "  DietPi: $red$dp_info$def\t\e$grey(Version: $dp_vers > $dp_update)$def"
      [ -t 1 ] && /bin/echo -e "  $dp_help"
      [ -t 1 ] && /bin/echo -e "$grey ============================================================$def"
    elif [ -n "$rd_info" ]; then
      /bin/echo -e "  $rd_info"
      [ -t 1 ] && /bin/echo -e "$grey ============================================================$def"
    elif [ -n "$dc_info" ]; then
      /bin/echo -e "  $dc_info"
      [ -t 1 ] && /bin/echo -e "$grey ============================================================$def"
    fi
  /bin/echo ""
}

alias motd='_motd'