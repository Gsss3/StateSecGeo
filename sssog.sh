#!/bin/bash



#Serv to Georgia <3 



bold=$(tput bold)
mwv="\e[92m"    
wtl="\e[91m"   
lrj="\e[34m"    
ttr="\e[97m"    
yvt="\e[93m"    
dft="\e[39m"   

#echo -e "${bold}"
if [ $(id -u) -ne 0 ];then
	echo "Script Should be run as root"
	exit
fi






dft_sshd () {

sed -i 's/#Port 65000/#Port 22/g' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin no/PermitRootLogin yes/g' /etc/ssh/sshd_config
echo ""
echo -e "${lrj}[ + ] კონფიგ ფაილები დაუბრუნდა საწყის მდგომარეობას! ${dft}"
echo ""

}






conf_sshd () {

sed -i 's/#Port 22/Port 65000/g' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
echo -e "${lrj} [+] თავდაცვის მიზნით მოხდა ssh-ის რეკონფიგურაცია! ${dft}"

}





auth_sshd () {


sshd_auth_ip=$(cat /var/log/auth.log | grep "sshd"|grep "Accepted" |grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" "/var/log/auth.log")

if [[ ! -z "$sshd_auth_ip" ]];then
	for ssh_ip in $sshd_auth_ip;
	do
		ssh_dtc=$(iptables -L | grep "ssh_dtc" | grep "$ssh_ip")
		if [[ -z "$ssh_dtc" ]];then
			echo -e "${wtl} [+] სერვერზე მოხდა root პრივილეგიით დაკავშირება ssh_ით ${dft} ${yvt}$ssh_ip ${dft} ${lrj} [ აღმოჩენის დრო: $(date +"%D") | $(date +"%H:%M") ] ${dft}"
			iptables -A INPUT -s $ssh_ip -j DROP --match comment --comment "ssh_dtc"
			echo ""
		fi
	done
fi


}


camera_control (){

	if [ -z $(modprobe -r uvcvideo | grep "fatal") ];then
		true
	else
		echo -e "${wtl} Someone is watching you"
	fi


}







ssh_brute_force_defense () {

iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 10 --hitcount 5 -j DROP


}





under_critical_attack() {


interface=$(route -n | awk '{print $8}' | awk '{print NR" "$0}' | sort -k1 -n -r | sed 's/^[^ ]* //g' | sort | uniq | head | sed 's/Iface//')

iptables -A INPUT -i $interface -J ACCEPT
iptables -A OUTPUT -i $interface -J ACCEPT
iptables -A INPUT -J DROP
iptables -A OUTPUT -J DROP


}











dir=/var/log/apache2/access.log



fw () {


	
sqlmap=$(grep "sqlmap" "$dir" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq)
nmap=$(grep "nmap" "$dir"| grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq)






if [[ "$sqlmap" ]];then
	for ip in $sqlmap;
	do
		sqlmap_rule=$(iptables -L | grep "sqlmap_detection" | grep "$ip")
                if [[ -z "$sqlmap_rule" ]];then	
			echo -e "${wtl} [!] აღმოჩენილი იქნა Sqlmap-ით ინექცირების მცდელობა!${dft} ${yvt} $ip ${dft} ${lrj} [ აღმოჩენის დრო: $(date +"%D") | $(date +"%H:%M") ] ${dft}"
			iptables -A INPUT -s $ip -p icmp -j DROP -m comment --comment "sqlmap_detection"
			echo ""
			iptables -A INPUT -s $ip -p tcp -m multiport --dports 80,443,8080 -j DROP -m comment --comment "sqlmap_detection"
			if [ $? -ne 1 ];then true;else echo "${wtl}[-] ვერ დაემატა firewall-ის წესებს${dft}";fi
		fi
	done
fi












if [[ "$nmap" ]];then	
	for ip in $nmap;
	do	
		nmap_rule=$(iptables -L | grep "nmap_detection" | grep "$ip")
		if [[ -z "$nmap_rule" ]];then
			echo -e "${wtl} [!] აღმოჩენილი იქნა Nmap-ით სკანირება!${dft} ${yvt} $ip ${dft} ${lrj} [ აღმოჩენის დრო: $(date +"%D") | $(date +"%H:%M") ] ${dft}"
			conf_sshd
			echo ""
			iptables -A INPUT -s $ip -p tcp --match multiport --dports 21,22,25,53,80,139,443,445 -j DROP -m comment --comment "nmap_detection"
			iptables -A INPUT -s $ip -p icmp -j DROP -m comment --comment "nmap_detection"
			if [ $? -ne 1 ];then true;else echo "${wtl}[-] ვერ დაემატა firewall-ის წესებს${dft}";fi
		fi
	done
fi










nclst=$(lsof -P -n -i | grep "nc" | grep "root" | grep "ESTABLISHED" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq)
if [[ -z "$nclst" ]];then
	for ip in $nclst;do
		nc_rule=$(iptables -L | grep "nc_detection" | grep "$ip")
		if [[ -z "$nc_rule" ]];then
			echo -e "${yvt}[!] აღმოჩენილი იქნა netcat კავშირი სერვერზე root პრივილეგიით!${dft} ${yvt}$ip ${dft} ${lrj} [ აღმოჩენის დრო: $(date +"%D") | $(date +"%H:%M") ] ${dft}"
			echo ""
			iptables -A INPUT -s $ip -j REJECT --match comment --comment "nc_detection"
			if [ $? -ne 1 ];then true;else echo "${wtl}[-] ვერ დაემატა firewall-ის წესებს${dft}";fi
		fi
	done
fi


auth_sshd
camera_control
}










if [[ $* == "-m" ]] || [[ $* == "--manual" ]];
then	
	echo ""
	echo -e "${mwv} [ X ] National Security Agency [ X ]${dft}"
	echo ""
	echo -e "${ttr}  [+] სკრიპტი გაშვებულია!${dft}"
	echo ""
	echo -e "${ttr}  [+] ყველა შემომავალი პაკეტი არის გაფილტრული!${dft}"
	echo ""
	echo ""
	ssh_brute_force_defense
	fw

elif [[ $1 == "-a" ]] || [[ $* == "--auto" ]];
then	
	echo ""
	echo -e "${mwv} [ X ] National Security Agency [ X ]${dft}"
	echo ""
	echo -e "${ttr}  [+] სკრიპტი გაშვებულია!${dft}"
	echo ""
	echo -e "${ttr}  [+] ყველა შემომავალი პაკეტი არის გაფილტრული!${dft}"
	echo ""
	echo ""
	ssh_brute_force_defense
	while true;do
		fw
	done

elif [[ $1 == "--dft" ]];then
	dft_sshd


elif [[ $1 == "--critical" ]];then
	echo ""
	echo -e "${ttr}[*] ჩართულია Survival რეჟიმი ${dft}"
	echo ""
	under_critical_under

elif [[ $1 == "" ]] || [[ $2 == "" ]];
then
	echo ""
	echo -e "${yvt}სკრიპტის პარამეტრები${dft}"
	echo ""
	echo -e "${yvt}-m | --manual${dft}"
	echo ""
	echo -e "${yvt}-a | --auto${dft}"
	echo ""
	echo -e "${yvt}Second Argument must be Server that you are using (apache2/nginx)${dft}"
	echo ""
	echo -e "${yvt}     --dft${dft}"
	echo ""

fi




