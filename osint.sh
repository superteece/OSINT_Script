#!/bin/bash

# Usage - make sure that all domains (FQDNs, not IP addresses!) being targeted are in targets.txt, in the same dir as osint.sh
# ./osint.sh
# all domains targeted will have a directory created for them.
# Important - This is intended to be used only in Kali. It aint gonna work anywhere else.

function cleanup {
  mv ./$i/*.txt ./$i/txt/
  mv ./$i/*.csv ./$i/csv/
}

function organize {
    #Create Scan Directory 
    mkdir ./$i
    mkdir ./$i/txt
    mkdir ./$i/csv
    mkdir ./$i/txt/fqdn_whois
    mkdir ./$i/csv/fqdn_whois
    mkdir ./$i/txt/ip_whois
    mkdir ./$i/csv/ip_whois
}

function massagedata {
  cat ./$i/reverse_$i.txt | sed 's/^...//' |  sed -e 's/^[ \t]*//' | tr -s ' ' ',' | sed '/Performing/d' | sed '/Reverse/d' | sed '1d;$d' | sed '$G' > ./$i/zreverse_$i.csv
  cat ./$i/txt/fqdn_whois/tech_contact_info_$i.txt | sed 's/:/,/1' | sed '$G' > ./$i/tech_contact_info_$i.csv
  cat ./$i/txt/fqdn_whois/registrar_info_$i.txt | sed 's/:/,/1' | sed '$G' > ./$i/registrar_info_$i.csv
  cat ./$i/txt/fqdn_whois/admin_contact_$i.txt | sed 's/:/,/1' | sed '$G' > ./$i/admin_contact_$i.csv
  cat ./$i/txt/fqdn_whois/tech_contact_info_$i.txt | sed 's/:/,/1' | sed '$G' > ./$i/csv/fqdn_whois/tech_contact_info_$i.csv
  cat ./$i/txt/fqdn_whois/registrar_info_$i.txt | sed 's/:/,/1' | sed '$G' > ./$i/csv/fqdn_whois/registrar_info_$i.csv
  cat ./$i/txt/fqdn_whois/admin_contact_$i.txt | sed 's/:/,/1' | sed '$G' > ./$i/csv/fqdn_whois/admin_contact_$i.csv
  cat ./$i/emails_harvested_$i.txt | sed '/^@/ d' | sed '$G' > ./$i/emails_harvested_$i.csv
  cat ./$i/address.txt | sed '1 i\IP Address(es) for Target Domain' | sed '$G' > ./$i/address.csv
  cat ./$i/range.txt | sed '1 i\IP Range for Target Domain' | sed '$G' > ./$i/range.csv
  cat ./$i/cidr.txt | sed '1 i\CIDR block for Target Domain' | sed '$G' > ./$i/cidr.csv
  cat ./$i/mail_servers_$i.txt | sed '1 i\Mail Servers for Target Domain' | sed '$G' > ./$i/mail_servers_$i.csv
  cat ./$i/output_nameservers_$i.txt | sed '1 i\DNS Name Servers for Target Domain' | sed '$G' > ./$i/output_nameservers_$i.csv
  cat ./$i/txt/ip_whois/address_whois_$i.txt | sed 's/:/,/1' | sed '$G' > ./$i/csv/ip_whois/address_whois_$i.csv
  cat ./$i/*.csv > ./$i/complete_$i.csv
}

function splash {
echo "                "
echo "This is an aggregator for OSINT gathering. What can I say, I'm lazy and was tired of "
echo "doing the same tasks over and over."
echo "            "
echo "Usage - make sure your targets are listed in a text file called targets.txt in the same "
echo "directory as this shell script. Then, just type ./osint.sh and you're off to the races!"
echo "            "
echo "            "
echo "If you have questions, contact me at"
echo "lostinmoscow@gmail.com"
}

function doitall {
      #Perform basic enumeration of domain
  echo "************************************************************************************"
  echo "Performing WHOIS operations"
  echo "************************************************************************************"
      #Perform WHOIS
    whois $i > ./$i/output_whois_$i.txt
  echo "************************************************************************************"
  echo "WHOIS operations complete, now performing HOST operations"
  echo "************************************************************************************"
      #Perform HOST
    host $i > ./$i/output_host_$i.txt
  echo "************************************************************************************"
  echo "HOST operations complete, now parsing data and separating to appropriate files"
  echo "************************************************************************************"
      #Separate address and save to file
    grep address ./$i/output_host_$i.txt  | cut -d " " -f 4 > ./$i/address.txt
      #Perform whois on IP ARIN info
    while read ip; do whois $ip; done < ./$i/address.txt | sed '/^#/ d'> ./$i/txt/ip_whois/address_whois_$i.txt
      #Extract name servers
    host -t ns $i | cut -d " " -f4 | sed 's/.$//' > ./$i/output_nameservers_$i.txt
      #Perform basic dns enumeration
    dnsenum $i > ./$i/output_dnsenum_$i.txt
      #Separate CIDR block and save to file
    while read ip; do whois $ip; done < ./$i/address.txt | grep CIDR: | cut -d " " -f 12 | uniq > ./$i/cidr.txt
      #Separate Network Range and save to file for use by DNSRecon
    while read ip; do whois $ip; done < ./$i/address.txt | grep NetRange | cut -d " " -f 8,9,10 | tr -d " " | uniq >> ./$i/range.txt
      #Separate mail servers and save in separate file
    grep mail ./$i/output_host_$i.txt | cut -d " " -f7 | sed 's/.$//' > ./$i/mail_servers_$i.txt
      #Parse out contact info for domain from whois
    grep Admin ./$i/output_whois_$i.txt | sed '/^Tech/ d' > ./$i/txt/fqdn_whois/admin_contact_$i.txt
    grep Reg ./$i/output_whois_$i.txt | head --lines=-3 | sed '/modify/d' | sed '/The Registry/d' | sed '/Registrars./d' | sed -e 's/^[ \t]*//' > ./$i/txt/fqdn_whois/registrar_info_$i.txt
    grep Tech ./$i/output_whois_$i.txt > ./$i/txt/fqdn_whois/tech_contact_info_$i.txt
    mv ./$i/output_whois_$i.txt ./$i/txt/fqdn_whois/output_whois_$i.txt
      #Perform full harvest for domain with shodanhq enabled - important, make sure your API key is specified in
      #/usr/share/theharvester/discovery/shodansearch.py !!! If you do not have an API key, remove -h from the command
      #below.
  echo "************************************************************************************"
  echo "Data parsing operations complete, now harvesting email and other data"
  echo "************************************************************************************"
    theharvester -d $i -b all -h | tee ./$i/output_theharvester.txt
      #Separate found email addresses and save to separate file
    grep @$i ./$i/output_theharvester.txt | sed '/^@/ d' > ./$i/emails_harvested_$i.txt
      #Perform threaded reverse DNS lookup of range extracted earlier
  echo "************************************************************************************"
  echo "Data harvesting complete, now performing reverse dns lookups for targeted domain"
  echo "************************************************************************************"
    for i in $(cat ./$i/range.txt); do echo $i; dnsrecon -r $i; done | tee ./$i/reverse_$i.txt
}

    splash
  echo "            "
  echo "            "
for i in $(cat ./targets.txt); do
  echo "************************************************************************************"
    echo "Currently performing OSINT operations on target - $i  "
    echo "Please be patient, this may take a while!"
  echo "************************************************************************************"
      organize
      doitall
      massagedata
      cleanup
    echo "All operations are completed - terminating processes"
done
    echo "All data has been saved and moved to the pertinent folders. Have fun!"
