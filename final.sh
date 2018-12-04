cat info.txt | while read line
do
host=$(echo "$line" | cut -d " " -f 1) 
username=$(echo "$line" | cut -d " " -f 2)
password=$(echo "$line" | cut -d " " -f 3)
path=$(echo "$line" | cut -d " " -f 4)
echo -e "----------------------------------------------------------------------------"
echo -e "[ Started for" $host "]\n\n"
python3 netconf7.py  $host $username $password -L $path
echo -e "\n\n[ Finished for" $host "]"
echo -e "----------------------------------------------------------------------------\n"
done | tee log_$(date "+%Y%m%d-%H.%M.%S")
