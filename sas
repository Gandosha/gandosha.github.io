/* This function performs a web application vulnerability scan on target IP. */
func WebScan(targetIP string, outputPath string, port2scan string, workgroup *sync.WaitGroup) {
	color.Green("\n\n[!] Starting to scan " + targetIP + " for web application vulnerabilities.\n\n")
	//Initiate cewl on targetIP:port2scan
	//cewl -d 5 -m 1 -w cewl_out --with-numbers -a --meta_file cewl_metadata_out -e --email_file cewl_emails_out 192.168.1.66:8888
	cewlCmd := exec.Command("bash", "-c", "cewl -d 10 -m 1 -w " + outputPath + "/cewl_out_" + port2scan + " --with-numbers -a --meta_file " + outputPath + "/cewl_metadata_out_" + port2scan + " -e --email_file " + outputPath + "/cewl_emails_out_" + port2scan + " " + targetIP + ":" + port2scan + " && cat " + outputPath + "/cewl_* > gobuster_wordlist && cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt >> gobuster_wordlist")
    	err := cewlCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//Initiate gobuster on targetIP:port2scan
	//gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /tmp/gobuster_out -u 192.168.1.66:8888 -f -r -k -n
	gobusterCmd := exec.Command("bash", "-c", "gobuster -w " + outputPath + "/gobuster_wordlist" + port2scan + " -o " + outputPath + "/gobuster_out_" + port2scan + " -u " + targetIP + ":" + port2scan + " -f -r -k -n")
    	err = gobusterCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//Initiate nikto with gobuster's output
	//https://cirt.net/nikto2-docs/options.html -mutate 6 with dictionary file
	niktoCmd := exec.Command("bash", "-c", "nikto -h " + outputPath + "/nmap_tcp_scan_output_grepable -Tuning x12567> " + outputPath + "/nikto_scan_out")
    	err = niktoCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	color.White("\n\n[+] Nikto's scan on " + targetIP + " is completed successfully.\n\n")
	workgroup.Done()	
}
