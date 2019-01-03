package main

import (
	"github.com/fatih/color"
	"os"
	"bufio"
	"os/exec"
	"net"
	"time"
)


/* This function performs a web application vulnerability scan against target IP. */
func WebScan(targetIP string, outputPath string, port2scan string) {
	color.Green("\n\n[!] Starting to scan " + targetIP + ":" + port2scan + " for web application vulnerabilities.\n\n")
	//Initiate cewl on targetIP:port2scan
	//cewl -d 5 -m 1 -w cewl_out --with-numbers -a --meta_file cewl_metadata_out -e --email_file cewl_emails_out 192.168.1.66:8888
	cewlCmd := exec.Command("bash", "-c", "cewl -d 5 -m 1 -w " + outputPath + "/cewl_out_" + port2scan + " --with-numbers -a --meta_file " + outputPath + "/cewl_metadata_out_" + port2scan + " -e --email_file " + outputPath + "/cewl_emails_out_" + port2scan + " " + targetIP + ":" + port2scan + " && cat " + outputPath + "/cewl_* > " + outputPath + "/gobuster_wordlist_" + port2scan + " && cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt >> " + outputPath + "/gobuster_wordlist_" + port2scan)
    	err := cewlCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//Initiate gobuster on targetIP:port2scan
	//gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /tmp/gobuster_out -u 192.168.1.66:8888 -f -r -k -n
	gobusterCmd := exec.Command("bash", "-c", "gobuster -w " + outputPath + "/gobuster_wordlist_" + port2scan + " -o " + outputPath + "/gobuster_out_" + port2scan + " -u http://" + targetIP + ":" + port2scan + " -f -r -k -n")
    	err = gobusterCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//open the file to read
	dirsFilePath := outputPath + "/gobuster_wordlist_" + port2scan
	//dirsFile := OpenFile2Read(dirs)
	dirsFile, _ := os.Open(dirsFilePath)
	defer dirsFile.Close()
	scanner := bufio.NewScanner(dirsFile)
	//Initiate nikto with gobuster's output (Line_by_Line)
	//nikto -h http://192.168.43.4:80/railsgoat
	for scanner.Scan() {
		niktoCmd := exec.Command("bash", "-c", "nikto -h http://" + targetIP + ":" + port2scan + "/" + scanner.Text() + " -Tuning x12567> " + outputPath + "/nikto_scan_out_" + port2scan)
	    	err = niktoCmd.Run()
	    	if err != nil {
			panic(err)
	    	}
	}
	color.White("\n\n[+] Web application vulnerability scan on " + targetIP + ":" + port2scan + " is completed successfully.\n\n")	
}

func HttpsCheck(targetIP string, port2scan string) bool {	
	timeout := time.Duration(5 * time.Second)
	_, err := net.DialTimeout("tcp","https://" + targetIP + ":" + port2scan, timeout)
	if err != nil {
        	return false
	}
	return true
}

func main() {
	//WebScan("192.168.43.4", "/home/HaGashash_Projects/megashesh_5/192.168.43.4", "80") //owaspbwa
	//WebScan("192.168.43.5", "/home/HaGashash_Projects/megashesh_7/192.168.43.5", "9001") //manjaro
	a := HttpsCheck("192.168.43.6","12380")
	color.White("\na:\n\n",a)
}
