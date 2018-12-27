package main

import (
    "os"
    "log"
    "fmt"
    "io/ioutil"
    "strings"
)

//This function spiders a target (http and https), prepars a wordlist (cewl), performs a directory fuzz (gobuster) and scans for web vulnerabilities (nikto).
//target variable should be http/https + IP + port
/*func WebScan(targetIP string, fullURL string, outputPath string, workgroup *sync.WaitGroup) {	
	color.Green("\n\n[!] Starting to CeWL " + target + ".\n\n")
	cewlCmd := exec.Command("bash", "-c", "cewl -d 5 -m 1 -w " + outputPath + "/cewl_out --with-numbers -a --meta_file " + outputPath + "/cewl_metadata_out -e --email_file " + outputPath + "/cewl_emails_out " + fullURL)
	err := cewlCmd.Run()
	if err != nil {
		panic(err)
	}
	color.White("\n\n[+] Wordlist for " + target + " is ready.\n\n")
	color.Green("\n\n[!] Starting to brute force directories of " + target + " for web application vulnerabilities.\n\n")
	//Initiate gobuster on discovered ports and add all of the output to gobuster_out file
	//gobuster code
	color.Green("\n\n[!] Starting to scan " + target + " for web application vulnerabilities.\n\n")
	//Give nikto the final gobuster output (I want to scan all pages)
	niktoCmd := exec.Command("bash", "-c", "nikto -h " + outputPath + "/gobuster_out -Tuning x12567 > " + outputPath + "/nikto_scan_out")
	err = niktoCmd.Run()
	if err != nil {
		panic(err)
	}
	color.White("\n\n[+] The web scan on " + target + " is completed successfully.\n\n")
	workgroup.Done()
}
*/

//This function opens a file for reading
func OpenFile2Read(outputPath string) string {
	file, err := os.Open(outputPath + "/nmap_tcp_scan_output_grepable")
	if err != nil {
		log.Fatal(err)
	}
	grepable, err := ioutil.ReadAll(file)
    	if err != nil {
        	log.Fatal(err)
    	}
	return string(grepable)
}


/*Dont forget: func TakeOutPorts(targetIP string, outputPath string, workgroup *sync.WaitGroup) []string {
//This function takes out http/s port number from a nmap grepable output and returns it.
func PortEr(data string, serviceName string) string {
	//Check if the serviceName is mentioned in the file, then extract its port number.
	var portNumbers []string
	var portNumber string
	exists := strings.Contains(data, serviceName)
	serviceNameIndex := strings.Index(data, serviceName)
	if( exists && serviceNameIndex != -1 ) {
		fmt.Printf("\nData:\n\n",data)
		fmt.Printf("\nserviceNameIndex:\n",int(serviceNameIndex))
		data = data[serviceNameIndex-22:]
		fmt.Printf("\nData_2:\n\n",data)
		psikIndex := strings.Index(data, ",")
		kavnatuy := strings.Index(data, "/")
		portNumber = data[psikIndex+2:kavnatuy]
		fmt.Printf("\nPort number extracted:\n",portNumber)
		data = data[kavnatuy:]
		fmt.Printf("\nData_3:\n\n",data)
		fmt.Printf("\n\n\n------------------------------------------------\n\n\n")
			
	} else {
		return -1
	}
	return portNumbers
	
}*/

//This function takes a nmap grepable output and a service name. It returns a slice of ports of that service.
func PortExtractor(data string, serviceName string) []string {
	var (
		portNumbers []string		
		portsWord = "Ports:"
		space = " "
		spaceIndex int 
		spaceIndexes []int
		backSlash = "/"
		backSlashIndex int
		backSlashIndexes []int
		comma = ","
		commaIndex int
		commaIndexes []int
		serviceNameIndex int
	)
	//scan data until it nil
	for _ = range data {
		portsWordIndex := strings.Index(data, portsWord)
		if ( portsWordIndex > 0 ) {
			data = data[portsWordIndex+6:]
		}
		fmt.Println("\n\ndata_1\n",data)
		//Space,comma and backSlash mapper
		for s1, v1 := range data {
			switch {
				case string(v1) == space:
					spaceIndexes = append(spaceIndexes,s1)
				case string(v1) == backSlash:
					backSlashIndexes = append(backSlashIndexes,s1)
				case string(v1) == comma:
					commaIndexes = append(commaIndexes,s1)
			}	
		}
		fmt.Println("\n\nspaceIndexes\n",spaceIndexes)
		fmt.Println("\n\nbackSlashIndexes\n",backSlashIndexes)
		fmt.Println("\n\ncommaIndexes\n",commaIndexes)
		serviceNameIndex = strings.Index(data, serviceName)
		//spaceIndex extractor
		for s2, v2 := range spaceIndexes {
			if ( v2 > serviceNameIndex ) {
				spaceIndex = spaceIndexes[s2-1]
				break
			}	
		}
		//backSlashIndex extractor
		for s3, v3 := range backSlashIndexes {
			if ( v3 < serviceNameIndex && v3 > spaceIndex ) {
				backSlashIndex = backSlashIndexes[s3]
				break
			}	
		}
		//commaIndex extractor
		for s4, v4 := range commaIndexes {
			if ( v4 > serviceNameIndex ) {
				commaIndex = commaIndexes[s4]
				break
			}	
		}
		portNumber := data[spaceIndex:backSlashIndex]
		data = data[commaIndex+1:]
		fmt.Println("\n\ndata_before_calling_again\n",data)
		fmt.Println("\n\nspaceIndex\n",spaceIndex)
		fmt.Println("\n\nbackSlashIndex\n",backSlashIndex)
		fmt.Println("\n\ncommaIndex\n",commaIndex)
		fmt.Println("\n\nportNumber extracted:\n",portNumber)
		portNumbers = append(portNumbers,portNumber)
	}
	fmt.Println("\n\nportNumbers:\n",portNumbers)
	/*switch {
	case len(data) > 0 && commaIndexes != nil:
		fmt.Printf("\n\n\n------------------------------------------------\n\n\n")
		return portNumber
		PortExtractor(data, serviceName)
	case commaIndexes == nil:
		fmt.Println("\n\nDone!\n\n")
	}*/
	return portNumbers
}

func main() {
	//var sliceOfPorts []string	//slice of ports per service
	a := OpenFile2Read("/root/Desktop/Yes")
	PortExtractor(a,"http")
	//p := PortExtractor(a,"http")
	//fmt.Printf("\n\nPort Extarcted:\n",p)
}
