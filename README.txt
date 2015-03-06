
a]TEAM NAME: POLARIS
*******************************************
b]Team: Rohith Narasimhamurthy
		Thai Shankar Shanmugha Sundaram
		Ullas Simhan Mandayam Nyayachavadi
*******************************************************************************************************************************************
c]In this project, we designed a File Transfer protocol which provides the best performance under extreme loss and delay conditions.

  For 20% loss and 200ms delay, File Transfer Rate of 75Mbps+ is achieved. And for no loss link, it achieves 88Mbps. 
*********************************************************************************************************************************************
d]The Contents of this tar folder 
   1. sender.c
   2. receiver.c
   3. md5.c
   4. Makefile
   5. func_util.c
   6. header.h
   7. README.txt
   8. Report.pdf
   9. ns file

e] Compilation 
*****************************
     make all          : compiles and creates executables - sender, receiver and md5 
     make <executable> : compiles for that particular executable (sender, receiver or md5) 
     make clean        : removes <executables> 
***********************************************************************************************************************************************    
e] Execution
   *******************
  -> make all
  -> ./sender <sendFilename> <DstIP> <RecreatedFile> 
  -> ./receiver <newFile>
  -> ./md5 <fileName>
**************************************************************************************************************************************************
h] Notes
   ********************
   -> Active ethernet interface has to be configured in the func_util.c according to node configuration on deter
   -> Receiver should be running prior to starting the file transfer 

****************************************************************************************************************************************
i] References
   *******************
 Hash bit array and md5 implementation logic from stackoverflow forums

**************************************************************END****************************************************************************************************   
