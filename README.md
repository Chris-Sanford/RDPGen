Overview:

RDPGen is a PowerShell module that generates an RDP file for a user and computer to access a Remote Desktop Gateway with the goal of streamlining the remote work enablement process. The Enable-RDPAccess function takes user input for a target user and computer, adds them to the proper Active Directory groups, generates a customized RDP gateway file, then sends an email to the end user with the RDP file attached and instructions in the body.

Requirements:
- Domain Admin Rights
- ActiveDirectory PowerShell Module (install Microsoft's Remote Server Administration Tools)
- Group Policy configured to enable RDP on target computers for target users
- (Optional) The .PFX SSL Certificate file from your RDP Gateway server installed into your Personal certificate store
- An SMTP (Email) Server that accepts insecure mail messages (i.e. an on-prem Exchange server)

Instructions:
- Download the module by clicking the green "Code" button on this page (you may need to be logged into GitHub)
- Extract the contents
- Copy the RDPGen folder into any directory found in $env:PSModulePath (i.e. C:\Program Files\WindowsPowerShell\Modules)
- Open RDPGen.psm1 in a text editor and set the environment variables located at the top
- (Optional) Customize the contents of template.htm (tip: use Outlook to create a template, File > Save As > Select HTML as File Type)
- (Optional) Customize the options within the New-RDPFile function if desired to configure the end user's RDP experience 
- Ensure your PowerShell Execution Policy will allow the execution of this script, understanding the security risks involved (Set-ExecutionPolicy Unrestricted)
- As a Domain Admin in an elevated PowerShell window, run the following command, replacing $USERNAME and $COMPUTERNAME accordingly:
Enable-RDPAccess -User $USERNAME -Computer $COMPUTERNAME

You can target a list of user and computer pairs by running Enable-RDPAccess in a foreach loop if desired.

Future Improvements:
- Create a config.ini file that must be configured to use the script
- Alert user to modify/update the config.ini file if it hasn't already been set
- Have New-RDPFile create an RDP file based on a template .rdp file using config.ini so end users never need to modify the module
- Create Synopsis/Description/Help content to make it more "official"
- Transcription/log file creation
