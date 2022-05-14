#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

#region Environment Variables - Set your environment variables here!
$smtpServer = "mail.domain.com" #STMP Server Domain Name that accepts insecure email send requests
$fromEmailDisplayName = "Information Technology"
$fromEmailAddress = "IT@domain.com"
$emailBodyTemplate = "C:\Path\To\Template.htm" #Path to HTML template file to be used for Email Body
$emailSubject = "Work from Home User Guide" #Subject line to use in Email
$rdsgatewayFQDN = "rdp.domain.com" #Remote Desktop Gateway's Fully Qualified Domain Name
$usersGroup = "Remote_Users" #AD Users Group associated to RAP Policy on RDP Gateway
$computersGroup = "Remote_Computers" #AD Computers Group associated to CAP Policy on RDP Gateway
$sslHash = "THUMBPRINT" #The thumbprint/hash of the SSL Certificate used to sign the RDP file(s)
#endregion

function Get-UserEmailAddress ($user)
{
    $script:userEmailAddress = (Get-ADUser -Identity $user -Properties EmailAddress).EmailAddress

    Switch ($?)
    {
        true{Write-Host "$user's email address is: $script:userEmailAddress" -ForegroundColor Green}
        false{throw "Something went wrong when querying Active Directory. Make sure the username is correct, you're running as a Domain Admin, and our connection to the domain controller is working."}
    }
}

function Get-UserPrincipalName ($user)
{
    $script:userPrincipalName = (Get-ADUser -Identity $user -Properties UserPrincipalName).UserPrincipalName

    Switch ($?)
    {
        true{Write-Host "$user's Principal Name is: $script:userPrincipalName" -ForegroundColor Green}
        false{throw "Something went wrong when querying Active Directory. Make sure the username is correct, you're running as a Domain Admin, and our connection to the domain controller is working."}
    }
}

function Get-ComputerSamAccountName ($computer) #This may not be necessary at all
{
    $script:computerSamAccountName = (Get-ADComputer -Identity $computer).SamAccountName

    Switch ($?)
    {
        true{Write-Host "$computer's SAM Account Name is: $script:computerSamAccountName" -ForegroundColor Green}
        false{throw "Something went wrong when querying Active Directory. Make sure the computer name is correct, you're running as a Domain Admin, and our connection to the domain controller is working."}
    }
}

function Add-ADComputerGroupMembership ($computer)
{
    Add-ADGroupMember -Identity $computersGroup -Members $script:computerSamAccountName

    Switch ($?)
    {
        true{Write-Host "$computer has been added to the $computersGroup group in Active Directory" -ForegroundColor Green}
        false{throw "Something went wrong when contacting Active Directory. Make sure the computer name is correct, you're running as a Domain Admin, and our connection to the domain controller is working."}
    }
}

function Add-ADUserGroupMembership ($user)
{
    Add-ADGroupMember -Identity $usersGroup -Members $user

    Switch ($?)
    {
        true{Write-Host "$user has been added to the $usersGroup group in Active Directory" -ForegroundColor Green}
        false{throw "Something went wrong when contacting Active Directory. Make sure the username is correct, you're running as a Domain Admin, and our connection to the domain controller is working."}
    }
}

function New-RDPFile ($user,$computer)
{
    $script:rdpFilePath = "${ENV:USERPROFILE}\Desktop\${user}_${computer}.rdp"

    Set-Content -Path $script:rdpFilePath -Value "full address:s:${computer}
username:s:${script:userPrincipalName}
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
winposstr:s:0,1,790,99,1682,868
compression:i:1
keyboardhook:i:2
audiocapturemode:i:1
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:0
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:${rdsgatewayFQDN}
gatewayusagemethod:i:1
gatewaycredentialssource:i:0
gatewayprofileusagemethod:i:1
promptcredentialonce:i:1
gatewaybrokeringtype:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
drivestoredirect:s:
"

    Switch ($?)
    {
        true{Write-Host "$script:rdpFilePath file generated successfully." -ForegroundColor Green}
        false{throw "Generation of RDP file failed."}
    }
}

function Invoke-RDPFileSignature ($user,$computer)
{
    #rdpsign is a Windows-native tool used to sign RDP files using an SSL certificate's hash/thumbprint
    rdpsign /sha256 $sslHash $script:rdpFilePath /q

    Switch ($?)
    {
        true{Write-Host "$script:rdpFilePath file has been signed successfully. This simply makes the 'Do you trust this?' popup less alarming." -ForegroundColor Green}
        false{Write-Host "Signing of ${user}_${computer}.rdp file failed. Please import/install the .PFX certificate of the RDS Gateway into your Current User Personal store. This is a non-fatal error. The RDP file is still valid, but users may be concerned by security/trust warnings." -ForegroundColor Yellow}
    }
}

function Send-Email
{
    Send-MailMessage -SmtpServer $smtpServer -From "$fromEmailDisplayName <$fromEmailAddress>" -To "<$script:userEmailAddress>" -Subject $emailSubject -BodyAsHTML -Body (Get-Content $emailBodyTemplate -Raw) -Attachments $script:rdpFilePath -DeliveryNotificationOption OnFailure

    Switch ($?)
    {
        true{Write-Host "$script:userEmailAddress has been sent an email with instructions. Undeliverable notifications and bounce-backs are delivered to $fromEmailAddress. Please note that emails will not appear in the Sent Items folder of $fromEmailAddress." -ForegroundColor Green}
        false{throw "Something failed when trying to send Email to $script:userEmailAddress. $smtpServer or the email body template file could be inaccessible."}
    }
}

function Enable-RDPAccess
{
    param
    (
    [Parameter(Mandatory=$true)]
    [string]$user,
    [Parameter(Mandatory=$true)]
    [string]$computer
    )

    Get-UserEmailAddress $user
    Get-UserPrincipalName $user
    Get-ComputerSamAccountName $computer
    Add-ADComputerGroupMembership $computer
    Add-ADUserGroupMembership $user
    New-RDPFile $user $computer
    Invoke-RDPFileSignature $user $computer
    Send-Email

    Write-Host "Please remember to reboot $computer and ensure Group Policy is configured properly to enable Remote Desktop access for $computersGroup." -ForegroundColor Yellow
}

Export-ModuleMember -Function * -Alias *
