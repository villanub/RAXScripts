#################################
# Configuring PowerShell Window #
#################################
Param
(
    [Parameter(Mandatory = $True)]
    [String]$RAXUser,
    [Parameter(Mandatory = $True)]
    [String]$RAXPassword
)

$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$Host.UI.RawUI.WindowTitle = "Configuring RAX Support Account"

########################
# Setting PS Functions #
########################
function Set-LocalAccount {
    $user = Get-WMIObject Win32_UserAccount -ComputerName $env:COMPUTERNAME -Filter "Name='$RAXUser'"
    #Creating User Account if it does not exist
    if (!$user) {
        NET USER $RAXUser $RAXPassword /ADD /y
        NET LOCALGROUP "Administrators" "$RAXUser" /add
        WMIC USERACCOUNT WHERE "Name='$RAXUser'" SET PasswordExpires=FALSE
    }
    else {
        Write-Host "Warning: User Exists. Resetting Password."
        NET USER $RAXUser $RAXPassword /y
    }
    
}

function Set-DomainAccount {
    New-ADUser -Name $RAXUser -SamAccountName $RAXUser -DisplayName $RAXUser
        -GivenName "Rackspace" -Surname "Support" `
        -EmailAddress "AzureSupport@rackspace.com" `
        -Path $OU -Enabled $true `
        -ChangePasswordAtLogon $false -PasswordNeverExpires $true `
        -AccountPassword $RAXPassword -PassThru
}


###################################
# Verify if Computer is on Domain #
###################################
if ((Get-WmiObject Win32_ComputerSystem).PartofDomain -eq $true) {
    Write-Host "Warning: Computer is on a Domain"

    Try {
        # Test if Server is a Domain Controller
        Import-Module ActiveDirectory
    }
    Catch {
        Write-Host "Active Directory PS Module Not Present"
    }

    $ComputerProperties = Get-ADComputer $env:COMPUTERNAME -properties *
    if ($ComputerProperties.PrimaryGroupID -eq "516") {
        Write-Host "$env:COMPUTERNAME is a Domain Controller"
        $ISDC = $TRUE 
    }
    else {
        Write-Host "Server is a member of the domain"
        Set-LocalAccount
    }
    
    
    
####################################
# Testing if Domain Account exists #
####################################
    if ($ISDC -eq $TRUE) { 
        #Fetching Domain Name
        $ADDomainName=(Get-WmiObject Win32_ComputerSystem).Domain

        #Splitting the domain name a.com to a and com
        $D1name=($ADDomainName.Split(".")[0])
        $D2name=($ADDomainName.Split(".")[1])
        Write-Host("Retrieved the Root AD domain.")
 
        $ADCompletePath = "LDAP://"+$ADServer+":"+$ADPort+"/DC="+$D1name+",DC="+$D2name
        $ADRoot =  [ADSI]'"$ADCompletePath"'

        $ADSearch = New-Object System.DirectoryServices.DirectorySearcher($ADRoot)  
        $SAMAccountName = "$RAXUser"
        $ADSearch.Filter = "(&(objectClass=user)(sAMAccountName=$SAMAccountName))"
        $ADSerachResult = $ADSearch.FindAll()
 
        if ($ADSerachResult.Count -eq 0)
        {
            Set-DomainAccount
        }
        else
        {
            Write-Host "Warning: User Exists"
            $oUser = [ADSI]"LDAP://$RAXUser"
            $ouser.psbase.invoke("SetPassword",$RAXPassword)
            $ouser.psbase.CommitChanges() 
        }   
    } 

}
else {

##########################
# Local Account Creation #
##########################
    Set-LocalAccount
}
##########################
# Removing log file with password
##########################
Remove-Item "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\1.4\CustomScriptHandler.log"
